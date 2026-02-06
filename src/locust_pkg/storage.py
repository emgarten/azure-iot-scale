import logging
import os
import random
import resource
import threading
from typing import Any, Optional

import gevent
import orjson
from azure.core import MatchConditions
from azure.core.exceptions import ResourceExistsError, ResourceModifiedError, ResourceNotFoundError
from azure.identity import AzureCliCredential, ChainedTokenCredential, DefaultAzureCredential
from azure.storage.blob import BlobServiceClient

logger = logging.getLogger("locust.storage")

# Storage authentication (in order of preference):
# 1. STORAGE_CONN_STR - Connection string for the storage account
# 2. STORAGE_ACCOUNT_URL - Account URL (e.g., https://<account>.blob.core.windows.net)
#    with DefaultAzureCredential (managed identity, Azure CLI, etc.)
# At least one must be set, otherwise an exception is raised.
storage_conn_str = os.getenv("STORAGE_CONN_STR")
storage_account_url = os.getenv("STORAGE_ACCOUNT_URL")
storage_container_name = os.getenv("STORAGE_CONTAINER_NAME", "scale")
counter_blob_prefix = os.getenv("COUNTER_BLOB_PREFIX", "counter")
device_data_blob_prefix = os.getenv("DEVICE_DATA_BLOB_PREFIX", "data")

# Increased default for scale: 50000 IDs per range reduces counter contention
# With 1M devices and 50000 per range, only 20 allocations needed per worker
device_id_range_size = int(os.getenv("DEVICE_ID_RANGE_SIZE", "5000"))
device_name_prefix = os.getenv("DEVICE_NAME_PREFIX", "device")

# Counter sharding: number of counter partitions to reduce contention
# With N shards, max N workers can allocate simultaneously without conflict
counter_shard_count = int(os.getenv("COUNTER_SHARD_COUNT", "25"))

# File descriptor warning threshold for scale testing
min_file_descriptors = int(os.getenv("MIN_FILE_DESCRIPTORS", "65536"))

# Global BlobServiceClient singleton with thread-safe initialization
_blob_service_client: Optional[BlobServiceClient] = None
_blob_service_client_lock: threading.Lock = threading.Lock()


def get_blob_service_client() -> BlobServiceClient:
    """Get or create the global BlobServiceClient singleton.

    Thread-safe: Uses double-checked locking pattern for efficient singleton initialization.

    Returns:
        BlobServiceClient: The global blob service client instance.
    """
    global _blob_service_client

    # Fast path: if already initialized, return immediately
    if _blob_service_client is not None:
        return _blob_service_client

    # Slow path: acquire lock and check again (double-checked locking)
    with _blob_service_client_lock:
        if _blob_service_client is None:
            # Configure connection pooling for high throughput
            # max_single_put_size: 64MB (default), max_block_size: 4MB (default)
            # connection_timeout and read_timeout for faster failure detection
            if storage_conn_str is not None:
                _blob_service_client = BlobServiceClient.from_connection_string(
                    storage_conn_str,
                    max_single_put_size=64 * 1024 * 1024,
                    max_block_size=4 * 1024 * 1024,
                    connection_timeout=10,
                    read_timeout=30,
                )
            elif storage_account_url is not None:
                # Try Azure CLI first (fast for local dev), then fall back to DefaultAzureCredential
                # (which includes ManagedIdentity, environment vars, etc. for cloud environments)
                credential = ChainedTokenCredential(AzureCliCredential(), DefaultAzureCredential())
                _blob_service_client = BlobServiceClient(
                    account_url=storage_account_url,
                    credential=credential,
                    max_single_put_size=64 * 1024 * 1024,
                    max_block_size=4 * 1024 * 1024,
                    connection_timeout=10,
                    read_timeout=30,
                )
            else:
                raise Exception("Missing STORAGE_CONN_STR or STORAGE_ACCOUNT_URL environment variable")

    return _blob_service_client


def check_file_descriptor_limit() -> None:
    """Check and warn if file descriptor limit is too low for scale testing.

    For millions of devices, each with an MQTT connection, we need a high
    file descriptor limit. This function checks the current soft limit and
    warns or raises if it's too low.

    Raises:
        RuntimeError: If file descriptor limit is critically low and STRICT_FD_CHECK is set.
    """
    try:
        soft_limit, hard_limit = resource.getrlimit(resource.RLIMIT_NOFILE)
        logger.info(f"File descriptor limits: soft={soft_limit}, hard={hard_limit}")

        if soft_limit < min_file_descriptors:
            # Try to increase soft limit to hard limit
            if hard_limit >= min_file_descriptors:
                try:
                    resource.setrlimit(resource.RLIMIT_NOFILE, (min_file_descriptors, hard_limit))
                    logger.info(f"Increased file descriptor soft limit to {min_file_descriptors}")
                except (ValueError, OSError) as e:
                    logger.warning(f"Could not increase file descriptor limit: {e}")

            # Re-check after attempted increase
            soft_limit, _ = resource.getrlimit(resource.RLIMIT_NOFILE)
            if soft_limit < min_file_descriptors:
                msg = (
                    f"File descriptor limit ({soft_limit}) is below recommended minimum "
                    f"({min_file_descriptors}) for scale testing. "
                    f"Run 'ulimit -n {min_file_descriptors}' or adjust system limits."
                )
                if os.getenv("STRICT_FD_CHECK", "false").lower() == "true":
                    raise RuntimeError(msg)
                else:
                    logger.warning(msg)
    except (AttributeError, OSError) as e:
        # resource module not available on all platforms (e.g., Windows)
        logger.debug(f"Could not check file descriptor limit: {e}")


def initialize_storage(blob_service_client: Optional[BlobServiceClient] = None) -> BlobServiceClient:
    """Initialize storage by creating containers if they don't exist.

    This should be called once at application startup to ensure all required
    containers are available. Also checks file descriptor limits for scale.

    Args:
        blob_service_client: Optional blob service client to use. If None, uses global singleton.

    Returns:
        BlobServiceClient: The blob service client that was initialized.
    """
    # Check file descriptor limits for scale testing
    check_file_descriptor_limit()

    if blob_service_client is None:
        blob_service_client = get_blob_service_client()

    try:
        # Create the main container if it doesn't exist
        container_client = blob_service_client.get_container_client(storage_container_name)
        container_client.create_container()
        logger.info(f"Created storage container: {storage_container_name}")
    except ResourceExistsError:
        # Container already exists, which is fine
        logger.debug(f"Storage container already exists: {storage_container_name}")
    except Exception as e:
        logger.warning(f"Error creating storage container {storage_container_name}: {e}")

    return blob_service_client


def save_device_data(
    device_name: str,
    data_dict: dict[str, Any],
    blob_service_client: Optional[BlobServiceClient] = None,
) -> None:
    """Save device data to Azure Blob Storage.

    Args:
        device_name: Name of the device
        data_dict: Dictionary containing device data to save
        blob_service_client: Optional blob service client to use. If None, uses global singleton.

    The data is saved as JSON and will overwrite any existing data for this device.
    """
    try:
        if blob_service_client is None:
            blob_service_client = get_blob_service_client()
        container_client = blob_service_client.get_container_client(storage_container_name)
        blob_name = f"{device_data_blob_prefix}/{device_name}/registration.json"
        blob_client = container_client.get_blob_client(blob_name)

        # Serialize to JSON
        json_data = orjson.dumps(data_dict)

        # Upload with overwrite
        blob_client.upload_blob(json_data, overwrite=True)
        logger.debug(f"Saved device data for {device_name}")
    except Exception as e:
        logger.error(f"Failed to save device data for {device_name}: {e}")
        # Don't raise - graceful degradation


def load_device_data(
    device_name: str,
    blob_service_client: Optional[BlobServiceClient] = None,
) -> Optional[dict[str, Any]]:
    """Load device data from Azure Blob Storage.

    Args:
        device_name: Name of the device
        blob_service_client: Optional blob service client to use. If None, uses global singleton.

    Returns:
        Dictionary containing device data if found and valid, None otherwise.
        Returns None if:
        - Blob doesn't exist
        - JSON parsing fails
        - Any required field is missing
    """
    required_fields = [
        "device_name",
        "registration_status",
        "assigned_hub",
        "device_id",
        "private_key_pem",
        "issued_cert_pem",
    ]

    try:
        if blob_service_client is None:
            blob_service_client = get_blob_service_client()
        container_client = blob_service_client.get_container_client(storage_container_name)
        blob_name = f"{device_data_blob_prefix}/{device_name}/registration.json"
        blob_client = container_client.get_blob_client(blob_name)

        # Direct download without exists() check - faster, one less API call
        # ResourceNotFoundError is caught below if blob doesn't exist
        blob_data = blob_client.download_blob().readall()
        data_dict = orjson.loads(blob_data)

        # Validate all required fields are present
        for field in required_fields:
            if field not in data_dict or data_dict[field] is None:
                logger.warning(f"Device data for {device_name} missing required field: {field}")
                return None

        logger.debug(f"Loaded device data for {device_name}")
        return dict(data_dict)  # Ensure proper dict type

    except ResourceNotFoundError:
        logger.debug(f"No device data found for {device_name}")
        return None
    except Exception as e:
        logger.warning(f"Failed to load device data for {device_name}: {e}")
        return None


def delete_device_data(
    device_name: str,
    blob_service_client: Optional[BlobServiceClient] = None,
) -> None:
    """Delete device data from Azure Blob Storage.

    Args:
        device_name: Name of the device
        blob_service_client: Optional blob service client to use. If None, uses global singleton.
    """
    try:
        if blob_service_client is None:
            blob_service_client = get_blob_service_client()
        container_client = blob_service_client.get_container_client(storage_container_name)
        blob_name = f"{device_data_blob_prefix}/{device_name}/registration.json"
        blob_client = container_client.get_blob_client(blob_name)

        # Direct delete without exists() check - faster, one less API call
        # delete_blob() is idempotent if blob doesn't exist (no error thrown)
        blob_client.delete_blob()
        logger.debug(f"Deleted device data for {device_name}")
    except ResourceNotFoundError:
        # Blob didn't exist, which is fine
        logger.debug(f"Device data for {device_name} did not exist")
    except Exception as e:
        logger.error(f"Failed to delete device data for {device_name}: {e}")


def allocate_device_id_range(
    device_prefix: Optional[str] = None,
    range_size: Optional[int] = None,
    blob_service_client: Optional[BlobServiceClient] = None,
    max_retries: int = 50,
) -> tuple[int, int]:
    """Atomically allocate a range of device IDs for a worker using sharded counters.

    This function uses ETag-based optimistic concurrency to safely allocate
    non-overlapping ID ranges to multiple workers. Counter sharding reduces
    contention by spreading workers across multiple counter blobs.

    Sharding strategy:
    - Workers are randomly assigned to one of COUNTER_SHARD_COUNT shards
    - Each shard manages its own ID space (shard 0: 0-N, shard 1: 1M-N+1M, etc.)
    - This allows N shards to allocate simultaneously without conflict

    Args:
        device_prefix: The device name prefix to use for isolation. If None, uses DEVICE_NAME_PREFIX.
        range_size: Number of IDs to allocate. If None, uses DEVICE_ID_RANGE_SIZE env var.
        blob_service_client: Optional blob service client. If None, uses global singleton.
        max_retries: Maximum number of retries on ETag conflict (default: 50 for scale).

    Returns:
        Tuple of (start_id, end_id) where end_id is exclusive.
        For example, (0, 50000) means IDs 0-49999 are allocated.

    Raises:
        Exception: If allocation fails after max_retries attempts.
    """
    if device_prefix is None:
        device_prefix = device_name_prefix
    if range_size is None:
        range_size = device_id_range_size
    if blob_service_client is None:
        blob_service_client = get_blob_service_client()

    container_client = blob_service_client.get_container_client(storage_container_name)

    # Sharding: randomly select a shard to reduce contention
    # Each shard has its own ID space offset by shard_id * 10_000_000_000 (10 billion)
    # This allows up to 10 billion IDs per shard, supporting billions of devices
    shard_id = random.randint(0, counter_shard_count - 1)
    shard_offset = shard_id * 10_000_000_000  # 10 billion IDs per shard

    blob_name = f"{counter_blob_prefix}/{device_prefix}/shard_{shard_id:03d}.json"
    blob_client = container_client.get_blob_client(blob_name)

    for attempt in range(max_retries):
        try:
            # Try to read existing counter
            try:
                download_result = blob_client.download_blob()
                blob_data = download_result.readall()
                counter_data = orjson.loads(blob_data)
                current_next_id = counter_data.get("next_id", 0)
                etag = download_result.properties.etag
            except ResourceNotFoundError:
                # Blob doesn't exist, start from 0 (within shard)
                current_next_id = 0
                etag = None

            # Calculate new range (within shard space)
            shard_start_id = current_next_id
            shard_end_id = shard_start_id + range_size
            new_counter_data = orjson.dumps({"next_id": shard_end_id})

            # Global IDs include shard offset
            global_start_id = shard_offset + shard_start_id
            global_end_id = shard_offset + shard_end_id

            # Attempt conditional write
            if etag is None:
                # Create new blob (will fail if another worker created it first)
                try:
                    blob_client.upload_blob(new_counter_data, overwrite=False)
                except ResourceExistsError:
                    # Another worker created it, retry with exponential backoff
                    delay = min(0.1 * (2 ** min(attempt, 5)), 2.0) + random.uniform(0, 0.5)
                    logger.debug(
                        f"Counter shard {shard_id} created by another worker, "
                        f"retrying (attempt {attempt + 1}, delay {delay:.2f}s)"
                    )
                    gevent.sleep(delay)
                    continue
            else:
                # Update existing blob with ETag check
                try:
                    blob_client.upload_blob(
                        new_counter_data,
                        overwrite=True,
                        etag=etag,
                        match_condition=MatchConditions.IfNotModified,
                    )
                except ResourceModifiedError:
                    # Another worker updated it, retry with exponential backoff
                    delay = min(0.1 * (2 ** min(attempt, 5)), 2.0) + random.uniform(0, 0.5)
                    logger.debug(
                        f"Counter shard {shard_id} modified by another worker, "
                        f"retrying (attempt {attempt + 1}, delay {delay:.2f}s)"
                    )
                    gevent.sleep(delay)
                    continue

            # Success!
            logger.info(
                f"Allocated device ID range [{global_start_id}, {global_end_id}) "
                f"for prefix '{device_prefix}' (shard {shard_id})"
            )
            return (global_start_id, global_end_id)

        except Exception as e:
            logger.warning(f"Error allocating device ID range (attempt {attempt + 1}): {e}")
            gevent.sleep(random.uniform(0.5, 1.0))

    raise Exception(f"Failed to allocate device ID range after {max_retries} attempts")


def clear_device_counter(
    device_prefix: Optional[str] = None,
    blob_service_client: Optional[BlobServiceClient] = None,
) -> int:
    """Clear all counter shards for a specific device prefix.

    This deletes all counter shard blobs, effectively resetting the counters
    for the specified device prefix. Handles both old single-counter format
    and new sharded format.

    Args:
        device_prefix: The device name prefix to clear. If None, uses DEVICE_NAME_PREFIX.
        blob_service_client: Optional blob service client. If None, uses global singleton.

    Returns:
        Number of counter blobs deleted.
    """
    if device_prefix is None:
        device_prefix = device_name_prefix
    if blob_service_client is None:
        blob_service_client = get_blob_service_client()

    deleted_count = 0

    try:
        container_client = blob_service_client.get_container_client(storage_container_name)

        # Delete all sharded counter blobs
        for shard_id in range(counter_shard_count):
            blob_name = f"{counter_blob_prefix}/{device_prefix}/shard_{shard_id:03d}.json"
            blob_client = container_client.get_blob_client(blob_name)
            try:
                blob_client.delete_blob()
                deleted_count += 1
                logger.debug(f"Deleted counter shard {shard_id} for prefix '{device_prefix}'")
            except ResourceNotFoundError:
                # Shard didn't exist, which is fine
                pass

        # Also try to delete legacy single counter (for backwards compatibility)
        legacy_blob_name = f"{counter_blob_prefix}/{device_prefix}/counter.json"
        legacy_blob_client = container_client.get_blob_client(legacy_blob_name)
        try:
            legacy_blob_client.delete_blob()
            deleted_count += 1
            logger.debug(f"Deleted legacy counter for prefix '{device_prefix}'")
        except ResourceNotFoundError:
            pass

        if deleted_count > 0:
            logger.info(f"Cleared {deleted_count} counter blob(s) for prefix '{device_prefix}'")

        return deleted_count

    except Exception as e:
        logger.error(f"Failed to clear device counter for prefix '{device_prefix}': {e}")
        return deleted_count


def list_device_counters(
    blob_service_client: Optional[BlobServiceClient] = None,
) -> list[str]:
    """List all device prefixes that have device counters.

    Args:
        blob_service_client: Optional blob service client. If None, uses global singleton.

    Returns:
        List of device prefixes that have counter blobs.
    """
    if blob_service_client is None:
        blob_service_client = get_blob_service_client()

    try:
        container_client = blob_service_client.get_container_client(storage_container_name)
        prefix = f"{counter_blob_prefix}/"
        device_prefixes: set[str] = set()

        for blob in container_client.list_blobs(name_starts_with=prefix):
            # Extract device_prefix from path like "counter/{device_prefix}/shard_000.json"
            parts = blob.name.split("/")
            if len(parts) >= 2:
                device_prefixes.add(parts[1])

        return list(device_prefixes)

    except Exception as e:
        logger.error(f"Failed to list device counters: {e}")
        return []


def clear_all_device_counters(
    blob_service_client: Optional[BlobServiceClient] = None,
) -> int:
    """Clear all device counters for all device prefixes.

    This is useful for cleanup after testing.

    Args:
        blob_service_client: Optional blob service client. If None, uses global singleton.

    Returns:
        Number of counters cleared.
    """
    if blob_service_client is None:
        blob_service_client = get_blob_service_client()

    device_prefixes = list_device_counters(blob_service_client)
    cleared_count = 0

    for device_prefix in device_prefixes:
        if clear_device_counter(device_prefix, blob_service_client):
            cleared_count += 1

    logger.info(f"Cleared {cleared_count} device counter(s)")
    return cleared_count
