import logging
import os
import random
import resource
import threading
from typing import Any, Optional

import gevent
import orjson
from azure.core.exceptions import ResourceExistsError, ResourceNotFoundError
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
device_id_range_size = int(os.getenv("DEVICE_ID_RANGE_SIZE", "2000"))
device_name_prefix = os.getenv("DEVICE_NAME_PREFIX", "scale-device-")

# Counter sharding: number of counter partitions to reduce contention
# With N shards, max N workers can allocate simultaneously without conflict
counter_shard_count = int(os.getenv("COUNTER_SHARD_COUNT", "50"))

# Shard capacity: maximum IDs per shard (determines shard offset spacing)
# Each engine gets exclusive access to one shard via leasing
# Default: 10000 IDs per shard (supports 2500 users with 4 devices each per engine)
shard_capacity = int(os.getenv("SHARD_CAPACITY", "2000"))

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


# Module-level state for shard leasing
_leased_shard_id: Optional[int] = None
_shard_lease_id: Optional[str] = None
_shard_blob_client: Optional[Any] = None  # BlobClient for the leased shard
_shard_lock: threading.Lock = threading.Lock()


def release_shard_lease() -> None:
    """Release the shard lease acquired by this engine.

    This should be called when the test stops to free the shard for
    future runs. Without this, infinite-duration leases persist on
    the shard blobs and can only be broken manually.

    Uses break_lease() which works unconditionally on infinite-duration
    leases, regardless of lease state.

    Safe to call multiple times or when no lease is held.
    """
    global _leased_shard_id, _shard_lease_id, _shard_blob_client

    with _shard_lock:
        if _shard_blob_client is not None:
            try:
                _shard_blob_client.break_lease(lease_break_period=0)
                logger.info(f"Broke lease on shard {_leased_shard_id}")
            except Exception as e:
                logger.warning(f"Failed to break lease on shard {_leased_shard_id}: {e}")

        _leased_shard_id = None
        _shard_lease_id = None
        _shard_blob_client = None


def _get_shard_blob_name(shard_id: int, device_prefix: str, hub_index: Optional[int]) -> str:
    """Build the blob path for a shard."""
    if hub_index is not None:
        return f"{counter_blob_prefix}/hub_{hub_index}/{device_prefix}/shard_{shard_id:03d}.json"
    return f"{counter_blob_prefix}/{device_prefix}/shard_{shard_id:03d}.json"


def _acquire_shard_lease(
    device_prefix: str,
    hub_index: Optional[int],
    blob_service_client: BlobServiceClient,
) -> tuple[int, Any, str]:
    """Acquire an exclusive lease on an available shard.

    Iterates through all shards and acquires a lease on the first available one.
    This ensures each engine gets exactly one shard with no overlap.

    Args:
        device_prefix: The device name prefix for isolation.
        hub_index: Optional hub index for per-hub isolation.
        blob_service_client: The blob service client.

    Returns:
        Tuple of (shard_id, blob_client, lease_id).

    Raises:
        Exception: If no shards are available (all leased by other engines).
    """
    container_client = blob_service_client.get_container_client(storage_container_name)

    # Try each shard in order until we get a lease
    for shard_id in range(counter_shard_count):
        blob_name = _get_shard_blob_name(shard_id, device_prefix, hub_index)
        blob_client = container_client.get_blob_client(blob_name)

        try:
            # Ensure blob exists before trying to lease
            try:
                blob_client.get_blob_properties()
            except ResourceNotFoundError:
                # Create the blob with initial counter
                try:
                    blob_client.upload_blob(orjson.dumps({"next_id": 0}), overwrite=False)
                    logger.debug(f"Created shard blob {shard_id}")
                except ResourceExistsError:
                    pass  # Another engine created it, that's fine

            # Try to acquire a lease (-1 = infinite duration)
            lease_client = blob_client.acquire_lease(lease_duration=-1)
            lease_id = lease_client.id
            hub_info = f", hub {hub_index}" if hub_index is not None else ""
            logger.info(f"Acquired lease on shard {shard_id} for prefix '{device_prefix}'{hub_info}")
            return (shard_id, blob_client, lease_id)

        except Exception as e:
            # Lease failed (likely already leased by another engine)
            logger.debug(f"Could not acquire lease on shard {shard_id}: {e}")
            continue

    raise Exception(f"No available shards - all {counter_shard_count} shards are leased by other engines")


def allocate_device_id_range(
    device_prefix: Optional[str] = None,
    range_size: Optional[int] = None,
    blob_service_client: Optional[BlobServiceClient] = None,
    max_retries: int = 50,
    storage_only_mode: bool = False,
    hub_index: Optional[int] = None,
) -> tuple[int, int]:
    """Atomically allocate a range of device IDs for a worker using leased shards.

    This function uses blob leasing to ensure each engine gets exclusive access
    to exactly one shard. The lease is held for the lifetime of the engine,
    preventing other engines from using the same shard.

    Sharding strategy:
    - Each engine acquires an exclusive lease on one shard (first available)
    - The leased shard is used for all ID allocations by that engine
    - Each shard has its own ID space offset by shard_id * SHARD_CAPACITY
    - SHARD_CAPACITY determines max IDs per shard (default 10000)
    - DEVICE_ID_RANGE_SIZE determines IDs allocated per call (default 1000)
    - This guarantees non-overlapping IDs across engines

    When hub_index is provided, the ID ranges are isolated per hub. Each hub
    gets its own folder and independent counter shards, so device IDs are
    allocated starting from 0 for each hub independently.

    Args:
        device_prefix: The device name prefix to use for isolation. If None, uses DEVICE_NAME_PREFIX.
        range_size: Number of IDs to allocate. If None, uses DEVICE_ID_RANGE_SIZE env var.
        blob_service_client: Optional blob service client. If None, uses global singleton.
        max_retries: Maximum number of retries on ETag conflict (default: 50 for scale).
        storage_only_mode: If True, ignore existing counter and start from 0 for testing.
        hub_index: Optional hub index for per-hub ID isolation. If provided, counter shards
            are stored in a hub-specific folder (hub_{hub_index}/{device_prefix}).

    Returns:
        Tuple of (start_id, end_id) where end_id is exclusive.
        For example, (0, 1000) means IDs 0-999 are allocated.

    Raises:
        Exception: If no shards are available or allocation fails.
    """
    global _leased_shard_id, _shard_lease_id, _shard_blob_client

    if device_prefix is None:
        device_prefix = device_name_prefix
    if range_size is None:
        range_size = device_id_range_size
    if blob_service_client is None:
        blob_service_client = get_blob_service_client()

    with _shard_lock:
        # Acquire a shard lease if we don't have one yet
        if _leased_shard_id is None:
            _leased_shard_id, _shard_blob_client, _shard_lease_id = _acquire_shard_lease(
                device_prefix, hub_index, blob_service_client
            )

        shard_id = _leased_shard_id
        blob_client = _shard_blob_client
        lease_id = _shard_lease_id

    # These should never be None after _acquire_shard_lease succeeds
    assert shard_id is not None and blob_client is not None and lease_id is not None

    # Calculate shard offset - each shard gets shard_capacity IDs of space
    # This is separate from range_size which is how many IDs are allocated per call
    shard_offset = shard_id * shard_capacity + (hub_index * 500000 if hub_index is not None else 0)

    for attempt in range(max_retries):
        try:
            # Read current counter (with lease)
            try:
                download_result = blob_client.download_blob(lease=lease_id)
                blob_data = download_result.readall()
                counter_data = orjson.loads(blob_data)

                if storage_only_mode:
                    current_next_id = 0
                else:
                    current_next_id = counter_data.get("next_id", 0)
            except ResourceNotFoundError:
                current_next_id = 0

            # Calculate new range (within shard space)
            shard_start_id = current_next_id
            shard_end_id = shard_start_id + range_size
            new_counter_data = orjson.dumps({"next_id": shard_end_id})

            # Global IDs include shard offset
            global_start_id = shard_offset + shard_start_id
            global_end_id = shard_offset + shard_end_id

            # Write with lease (no ETag needed since we hold the lease)
            blob_client.upload_blob(new_counter_data, overwrite=True, lease=lease_id)

            # Success!
            hub_info = f", hub {hub_index}" if hub_index is not None else ""
            logger.info(
                f"Allocated device ID range [{global_start_id}, {global_end_id}) "
                f"for prefix '{device_prefix}' (shard {shard_id}{hub_info})"
            )
            return (global_start_id, global_end_id)

        except Exception as e:
            logger.warning(f"Error allocating device ID range (attempt {attempt + 1}): {e}")
            gevent.sleep(random.uniform(0.5, 1.0))

    raise Exception(f"Failed to allocate device ID range after {max_retries} attempts")


def clear_device_counter(
    device_prefix: Optional[str] = None,
    blob_service_client: Optional[BlobServiceClient] = None,
    hub_index: Optional[int] = None,
) -> int:
    """Clear all counter shards for a specific device prefix.

    This deletes all counter shard blobs, effectively resetting the counters
    for the specified device prefix. Handles both old single-counter format
    and new sharded format.

    When hub_index is provided, only clears counters in the hub-specific folder.

    Args:
        device_prefix: The device name prefix to clear. If None, uses DEVICE_NAME_PREFIX.
        blob_service_client: Optional blob service client. If None, uses global singleton.
        hub_index: Optional hub index for per-hub counter isolation. If provided, only
            clears counters in the hub-specific folder (hub_{hub_index}/{device_prefix}).

    Returns:
        Number of counter blobs deleted.
    """
    if device_prefix is None:
        device_prefix = device_name_prefix
    if blob_service_client is None:
        blob_service_client = get_blob_service_client()

    deleted_count = 0
    hub_info = f", hub {hub_index}" if hub_index is not None else ""

    try:
        container_client = blob_service_client.get_container_client(storage_container_name)

        # Delete all sharded counter blobs
        for shard_id in range(counter_shard_count):
            if hub_index is not None:
                blob_name = f"{counter_blob_prefix}/hub_{hub_index}/{device_prefix}/shard_{shard_id:03d}.json"
            else:
                blob_name = f"{counter_blob_prefix}/{device_prefix}/shard_{shard_id:03d}.json"
            blob_client = container_client.get_blob_client(blob_name)
            try:
                blob_client.delete_blob()
                deleted_count += 1
                logger.debug(f"Deleted counter shard {shard_id} for prefix '{device_prefix}'{hub_info}")
            except ResourceNotFoundError:
                # Shard didn't exist, which is fine
                pass

        # Also try to delete legacy single counter (for backwards compatibility)
        if hub_index is not None:
            legacy_blob_name = f"{counter_blob_prefix}/hub_{hub_index}/{device_prefix}/counter.json"
        else:
            legacy_blob_name = f"{counter_blob_prefix}/{device_prefix}/counter.json"
        legacy_blob_client = container_client.get_blob_client(legacy_blob_name)
        try:
            legacy_blob_client.delete_blob()
            deleted_count += 1
            logger.debug(f"Deleted legacy counter for prefix '{device_prefix}'{hub_info}")
        except ResourceNotFoundError:
            pass

        if deleted_count > 0:
            logger.info(f"Cleared {deleted_count} counter blob(s) for prefix '{device_prefix}'{hub_info}")

        return deleted_count

    except Exception as e:
        logger.error(f"Failed to clear device counter for prefix '{device_prefix}'{hub_info}: {e}")
        return deleted_count
