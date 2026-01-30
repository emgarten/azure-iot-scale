import logging
import os
import random
import threading
from typing import Any, Optional

import gevent
import orjson
from azure.core import MatchConditions
from azure.core.exceptions import ResourceExistsError, ResourceModifiedError, ResourceNotFoundError
from azure.identity import AzureCliCredential, ChainedTokenCredential, DefaultAzureCredential
from azure.storage.blob import BlobServiceClient

from utils import require_env

logger = logging.getLogger("locust.storage")

# Storage authentication (in order of preference):
# 1. STORAGE_CONN_STR - Connection string for the storage account
# 2. STORAGE_ACCOUNT_URL - Account URL (e.g., https://<account>.blob.core.windows.net)
#    with DefaultAzureCredential (managed identity, Azure CLI, etc.)
# At least one must be set, otherwise an exception is raised in get_blob_service_client().
storage_conn_str = os.getenv("STORAGE_CONN_STR")
storage_account_url = os.getenv("STORAGE_ACCOUNT_URL")
storage_container_name = require_env("STORAGE_CONTAINER_NAME")
counter_blob_prefix = require_env("COUNTER_BLOB_PREFIX")
device_data_blob_prefix = require_env("DEVICE_DATA_BLOB_PREFIX")
device_id_range_size = int(require_env("DEVICE_ID_RANGE_SIZE"))
device_name_prefix = require_env("DEVICE_NAME_PREFIX")

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
            if storage_conn_str is not None:
                _blob_service_client = BlobServiceClient.from_connection_string(storage_conn_str)
            elif storage_account_url is not None:
                # Try Azure CLI first (fast for local dev), then fall back to DefaultAzureCredential
                # (which includes ManagedIdentity, environment vars, etc. for cloud environments)
                credential = ChainedTokenCredential(AzureCliCredential(), DefaultAzureCredential())
                _blob_service_client = BlobServiceClient(account_url=storage_account_url, credential=credential)
            else:
                raise Exception("Missing STORAGE_CONN_STR or STORAGE_ACCOUNT_URL environment variable")

    return _blob_service_client


def initialize_storage(blob_service_client: Optional[BlobServiceClient] = None) -> BlobServiceClient:
    """Initialize storage by creating containers if they don't exist.

    This should be called once at application startup to ensure all required
    containers are available.

    Args:
        blob_service_client: Optional blob service client to use. If None, uses global singleton.

    Returns:
        BlobServiceClient: The blob service client that was initialized.
    """
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

        # Check if blob exists
        if not blob_client.exists():
            logger.debug(f"No device data found for {device_name}")
            return None

        # Download and parse JSON
        blob_data = blob_client.download_blob().readall()
        data_dict = orjson.loads(blob_data)

        # Validate all required fields are present
        for field in required_fields:
            if field not in data_dict or data_dict[field] is None:
                logger.warning(f"Device data for {device_name} missing required field: {field}")
                return None

        logger.debug(f"Loaded device data for {device_name}")
        return dict(data_dict)  # Ensure proper dict type

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

        if blob_client.exists():
            blob_client.delete_blob()
            logger.debug(f"Deleted device data for {device_name}")
    except Exception as e:
        logger.error(f"Failed to delete device data for {device_name}: {e}")


def allocate_device_id_range(
    device_prefix: Optional[str] = None,
    range_size: Optional[int] = None,
    blob_service_client: Optional[BlobServiceClient] = None,
    max_retries: int = 10,
) -> tuple[int, int]:
    """Atomically allocate a range of device IDs for a worker.

    This function uses ETag-based optimistic concurrency to safely allocate
    non-overlapping ID ranges to multiple workers. Each worker gets a unique
    range of IDs to use locally without further coordination.

    Args:
        device_prefix: The device name prefix to use for isolation. If None, uses DEVICE_NAME_PREFIX.
        range_size: Number of IDs to allocate. If None, uses DEVICE_ID_RANGE_SIZE env var.
        blob_service_client: Optional blob service client. If None, uses global singleton.
        max_retries: Maximum number of retries on ETag conflict (default: 10).

    Returns:
        Tuple of (start_id, end_id) where end_id is exclusive.
        For example, (0, 1000) means IDs 0-999 are allocated.

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
    blob_name = f"{counter_blob_prefix}/{device_prefix}/counter.json"
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
                # Blob doesn't exist, start from 0
                current_next_id = 0
                etag = None

            # Calculate new range
            start_id = current_next_id
            end_id = start_id + range_size
            new_counter_data = orjson.dumps({"next_id": end_id})

            # Attempt conditional write
            if etag is None:
                # Create new blob (will fail if another worker created it first)
                try:
                    blob_client.upload_blob(new_counter_data, overwrite=False)
                except ResourceExistsError:
                    # Another worker created it, retry
                    logger.debug(f"Counter blob created by another worker, retrying (attempt {attempt + 1})")
                    gevent.sleep(random.uniform(0.1, 0.5))
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
                    # Another worker updated it, retry
                    logger.debug(f"Counter blob modified by another worker, retrying (attempt {attempt + 1})")
                    gevent.sleep(random.uniform(0.1, 0.5))
                    continue

            # Success!
            logger.info(f"Allocated device ID range [{start_id}, {end_id}) for prefix '{device_prefix}'")
            return (start_id, end_id)

        except Exception as e:
            logger.warning(f"Error allocating device ID range (attempt {attempt + 1}): {e}")
            gevent.sleep(random.uniform(0.5, 1.0))

    raise Exception(f"Failed to allocate device ID range after {max_retries} attempts")


def clear_device_counter(
    device_prefix: Optional[str] = None,
    blob_service_client: Optional[BlobServiceClient] = None,
) -> bool:
    """Clear the device counter for a specific device prefix.

    This deletes the counter blob, effectively resetting the counter to 0
    for the specified device prefix.

    Args:
        device_prefix: The device name prefix to clear. If None, uses DEVICE_NAME_PREFIX.
        blob_service_client: Optional blob service client. If None, uses global singleton.

    Returns:
        True if the counter was cleared, False if it didn't exist.
    """
    if device_prefix is None:
        device_prefix = device_name_prefix
    if blob_service_client is None:
        blob_service_client = get_blob_service_client()

    try:
        container_client = blob_service_client.get_container_client(storage_container_name)
        blob_name = f"{counter_blob_prefix}/{device_prefix}/counter.json"
        blob_client = container_client.get_blob_client(blob_name)

        if blob_client.exists():
            blob_client.delete_blob()
            logger.info(f"Cleared device counter for prefix '{device_prefix}'")
            return True
        else:
            logger.debug(f"Device counter for prefix '{device_prefix}' does not exist")
            return False

    except Exception as e:
        logger.error(f"Failed to clear device counter for prefix '{device_prefix}': {e}")
        return False


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
        device_prefixes = []

        for blob in container_client.list_blobs(name_starts_with=prefix):
            # Extract device_prefix from path like "counter/{device_prefix}/counter.json"
            parts = blob.name.split("/")
            if len(parts) >= 2:
                device_prefix = parts[1]
                if device_prefix not in device_prefixes:
                    device_prefixes.append(device_prefix)

        return device_prefixes

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
