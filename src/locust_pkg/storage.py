import logging
import os
from typing import Any, Optional

import orjson
from azure.identity import DefaultAzureCredential
from azure.storage.blob import BlobServiceClient

logger = logging.getLogger("locust.storage")

storage_conn_str = os.getenv("STORAGE_CONN_STR")
storage_container_name = os.getenv("STORAGE_CONTAINER_NAME", "scale")
counter_blob_prefix = os.getenv("COUNTER_BLOB_PREFIX", "counter")
device_data_blob_prefix = os.getenv("DEVICE_DATA_BLOB_PREFIX", "data")


def get_blob_service_client() -> BlobServiceClient:
    if storage_conn_str is None:
        # Use default Azure credentials (managed identity, Azure CLI, etc.)
        storage_account_url = os.getenv("STORAGE_ACCOUNT_URL")
        if storage_account_url is None:
            raise Exception("Missing STORAGE_CONN_STR or STORAGE_ACCOUNT_URL environment variable")
        credential = DefaultAzureCredential()
        return BlobServiceClient(account_url=storage_account_url, credential=credential)
    return BlobServiceClient.from_connection_string(storage_conn_str)


def save_device_data(device_name: str, data_dict: dict[str, Any]) -> None:
    """Save device data to Azure Blob Storage.

    Args:
        device_name: Name of the device
        data_dict: Dictionary containing device data to save

    The data is saved as JSON and will overwrite any existing data for this device.
    """
    try:
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


def load_device_data(device_name: str) -> Optional[dict[str, Any]]:
    """Load device data from Azure Blob Storage.

    Args:
        device_name: Name of the device

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


def delete_device_data(device_name: str) -> None:
    """Delete device data from Azure Blob Storage.

    Args:
        device_name: Name of the device
    """
    try:
        blob_service_client = get_blob_service_client()
        container_client = blob_service_client.get_container_client(storage_container_name)
        blob_name = f"{device_data_blob_prefix}/{device_name}/registration.json"
        blob_client = container_client.get_blob_client(blob_name)

        if blob_client.exists():
            blob_client.delete_blob()
            logger.debug(f"Deleted device data for {device_name}")
    except Exception as e:
        logger.error(f"Failed to delete device data for {device_name}: {e}")
