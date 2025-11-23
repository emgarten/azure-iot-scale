import os
from azure.identity import DefaultAzureCredential
from azure.storage.blob import BlobServiceClient

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
