"""Azure Device Registry (ADR) utility functions.

This module provides reusable functions for interacting with Azure Device Registry
via the Azure Resource Manager (ARM) API.
"""

import logging
import secrets
import threading
import time
from datetime import datetime, timezone
from typing import Any, Callable, Optional

import gevent
import requests
from azure.core.credentials import AccessToken
from azure.identity import AzureCliCredential, ChainedTokenCredential, DefaultAzureCredential
from requests.adapters import HTTPAdapter

logger = logging.getLogger("locust.adr_utils")

# Constants
API_VERSION = "2025-11-01-preview"
ARM_BASE_URL = "https://management.azure.com"
ARM_SCOPE = "https://management.azure.com/.default"
POLL_INTERVAL_SECONDS = 2
MAX_POLL_ATTEMPTS = 60
REQUEST_TIMEOUT_SECONDS = 30

# Global credential and token singleton with thread-safe initialization
_credential: Optional[ChainedTokenCredential] = None
_credential_lock: threading.Lock = threading.Lock()
_cached_token: Optional[AccessToken] = None
_token_lock: threading.Lock = threading.Lock()

# Global session singleton with connection pooling for efficient HTTP reuse
_session: Optional[requests.Session] = None
_session_lock: threading.Lock = threading.Lock()


def _get_session() -> requests.Session:
    """Get or create the global session singleton with connection pooling.

    Thread-safe: Uses double-checked locking pattern for efficient singleton initialization.
    The session is configured with a large connection pool to support high concurrency
    in scale testing scenarios.

    Returns:
        requests.Session: The global session instance with connection pooling.
    """
    global _session

    # Fast path: if already initialized, return immediately
    if _session is not None:
        return _session

    # Slow path: acquire lock and check again (double-checked locking)
    with _session_lock:
        if _session is None:
            _session = requests.Session()
            # Configure connection pool for high concurrency
            adapter = HTTPAdapter(
                pool_connections=100,  # Number of connection pools (per host)
                pool_maxsize=100,  # Max connections per pool
                max_retries=0,  # We handle retries ourselves in adr_user.py
            )
            _session.mount("https://", adapter)
            _session.mount("http://", adapter)
            logger.info("Initialized HTTP session with connection pooling (pool_maxsize=100)")

    return _session


def _get_credential() -> ChainedTokenCredential:
    """Get or create the global credential singleton.

    Thread-safe: Uses double-checked locking pattern for efficient singleton initialization.

    Returns:
        ChainedTokenCredential: The global credential instance.
    """
    global _credential

    # Fast path: if already initialized, return immediately
    if _credential is not None:
        return _credential

    # Slow path: acquire lock and check again (double-checked locking)
    with _credential_lock:
        if _credential is None:
            # Try Azure CLI first (fast for local dev), then fall back to DefaultAzureCredential
            # (which includes ManagedIdentity, environment vars, etc. for cloud environments)
            _credential = ChainedTokenCredential(AzureCliCredential(), DefaultAzureCredential())
            logger.info("Initialized Azure credential chain")

    return _credential


def get_adr_token() -> str:
    """Get a valid ARM access token, refreshing if expired.

    Thread-safe: Uses locking to prevent concurrent token refresh.

    Returns:
        str: A valid access token for ARM API calls.
    """
    global _cached_token

    with _token_lock:
        # Check if we have a valid cached token (with 5 minute buffer)
        if _cached_token is not None:
            # Token expires_on is a Unix timestamp
            if _cached_token.expires_on > time.time() + 300:
                return _cached_token.token

        # Get a new token
        credential = _get_credential()
        _cached_token = credential.get_token(ARM_SCOPE)
        logger.debug("Refreshed ARM access token")
        return _cached_token.token


def _get_headers(token: str) -> dict[str, str]:
    """Build standard headers for ARM API requests.

    Args:
        token: The access token to use for authorization.

    Returns:
        dict: Headers dictionary with Authorization and Content-Type.
    """
    return {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }


def _raise_for_status_with_body(response: requests.Response) -> None:
    """Raise HTTPError with response body included in the message.

    Args:
        response: The response to check.

    Raises:
        requests.HTTPError: If the response status code indicates an error.
    """
    if response.status_code >= 400:
        try:
            error_body = response.json()
        except Exception:
            error_body = response.text
        raise requests.HTTPError(
            f"{response.status_code} {response.reason} for url: {response.url}\nResponse: {error_body}",
            response=response,
        )


def poll_async_operation(
    url: str,
    token: str,
    operation_name: str = "async_operation",
    on_poll: Optional[Callable[[int, str, float], None]] = None,
) -> dict[str, Any]:
    """Poll an Azure async operation until completion.

    Args:
        url: The async operation URL to poll.
        token: The access token to use for authorization.
        operation_name: Name for logging purposes (e.g., "create_device").
        on_poll: Optional callback called after each poll attempt with
                 (attempt_number, status, elapsed_seconds). Can be used
                 to fire Locust events or custom logging.

    Returns:
        dict: The final operation result.

    Raises:
        RuntimeError: If the operation fails or is canceled.
        TimeoutError: If the operation does not complete within the timeout.
    """
    headers = _get_headers(token)
    poll_start_time = time.time()

    logger.info(f"Starting async polling for {operation_name} (max {MAX_POLL_ATTEMPTS} attempts)")

    for attempt in range(MAX_POLL_ATTEMPTS):
        response = _get_session().get(url, headers=headers, timeout=REQUEST_TIMEOUT_SECONDS)
        response.raise_for_status()
        result: dict[str, Any] = response.json()

        status = result.get("status", "").lower()
        elapsed = time.time() - poll_start_time

        if on_poll is not None:
            on_poll(attempt + 1, status, elapsed)

        if status == "succeeded":
            logger.info(f"Async {operation_name} succeeded after {attempt + 1} poll(s), {elapsed:.1f}s total")
            return result
        elif status in ("failed", "canceled"):
            error = result.get("error", {})
            logger.error(f"Async {operation_name} {status} after {attempt + 1} poll(s): {error.get('message')}")
            raise RuntimeError(f"Async operation {status}: {error.get('message', 'Unknown error')}")

        # Log progress every 5 attempts or on first attempt
        if attempt == 0 or (attempt + 1) % 5 == 0:
            logger.info(
                f"Polling {operation_name}: attempt {attempt + 1}/{MAX_POLL_ATTEMPTS}, status={status}, elapsed={elapsed:.1f}s"
            )

        gevent.sleep(POLL_INTERVAL_SECONDS)

    elapsed = time.time() - poll_start_time
    logger.error(f"Async {operation_name} timed out after {MAX_POLL_ATTEMPTS} polls, {elapsed:.1f}s")
    raise TimeoutError(f"Async operation did not complete after {MAX_POLL_ATTEMPTS * POLL_INTERVAL_SECONDS} seconds")


def create_adr_device(
    subscription_id: str,
    resource_group: str,
    namespace: str,
    device_name: str,
    location: str,
    token: Optional[str] = None,
    on_poll: Optional[Callable[[int, str, float], None]] = None,
) -> dict[str, Any]:
    """Create a device in an ADR namespace via PUT.

    Args:
        subscription_id: Azure subscription ID.
        resource_group: Resource group name.
        namespace: ADR namespace name.
        device_name: Name for the new device.
        location: Azure location for the device.
        token: Optional access token. If None, will be fetched automatically.
        on_poll: Optional callback for async polling progress. See poll_async_operation.

    Returns:
        dict: The created device resource.

    Raises:
        requests.HTTPError: If the API call fails.
    """
    create_start_time = time.time()

    if token is None:
        token = get_adr_token()

    url = (
        f"{ARM_BASE_URL}/subscriptions/{subscription_id}/resourceGroups/{resource_group}"
        f"/providers/Microsoft.DeviceRegistry/namespaces/{namespace}/devices/{device_name}"
        f"?api-version={API_VERSION}"
    )

    headers = _get_headers(token)
    headers["If-None-Match"] = "*"  # Only create if device doesn't exist (returns 412 if exists)
    created_at = int(datetime.now(timezone.utc).timestamp())
    external_device_id = f"ext-{device_name}"

    payload = {
        "location": location,
        "properties": {
            "enabled": True,
            "externalDeviceId": external_device_id,
            "operatingSystem": "Linux",
            "attributes": {
                "updateCount": 0,
                "createdAt": created_at,
            },
        },
    }

    logger.info(f"Sending PUT request for device: {device_name}")
    response = _get_session().put(url, headers=headers, json=payload, timeout=REQUEST_TIMEOUT_SECONDS)
    put_elapsed = time.time() - create_start_time
    logger.info(f"PUT response for {device_name}: status={response.status_code}, elapsed={put_elapsed:.1f}s")

    _raise_for_status_with_body(response)

    # Handle long-running operation
    if response.status_code in (201, 202):
        async_url = response.headers.get("Azure-AsyncOperation") or response.headers.get("Location")
        if async_url:
            logger.info(f"Device {device_name} requires async polling (status={response.status_code})")
            poll_async_operation(async_url, token, operation_name=f"create_{device_name}", on_poll=on_poll)
    else:
        logger.info(f"Device {device_name} created synchronously (status={response.status_code})")

    total_elapsed = time.time() - create_start_time
    logger.info(f"Device {device_name} creation complete, total time: {total_elapsed:.1f}s")

    result: dict[str, Any] = response.json()
    return result


def patch_adr_device_os_version(
    subscription_id: str,
    resource_group: str,
    namespace: str,
    device_name: str,
    token: Optional[str] = None,
) -> tuple[dict[str, Any], str]:
    """PATCH a device with a random OS version.

    Args:
        subscription_id: Azure subscription ID.
        resource_group: Resource group name.
        namespace: ADR namespace name.
        device_name: Name of the device to update.
        token: Optional access token. If None, will be fetched automatically.

    Returns:
        tuple: (updated device resource, new OS version string)

    Raises:
        requests.HTTPError: If the API call fails.
    """
    if token is None:
        token = get_adr_token()

    url = (
        f"{ARM_BASE_URL}/subscriptions/{subscription_id}/resourceGroups/{resource_group}"
        f"/providers/Microsoft.DeviceRegistry/namespaces/{namespace}/devices/{device_name}"
        f"?api-version={API_VERSION}"
    )

    headers = _get_headers(token)
    # Generate random version like "5.15.146"
    os_version = f"{secrets.randbelow(10)}.{secrets.randbelow(100)}.{secrets.randbelow(1000)}"

    payload = {
        "properties": {
            "operatingSystemVersion": os_version,
        },
    }

    response = _get_session().patch(url, headers=headers, json=payload, timeout=REQUEST_TIMEOUT_SECONDS)
    _raise_for_status_with_body(response)

    # Handle long-running operation
    if response.status_code in (201, 202):
        async_url = response.headers.get("Azure-AsyncOperation") or response.headers.get("Location")
        if async_url:
            logger.debug(f"Waiting for device update to complete: {device_name}")
            poll_async_operation(async_url, token)

    result: dict[str, Any] = response.json()
    return result, os_version


def get_adr_device(
    subscription_id: str,
    resource_group: str,
    namespace: str,
    device_name: str,
    token: Optional[str] = None,
) -> dict[str, Any]:
    """Get a device from an ADR namespace via GET.

    Args:
        subscription_id: Azure subscription ID.
        resource_group: Resource group name.
        namespace: ADR namespace name.
        device_name: Name of the device to retrieve.
        token: Optional access token. If None, will be fetched automatically.

    Returns:
        dict: The device resource.

    Raises:
        requests.HTTPError: If the API call fails.
    """
    if token is None:
        token = get_adr_token()

    url = (
        f"{ARM_BASE_URL}/subscriptions/{subscription_id}/resourceGroups/{resource_group}"
        f"/providers/Microsoft.DeviceRegistry/namespaces/{namespace}/devices/{device_name}"
        f"?api-version={API_VERSION}"
    )

    headers = _get_headers(token)

    response = _get_session().get(url, headers=headers, timeout=REQUEST_TIMEOUT_SECONDS)
    _raise_for_status_with_body(response)

    result: dict[str, Any] = response.json()
    return result


def delete_adr_device(
    subscription_id: str,
    resource_group: str,
    namespace: str,
    device_name: str,
    token: Optional[str] = None,
) -> bool:
    """Delete a device from an ADR namespace.

    Args:
        subscription_id: Azure subscription ID.
        resource_group: Resource group name.
        namespace: ADR namespace name.
        device_name: Name of the device to delete.
        token: Optional access token. If None, will be fetched automatically.

    Returns:
        bool: True if device was deleted, False if it didn't exist.

    Raises:
        requests.HTTPError: If the API call fails (other than 404).
    """
    if token is None:
        token = get_adr_token()

    url = (
        f"{ARM_BASE_URL}/subscriptions/{subscription_id}/resourceGroups/{resource_group}"
        f"/providers/Microsoft.DeviceRegistry/namespaces/{namespace}/devices/{device_name}"
        f"?api-version={API_VERSION}"
    )

    headers = _get_headers(token)

    response = _get_session().delete(url, headers=headers, timeout=REQUEST_TIMEOUT_SECONDS)

    # 404 means device doesn't exist, which is fine for cleanup
    if response.status_code == 404:
        logger.debug(f"Device {device_name} not found (already deleted)")
        return False

    _raise_for_status_with_body(response)

    # Handle long-running operation
    if response.status_code in (202,):
        async_url = response.headers.get("Azure-AsyncOperation") or response.headers.get("Location")
        if async_url:
            logger.debug(f"Waiting for device deletion to complete: {device_name}")
            poll_async_operation(async_url, token)

    return True
