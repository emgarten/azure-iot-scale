"""Locust user for Azure Device Registry (ADR) GET and PATCH operations.

This module provides a Locust user that manages multiple ADR devices using
distributed device ID allocation. It creates devices on startup with robust
retry handling, then performs GET (70%) and PATCH (30%) operations in
round-robin fashion across all devices.
"""

import logging
import threading
import time
from typing import Any

import requests
from locust import User, constant_pacing, events, task

from adr_utils import create_adr_device, get_adr_device, get_adr_token, patch_adr_device_os_version
from storage import allocate_device_id_range, clear_device_counter, initialize_storage
from utils import config

logger = logging.getLogger("locust.adr_user")


@events.test_stop.add_listener  # type: ignore[misc]
def on_test_stop(environment: Any, **kwargs: Any) -> None:
    """Clean up the device counter blob when the test stops."""
    logger.info("Test stopping, cleaning up device counter")
    clear_device_counter()


class AdrUser(User):
    """Locust user that manages multiple ADR devices for GET/PATCH testing.

    This user allocates a range of device IDs, creates all devices on startup
    with robust retry handling, then performs GET and PATCH operations in
    round-robin fashion across all devices.

    Environment Variables:
        ADR_SUBSCRIPTION_ID (required): Azure subscription ID
        ADR_RESOURCE_GROUP (required): Resource group name
        ADR_NAMESPACE (required): ADR namespace name
        ADR_LOCATION (required): Azure location for devices
        DEVICE_NAME_PREFIX (optional): Device name prefix (default: "device")
        ADR_REQUEST_INTERVAL (optional): Seconds between requests (default: 5)
        DEVICES_PER_USER (optional): Number of devices per user (default: 1)
        DEVICE_ID_RANGE_SIZE (optional): IDs to allocate per worker (default: 2500)
    """

    _storage_initialized: bool = False  # Class-level flag for one-time storage initialization

    # Distributed device ID range allocation (per-worker, shared across all AdrUser instances)
    _id_range_lock: threading.Lock = threading.Lock()  # Lock for thread-safe ID range allocation
    _id_range_start: int = 0  # Start of allocated range (inclusive)
    _id_range_end: int = 0  # End of allocated range (exclusive)
    _id_range_current: int = 0  # Next ID to use within the range
    _id_range_allocated: bool = False  # Whether a range has been allocated

    def wait_time(self) -> float:
        """Calculate wait time between tasks using lazy config."""
        interval = config.get_int("ADR_REQUEST_INTERVAL")
        devices = config.get_int("DEVICES_PER_USER")
        result: float = constant_pacing(interval / devices)(self)  # type: ignore[no-untyped-call]
        return result

    @classmethod
    def _ensure_id_range_unlocked(cls) -> None:
        """Ensure an ID range is allocated for this worker (must hold _id_range_lock).

        This method allocates a new range from Azure Blob Storage if:
        - No range has been allocated yet, or
        - The current range is exhausted

        The allocation is atomic and uses ETag-based optimistic concurrency
        to ensure non-overlapping ranges across all workers.

        Note: Caller must hold _id_range_lock before calling this method.
        """
        if cls._id_range_current >= cls._id_range_end:
            device_name_prefix = config.get("DEVICE_NAME_PREFIX")
            logger.info(f"Allocating new device ID range for prefix '{device_name_prefix}'")
            cls._id_range_start, cls._id_range_end = allocate_device_id_range(device_name_prefix)
            cls._id_range_current = cls._id_range_start
            cls._id_range_allocated = True
            logger.info(f"Allocated device ID range [{cls._id_range_start}, {cls._id_range_end})")

    @classmethod
    def get_device_name(cls) -> str:
        """Generate a unique device name using the prefix and a distributed counter.

        This method ensures device names are unique across all workers by:
        1. Allocating non-overlapping ID ranges from Azure Blob Storage
        2. Using IDs from the allocated range locally without coordination
        3. Automatically allocating a new range when the current one is exhausted

        Thread-safe: Uses a lock to prevent concurrent access from multiple threads.

        Returns:
            A unique device name in the format "{prefix}{id}"
        """
        with cls._id_range_lock:
            cls._ensure_id_range_unlocked()
            device_id = cls._id_range_current
            cls._id_range_current += 1
        device_name = f"{config.get('DEVICE_NAME_PREFIX')}{device_id}"
        logger.info(f"Generated device name: {device_name}")
        return device_name

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)

        # Initialize storage once globally
        if not AdrUser._storage_initialized:
            logger.info("Initializing storage (one-time setup)")
            initialize_storage()
            AdrUser._storage_initialized = True

        # List of device names managed by this user
        self.device_names: list[str] = []
        self._current_device_index: int = 0  # For round-robin selection

        devices_per_user = config.get_int("DEVICES_PER_USER")
        logger.info(f"Starting AdrUser with {devices_per_user} device(s)")

        # Generate device names
        for i in range(devices_per_user):
            device_name = self.get_device_name()
            self.device_names.append(device_name)
            logger.info(f"Allocated device name {i + 1}/{devices_per_user}: {device_name}")

        logger.info(f"AdrUser initialized with {len(self.device_names)} device(s)")

    def _fire_request_event(
        self,
        name: str,
        start_time: float,
        exception: BaseException | None = None,
        response_length: int = 0,
    ) -> None:
        """Fire a Locust request event to report metrics.

        Args:
            name: The request name (e.g., "create_device", "patch_device").
            start_time: The time.time() when the request started.
            exception: Optional exception if the request failed.
            response_length: Optional response length in bytes.
        """
        # If exception is an HTTPError with a response, include status code in name
        event_name = name
        if exception is not None and isinstance(exception, requests.HTTPError):
            if exception.response is not None:
                event_name = f"{name}_{exception.response.status_code}"

        response_time = (time.time() - start_time) * 1000  # Convert to milliseconds
        self.environment.events.request.fire(
            request_type="ADR",
            name=event_name,
            response_time=response_time,
            response_length=response_length,
            exception=exception,
            context={},
        )

    def _create_device_with_retry(self, device_name: str) -> bool:
        """Create device with indefinite retry on transient errors.

        Args:
            device_name: Name of the device to create.

        Returns:
            True if device was created or already exists.
        """
        backoff = 1.0
        max_backoff = 60.0

        # Pre-fetch token once to ensure auth is working
        get_adr_token()

        while True:
            start_time = time.time()
            try:
                create_adr_device(
                    subscription_id=config.get("ADR_SUBSCRIPTION_ID"),
                    resource_group=config.get("ADR_RESOURCE_GROUP"),
                    namespace=config.get("ADR_NAMESPACE"),
                    device_name=device_name,
                    location=config.get("ADR_LOCATION"),
                )
                self._fire_request_event("create_device", start_time)
                logger.info(f"Device created: {device_name}")
                return True

            except requests.HTTPError as e:
                status = e.response.status_code if e.response else 0

                if status == 409:  # Already exists - noop
                    logger.info(f"Device already exists: {device_name}")
                    self._fire_request_event("create_device", start_time)
                    return True
                elif status == 429:  # Throttled
                    retry_after = float(e.response.headers.get("Retry-After", backoff)) if e.response else backoff
                    logger.warning(f"Throttled creating {device_name}, retrying after {retry_after}s")
                    self._fire_request_event("create_device", start_time, exception=e)
                    time.sleep(retry_after)
                elif status >= 500:  # Server error
                    logger.warning(f"Server error creating {device_name}: {status}, retrying after {backoff}s")
                    self._fire_request_event("create_device", start_time, exception=e)
                    time.sleep(backoff)
                    backoff = min(backoff * 2, max_backoff)
                else:  # Non-retryable client error
                    logger.error(f"Failed to create device {device_name}: {e}")
                    self._fire_request_event("create_device", start_time, exception=e)
                    raise

            except Exception as e:
                logger.error(f"Unexpected error creating device {device_name}: {e}")
                self._fire_request_event("create_device", start_time, exception=e)
                time.sleep(backoff)
                backoff = min(backoff * 2, max_backoff)

    def on_start(self) -> None:
        """Create all devices on startup with robust retry handling."""
        logger.info(f"Creating {len(self.device_names)} device(s)")

        for i, device_name in enumerate(self.device_names):
            logger.info(f"Creating device {i + 1}/{len(self.device_names)}: {device_name}")
            self._create_device_with_retry(device_name)

        logger.info(f"All {len(self.device_names)} device(s) created")

    def _get_next_device_name(self) -> str | None:
        """Get the next device name in round-robin fashion.

        Returns:
            The next device name, or None if no devices exist.
        """
        if not self.device_names:
            return None

        device_name = self.device_names[self._current_device_index % len(self.device_names)]
        self._current_device_index += 1
        return device_name

    @task(weight=70)
    def get_device(self) -> None:
        """GET a device in round-robin order."""
        device_name = self._get_next_device_name()

        if device_name is None:
            logger.warning("No devices available, skipping get")
            return

        start_time = time.time()

        try:
            result = get_adr_device(
                subscription_id=config.get("ADR_SUBSCRIPTION_ID"),
                resource_group=config.get("ADR_RESOURCE_GROUP"),
                namespace=config.get("ADR_NAMESPACE"),
                device_name=device_name,
            )
            # Estimate response size from JSON
            import json

            response_length = len(json.dumps(result))
            self._fire_request_event("get_device", start_time, response_length=response_length)
            logger.debug(f"Got device {device_name}")

        except Exception as e:
            logger.error(f"Failed to get device {device_name}: {e}")
            self._fire_request_event("get_device", start_time, exception=e)

    @task(weight=30)
    def patch_device(self) -> None:
        """PATCH a device's operatingSystemVersion field in round-robin order."""
        device_name = self._get_next_device_name()

        if device_name is None:
            logger.warning("No devices available, skipping patch")
            return

        start_time = time.time()

        try:
            result, os_version = patch_adr_device_os_version(
                subscription_id=config.get("ADR_SUBSCRIPTION_ID"),
                resource_group=config.get("ADR_RESOURCE_GROUP"),
                namespace=config.get("ADR_NAMESPACE"),
                device_name=device_name,
            )
            # Estimate response size from JSON
            import json

            response_length = len(json.dumps(result))
            self._fire_request_event("patch_device", start_time, response_length=response_length)
            logger.debug(f"Patched device {device_name} with OS version: {os_version}")

        except Exception as e:
            logger.error(f"Failed to patch device {device_name}: {e}")
            self._fire_request_event("patch_device", start_time, exception=e)
