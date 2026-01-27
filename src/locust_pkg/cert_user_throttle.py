"""Locust user for IoT Hub certificate-based device throttle testing.

This module provides a Locust user optimized for high-rate certificate request
testing. It sends requests at a configurable rate per minute, handles 429 rate
limiting gracefully, and supports storage-only mode for pre-provisioned devices.

Key differences from CertUser:
- Uses CERT_REQUESTS_PER_MINUTE for rate control (instead of CERT_REQUEST_INTERVAL)
- Supports SEND_MAX_RATE mode to send requests as fast as possible
- Always sends invalid "replace" field to avoid 409 conflicts
- Handles 429 and 412 responses as expected (not errors)
- Supports USE_STORED_DEVICES_ONLY mode for pre-provisioned device testing
"""

import logging
import os
import sys
import tempfile
import threading
import zipfile
from pathlib import Path
from typing import Any

from locust import User, constant_pacing, events, task

# Load the azure-iot-device wheel if present
wheel_path = Path("azure_iot_device-2.14.0-test-2-py3-none-any.whl")
if wheel_path.exists():
    print(f"Wheel file found at: {wheel_path.resolve()}")
    extract_dir = Path(tempfile.mkdtemp(prefix="wheel_"))
    with zipfile.ZipFile(wheel_path) as zf:
        zf.extractall(extract_dir)
    # The package top-level is typically a directory next to *.dist-info inside the wheel
    sys.path.insert(0, str(extract_dir))

from hub_cert_device import HubCertDevice  # noqa: E402
from storage import allocate_device_id_range, clear_device_counter, initialize_storage  # noqa: E402

logger = logging.getLogger("locust.cert_user_throttle")

# Whether to clear device counters on test stop (disabled by default for scale)
# Set to "true" only for small tests where you want counters reset between runs
clear_counter_on_stop = os.getenv("CLEAR_COUNTER_ON_STOP", "false").lower() == "true"


@events.test_stop.add_listener  # type: ignore[misc]
def on_test_stop(environment: Any, **kwargs: Any) -> None:
    """Optionally clean up the device counter blobs when the test stops."""
    if clear_counter_on_stop:
        logger.info("Test stopping, cleaning up device counter")
        clear_device_counter()
    else:
        logger.info("Test stopping (counter cleanup disabled for scale)")


# Environment configuration
device_name_prefix = os.getenv("DEVICE_NAME_PREFIX", "device")
devices_per_user = int(os.getenv("DEVICES_PER_USER", "1"))  # number of devices per user

# Rate configuration: requests per minute
# Default: 1 request per minute per user (across all devices)
cert_requests_per_minute = float(os.getenv("CERT_REQUESTS_PER_MINUTE", "1"))

# Max rate mode: send requests as fast as possible (no delay between requests)
# When enabled, CERT_REQUESTS_PER_MINUTE is ignored
send_max_rate = os.getenv("SEND_MAX_RATE", "false").lower() == "true"

# Storage-only mode: only use devices that already exist in storage, don't provision new ones
# This is useful for load testing with pre-provisioned devices
use_stored_devices_only = os.getenv("USE_STORED_DEVICES_ONLY", "false").lower() == "true"


def _calculate_wait_time() -> float:
    """Calculate the wait time between tasks based on requests per minute.

    If SEND_MAX_RATE is enabled, returns 0 (no delay).
    Otherwise, calculates wait time to achieve the target requests per minute.

    Returns:
        Wait time in seconds between task executions.
    """
    if send_max_rate:
        return 0.0

    if cert_requests_per_minute <= 0:
        raise ValueError("CERT_REQUESTS_PER_MINUTE must be positive")

    # seconds_per_request = 60 / requests_per_minute
    # Since we have devices_per_user devices and round-robin through them,
    # each task call handles one device, so we need to fire tasks at the target rate
    return 60.0 / cert_requests_per_minute


class CertUserThrottle(User):
    """Locust user optimized for high-rate certificate request testing.

    This user provisions and connects multiple devices (configurable via DEVICES_PER_USER),
    then requests certificate renewals at a configurable rate. It handles throttling
    (429) and precondition failures (412) gracefully without treating them as errors.

    Environment Variables:
        DEVICES_PER_USER: Number of devices per Locust user (default: 1)
        CERT_REQUESTS_PER_MINUTE: Target certificate requests per minute per user (default: 1)
        SEND_MAX_RATE: Send requests as fast as possible, ignoring CERT_REQUESTS_PER_MINUTE (default: "false")
        DEVICE_NAME_PREFIX: Prefix for device names (default: "device"), also used for counter isolation
        DEVICE_ID_RANGE_SIZE: Number of device IDs to allocate per worker (default: 2500)
        USE_STORED_DEVICES_ONLY: Only use pre-provisioned devices from storage (default: "false")
    """

    wait_time = constant_pacing(_calculate_wait_time())  # type: ignore[no-untyped-call]
    _storage_initialized: bool = False  # Class-level flag for one-time storage initialization

    # Distributed device ID range allocation (per-worker, shared across all CertUserThrottle instances)
    _id_range_lock: threading.Lock = threading.Lock()  # Lock for thread-safe ID range allocation
    _id_range_start: int = 0  # Start of allocated range (inclusive)
    _id_range_end: int = 0  # End of allocated range (exclusive)
    _id_range_current: int = 0  # Next ID to use within the range
    _id_range_allocated: bool = False  # Whether a range has been allocated

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
        device_name = f"{device_name_prefix}{device_id}"
        logger.info(f"Generated device name: {device_name}")
        return device_name

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)

        # Initialize storage once globally (similar to device counter pattern)
        if not CertUserThrottle._storage_initialized:
            logger.info("Initializing storage (one-time setup)")
            initialize_storage()
            CertUserThrottle._storage_initialized = True

        # List of devices managed by this user
        self.devices: list[HubCertDevice] = []
        self._current_device_index: int = 0  # For round-robin message sending

        logger.info(f"Starting CertUserThrottle with {devices_per_user} device(s)")

        # Create device instances only - provisioning and connecting happens lazily in request_certificate
        for i in range(devices_per_user):
            device_name = self.get_device_name()
            logger.info(f"Creating device {i + 1}/{devices_per_user}: {device_name}")

            try:
                device = HubCertDevice(device_name, self.environment)
                self.devices.append(device)
                logger.info(f"Device {device_name} created")

            except Exception as e:
                # Failure isolation - log and continue with other devices
                logger.error(f"Failed to create device {device_name}: {e}")
                continue

        logger.info(f"CertUserThrottle initialized with {len(self.devices)} device(s)")

    def on_start(self) -> None:
        """Eagerly provision and connect all devices before tasks run.

        This prevents blocking during task execution, which would break
        constant_pacing timing. Devices that fail to provision/connect
        are logged but kept in the list for retry attempts during tasks.
        """
        logger.info(f"Starting eager initialization for {len(self.devices)} device(s)")

        for i, device in enumerate(self.devices):
            logger.info(f"Initializing device {i + 1}/{len(self.devices)}: {device.device_name}")

            # Provision if not already provisioned
            if not self._is_device_provisioned(device):
                if not device.provision(storage_only=use_stored_devices_only):
                    if use_stored_devices_only:
                        logger.info(f"Device {device.device_name} not found in storage (storage-only mode)")
                    else:
                        logger.warning(f"Failed to provision device {device.device_name} during startup")
                    continue  # provision() already handles connect on success

            # Connect if provisioned but not connected (e.g., restored from storage without validation)
            if not device.is_connected:
                if not device.connect():
                    logger.warning(f"Failed to connect device {device.device_name} during startup")

        connected_count = sum(1 for d in self.devices if d.is_connected)
        logger.info(f"Eager initialization complete: {connected_count}/{len(self.devices)} devices connected")

    def _get_next_device(self) -> HubCertDevice | None:
        """Get the next device in round-robin fashion.

        Returns:
            The next device, or None if no devices exist.
        """
        if not self.devices:
            return None

        # Round-robin selection across all devices (regardless of status)
        device = self.devices[self._current_device_index % len(self.devices)]
        self._current_device_index += 1
        return device

    def _is_device_provisioned(self, device: HubCertDevice) -> bool:
        """Check if a device has been successfully provisioned.

        Args:
            device: The device to check

        Returns:
            True if the device is provisioned and assigned, False otherwise.
        """
        return device.registration_result is not None and device.registration_result.status == "assigned"

    @task
    def request_certificate(self) -> None:
        """Request a certificate renewal from the next device in round-robin order.

        Devices are eagerly initialized in on_start(), so this task should not
        block on provisioning or connection. The request_new_certificate method
        handles reconnection if the connection was lost.

        This task uses request_new_certificate() with use_invalid_replace=True
        to avoid 409 conflicts. 429 and 412 responses are expected and handled
        gracefully.
        """
        device = self._get_next_device()

        if device is None:
            logger.warning("No devices available, skipping certificate request")
            return

        # Emit time since last certificate response (if available)
        time_since_last = device.get_time_since_last_cert_response()
        if time_since_last is not None:
            logger.info(f"Device {device.device_name}: {time_since_last:.2f}s since last cert response")

        # Skip devices that failed to provision during on_start()
        if not self._is_device_provisioned(device):
            logger.debug(f"Device {device.device_name} not provisioned, skipping")
            return

        device.request_new_certificate(use_invalid_replace=True)

    def on_stop(self) -> None:
        """Cleanup method called when the user stops."""
        logger.info(f"Stopping CertUserThrottle with {len(self.devices)} device(s)")

        for device in self.devices:
            try:
                device.disconnect()
            except Exception as e:
                logger.error(f"Error disconnecting device {device.device_name}: {e}")
