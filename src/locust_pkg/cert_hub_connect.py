"""Locust user for IoT Hub connect/disconnect scale testing.

This module provides a Locust user that tests IoT Hub connect/disconnect operations
at scale. Unlike CertUser which keeps connections open for certificate requests,
this user connects and disconnects as part of each task iteration.
"""

import logging
import sys
import tempfile
import threading
import zipfile
from pathlib import Path
from typing import Any

from locust import User, constant_pacing, events, task

from utils import config

# Load the azure-iot-device wheel if present
wheel_path = Path("azure_iot_device-2.14.0-py3-none-any.whl")
if wheel_path.exists():
    print(f"Wheel file found at: {wheel_path.resolve()}")
    extract_dir = Path(tempfile.mkdtemp(prefix="wheel_"))
    with zipfile.ZipFile(wheel_path) as zf:
        zf.extractall(extract_dir)
    # The package top-level is typically a directory next to *.dist-info inside the wheel
    sys.path.insert(0, str(extract_dir))

from hub_cert_device import HubCertDevice  # noqa: E402
from storage import allocate_device_id_range, clear_device_counter, initialize_storage  # noqa: E402

logger = logging.getLogger("locust.cert_hub_connect")


@events.test_stop.add_listener  # type: ignore[misc]
def on_test_stop(environment: Any, **kwargs: Any) -> None:
    """Clean up the device counter blob when the test stops."""
    logger.info("Test stopping, cleaning up device counter")
    clear_device_counter()


class CertHubConnectUser(User):
    """Locust user that tests IoT Hub connect/disconnect operations at scale.

    This user provisions devices lazily (on first task execution) and performs
    connect/disconnect cycles as the primary operation. Unlike CertUser which
    keeps connections open, this user disconnects after each successful connection.

    Environment Variables:
        DEVICES_PER_USER: Number of devices per Locust user (default: 1)
        CONNECT_REQUEST_INTERVAL: Seconds between connect/disconnect cycles (default: 90)
        DEVICE_NAME_PREFIX: Prefix for device names (default: "device"), also used for counter isolation
        DEVICE_ID_RANGE_SIZE: Number of device IDs to allocate per worker (default: 2500)
    """

    _storage_initialized: bool = False  # Class-level flag for one-time storage initialization

    def wait_time(self) -> float:
        """Calculate wait time between tasks using lazy config."""
        interval = config.get_int("CONNECT_REQUEST_INTERVAL")
        devices = config.get_int("DEVICES_PER_USER")
        result: float = constant_pacing(interval / devices)(self)  # type: ignore[no-untyped-call]
        return result

    # Distributed device ID range allocation (per-worker, shared across all CertHubConnectUser instances)
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

        # Initialize storage once globally (similar to device counter pattern)
        if not CertHubConnectUser._storage_initialized:
            logger.info("Initializing storage (one-time setup)")
            initialize_storage()
            CertHubConnectUser._storage_initialized = True

        # List of devices managed by this user
        self.devices: list[HubCertDevice] = []
        self._current_device_index: int = 0  # For round-robin device selection

        devices_per_user = config.get_int("DEVICES_PER_USER")
        logger.info(f"Starting CertHubConnectUser with {devices_per_user} device(s)")

        # Create device instances only - provisioning happens lazily in connect_disconnect task
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

        logger.info(f"CertHubConnectUser initialized with {len(self.devices)} device(s)")

    def on_start(self) -> None:
        """Called when user starts - no eager provisioning for this user type.

        Unlike CertUser which eagerly provisions during on_start(), this user
        provisions lazily during task execution to test the full connect flow.
        """
        logger.info(f"CertHubConnectUser on_start called with {len(self.devices)} device(s) (lazy provisioning)")

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
    def connect_disconnect(self) -> None:
        """Connect to IoT Hub and immediately disconnect.

        This task performs a complete connect/disconnect cycle:
        1. Get next device via round-robin
        2. Ensure device is provisioned (lazy provisioning on first access)
        3. Connect to IoT Hub
        4. Disconnect immediately after successful connection

        Devices are provisioned lazily on first task execution, not during on_start().
        """
        device = self._get_next_device()

        if device is None:
            logger.warning("No devices available, skipping connect/disconnect")
            return

        # Lazy provisioning: provision if not already provisioned
        if not self._is_device_provisioned(device):
            logger.info(f"Device {device.device_name} not provisioned, provisioning now")
            if not device.provision():
                logger.warning(f"Failed to provision device {device.device_name}")
                return
            # provision() already connects, so we just need to disconnect
            logger.info(f"Device {device.device_name} provisioned and connected, disconnecting")
            device.disconnect()
            return

        # Device is provisioned - attempt to connect
        if not device.is_connected:
            if not device._connect_with_retry():
                # Connection failed after retries - delete bad data and re-provision
                logger.warning(
                    f"Failed to connect device {device.device_name} after retries, " "deleting data and re-provisioning"
                )
                device.delete_device_data()
                # Clear the registration state so we can re-provision
                device.registration_result = None
                device.issued_cert_data = ""

                if not device.provision():
                    logger.warning(f"Failed to re-provision device {device.device_name}")
                    return
                # provision() already connects, so we just need to disconnect

        # Device is now connected (either from connect or provision) - disconnect
        if device.is_connected:
            logger.debug(f"Device {device.device_name} connected, disconnecting")
            device.disconnect()

    def on_stop(self) -> None:
        """Cleanup method called when the user stops."""
        logger.info(f"Stopping CertHubConnectUser with {len(self.devices)} device(s)")

        for device in self.devices:
            try:
                device.disconnect()
            except Exception as e:
                logger.error(f"Error disconnecting device {device.device_name}: {e}")
