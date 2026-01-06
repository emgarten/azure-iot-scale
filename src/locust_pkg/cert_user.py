"""Locust user for IoT Hub certificate-based device testing.

This module provides a Locust user that manages multiple IoT Hub devices,
sending messages in a round-robin fashion across all connected devices.
"""

import logging
import os
import sys
import tempfile
import zipfile
from pathlib import Path
from typing import Any

from locust import User, constant_pacing, task

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
from storage import initialize_storage  # noqa: E402

logger = logging.getLogger("locust.cert_user")

# Environment configuration
hub_message_interval = int(os.getenv("HUB_MESSAGE_INTERVAL", "5"))  # seconds
device_name_prefix = os.getenv("DEVICE_NAME_PREFIX", "device-")
hub_message_size = int(os.getenv("HUB_MESSAGE_SIZE", "256"))  # bytes
devices_per_user = int(os.getenv("DEVICES_PER_USER", "1"))  # number of devices per user


class CertUser(User):
    """Locust user that manages multiple IoT Hub devices.

    This user provisions and connects multiple devices (configurable via DEVICES_PER_USER),
    then sends messages in a round-robin fashion across all connected devices.

    Environment Variables:
        DEVICES_PER_USER: Number of devices per Locust user (default: 1)
        HUB_MESSAGE_INTERVAL: Seconds between message sends (default: 5)
        DEVICE_NAME_PREFIX: Prefix for device names (default: "device-")
        HUB_MESSAGE_SIZE: Size of message payload in bytes (default: 256)
    """

    wait_time = constant_pacing(hub_message_interval)  # type: ignore[no-untyped-call]
    _device_counter: int = 0  # Class-level counter for unique device numbering
    _storage_initialized: bool = False  # Class-level flag for one-time storage initialization

    @classmethod
    def get_device_name(cls) -> str:
        """Generate a unique device name using the prefix and an incrementing counter."""
        device_name = f"{device_name_prefix}{cls._device_counter}"
        cls._device_counter += 1
        return device_name

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)

        # Initialize storage once globally (similar to device counter pattern)
        if not CertUser._storage_initialized:
            logger.info("Initializing storage (one-time setup)")
            initialize_storage()
            CertUser._storage_initialized = True

        # List of devices managed by this user
        self.devices: list[HubCertDevice] = []
        self._current_device_index: int = 0  # For round-robin message sending

        logger.info(f"Starting CertUser with {devices_per_user} device(s)")

        # Initialize devices with failure isolation
        for i in range(devices_per_user):
            device_name = self.get_device_name()
            logger.info(f"Initializing device {i + 1}/{devices_per_user}: {device_name}")

            try:
                device = HubCertDevice(device_name, self.environment)

                # Provision the device (loads from storage or provisions via DPS)
                if not device.provision():
                    logger.warning(f"Failed to provision device {device_name}, skipping")
                    continue

                # Connect to IoT Hub
                if not device.connect():
                    logger.warning(f"Failed to connect device {device_name}, skipping")
                    continue

                self.devices.append(device)
                logger.info(f"Device {device_name} ready")

            except Exception as e:
                # Failure isolation - log and continue with other devices
                logger.error(f"Failed to initialize device {device_name}: {e}")
                continue

        logger.info(f"CertUser initialized with {len(self.devices)} connected device(s)")

    def _get_next_device(self) -> HubCertDevice | None:
        """Get the next connected device in round-robin fashion.

        Returns:
            The next connected device, or None if no devices are connected.
        """
        # Filter to only connected devices
        connected_devices = [d for d in self.devices if d.is_connected]

        if not connected_devices:
            return None

        # Round-robin selection
        device = connected_devices[self._current_device_index % len(connected_devices)]
        self._current_device_index += 1
        return device

    @task
    def send_message(self) -> None:
        """Send a message from the next device in round-robin order."""
        device = self._get_next_device()

        if device is None:
            logger.warning("No connected devices available, skipping message send")
            return

        device.send_message(hub_message_size)

    def on_stop(self) -> None:
        """Cleanup method called when the user stops."""
        logger.info(f"Stopping CertUser with {len(self.devices)} device(s)")

        for device in self.devices:
            try:
                device.disconnect()
            except Exception as e:
                logger.error(f"Error disconnecting device {device.device_name}: {e}")
