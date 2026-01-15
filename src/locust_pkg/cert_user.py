"""Locust user for IoT Hub certificate-based device testing.

This module provides a Locust user that manages multiple IoT Hub devices,
requesting certificate renewals in a round-robin fashion across all connected devices.
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
cert_request_interval = int(os.getenv("CERT_REQUEST_INTERVAL", "90"))  # seconds
device_name_prefix = os.getenv("DEVICE_NAME_PREFIX", "device-")
devices_per_user = int(os.getenv("DEVICES_PER_USER", "1"))  # number of devices per user
cert_replace_enabled = os.getenv("CERT_REPLACE_ENABLED", "false").lower() == "true"


class CertUser(User):
    """Locust user that manages multiple IoT Hub devices.

    This user provisions and connects multiple devices (configurable via DEVICES_PER_USER),
    then requests certificate renewals in a round-robin fashion across all connected devices.

    Environment Variables:
        DEVICES_PER_USER: Number of devices per Locust user (default: 1)
        CERT_REQUEST_INTERVAL: Seconds between certificate requests (default: 90)
        DEVICE_NAME_PREFIX: Prefix for device names (default: "device-")
        CERT_REPLACE_ENABLED: Enable certificate replacement mode (default: "false")
    """

    wait_time = constant_pacing(cert_request_interval / devices_per_user)  # type: ignore[no-untyped-call]
    _device_counter: int = 0  # Class-level counter for unique device numbering
    _storage_initialized: bool = False  # Class-level flag for one-time storage initialization

    @classmethod
    def get_device_name(cls) -> str:
        """Generate a unique device name using the prefix and an incrementing counter."""
        device_name = f"{device_name_prefix}{cls._device_counter}"
        cls._device_counter += 1
        logger.info(f"Generated device name: {device_name}")
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

        logger.info(f"CertUser initialized with {len(self.devices)} device(s)")

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

        This method handles lazy initialization:
        - If the device hasn't been provisioned, provision it first
        - If the device isn't connected, connect it first
        - Emit the duration since the last certificate response (if available)
        """
        device = self._get_next_device()

        if device is None:
            logger.warning("No devices available, skipping certificate request")
            return

        # Emit time since last certificate response (if available)
        time_since_last = device.get_time_since_last_cert_response()
        if time_since_last is not None:
            logger.info(f"Device {device.device_name}: {time_since_last:.2f}s since last cert response")

        # Lazy provisioning: provision if not already provisioned
        if not self._is_device_provisioned(device):
            logger.info(f"Device {device.device_name} not provisioned, provisioning now")
            if not device.provision():
                logger.warning(f"Failed to provision device {device.device_name}, skipping")
                return

        # Lazy connection: connect if not connected
        if not device.is_connected:
            logger.info(f"Device {device.device_name} not connected, connecting now")
            if not device.connect():
                logger.warning(f"Failed to connect device {device.device_name}, skipping")
                return

        device.request_new_certificate(replace=cert_replace_enabled)

    def on_stop(self) -> None:
        """Cleanup method called when the user stops."""
        logger.info(f"Stopping CertUser with {len(self.devices)} device(s)")

        for device in self.devices:
            try:
                device.disconnect()
            except Exception as e:
                logger.error(f"Error disconnecting device {device.device_name}: {e}")
