"""Locust user for multi-hub IoT certificate-based device testing.

This module provides a Locust user optimized for Azure Load Testing with multiple IoT Hubs.
Each Azure Load Testing engine corresponds to one hub, with deterministic device ID sharding
based on engine index for predictable, non-overlapping device distribution.

**DPS Custom Allocation Policy Required:**
This module assumes a custom allocation policy is configured in DPS that routes devices
deterministically based on device ID ranges to specific IoT Hubs. Without this, DPS will
randomly distribute devices across hubs, breaking the engine-to-hub mapping.

See deploy/allocation_policy/ for the Azure Function implementation.

Key differences from CertUser:
- Deterministic device ID sharding (no blob-based counter allocation)
- Engine-based device distribution for multi-hub scenarios
- Lazy provisioning: devices provision on first use, not eagerly at startup
- Simplified configuration via Azure Load Testing environment variables
"""

import logging
import os
import sys
import tempfile
import threading
import zipfile
from pathlib import Path
from typing import Any

from locust import User, constant_pacing, task

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
from storage import initialize_storage  # noqa: E402

logger = logging.getLogger("locust.multi_hub_user")

# Environment configuration
cert_request_interval = int(os.getenv("CERT_REQUEST_INTERVAL", "90"))  # seconds
device_name_prefix = os.getenv("DEVICE_NAME_PREFIX", "device")
devices_per_user = int(os.getenv("DEVICES_PER_USER", "1"))  # number of devices per Locust user instance
cert_replace_enabled = os.getenv("CERT_REPLACE_ENABLED", "false").lower() == "true"

# Azure Load Testing engine configuration for multi-hub sharding
# AZURE_LOAD_TEST_ENGINE_INSTANCE: 0-indexed engine ID (provided by Azure Load Testing)
# AZURE_LOAD_TEST_ENGINE_COUNT: Total number of engines (provided by Azure Load Testing)
# DEVICES_PER_ENGINE: Total devices this engine should create and manage
# ENGINES_PER_HUB: Number of engines assigned to each hub (for multi-engine-per-hub scenarios)
engine_index = int(os.getenv("AZURE_LOAD_TEST_ENGINE_INSTANCE", "0"))
engine_count = int(os.getenv("AZURE_LOAD_TEST_ENGINE_COUNT", "1"))
devices_per_engine = int(os.getenv("DEVICES_PER_ENGINE", "100000"))
engines_per_hub = int(os.getenv("ENGINES_PER_HUB", "5"))

# Derived values for multi-engine-per-hub scenarios
# hub_index: which hub this engine is assigned to (engines 0-4 → hub 0, engines 5-9 → hub 1, etc.)
# engine_index_within_hub: this engine's position within its assigned hub (0 to engines_per_hub-1)
hub_index = engine_index // engines_per_hub
engine_index_within_hub = engine_index % engines_per_hub
hub_count = max(1, engine_count // engines_per_hub)


def get_engine_device_ids() -> list[int]:
    """Get the list of device IDs assigned to this engine.

    With multiple engines per hub, device IDs are partitioned hierarchically:
    1. First by hub (hub_index * devices_per_hub)
    2. Then by engine within hub (engine_index_within_hub * devices_per_engine)

    Example with 5 hubs, 5 engines/hub, 200K devices/engine:
    - Hub 0 (engines 0-4): devices 0 - 999,999
      - Engine 0: 0 - 199,999
      - Engine 1: 200,000 - 399,999
      - ...
    - Hub 1 (engines 5-9): devices 1,000,000 - 1,999,999
      - Engine 5: 1,000,000 - 1,199,999
      - ...

    Returns:
        List of device IDs for this engine.
    """
    devices_per_hub = devices_per_engine * engines_per_hub
    hub_base_id = hub_index * devices_per_hub
    engine_base_id = hub_base_id + (engine_index_within_hub * devices_per_engine)
    return list(range(engine_base_id, engine_base_id + devices_per_engine))


class MultiHubUser(User):
    """Locust user for multi-hub IoT device testing with Azure Load Testing.

    This user is designed for scenarios where:
    - Multiple IoT Hubs are configured behind a single DPS
    - Multiple engines can be assigned to each hub (ENGINES_PER_HUB)
    - Devices are deterministically assigned based on hub and engine index

    Device ID assignment with multiple engines per hub:
    - Engines are grouped by hub: engines 0 to (ENGINES_PER_HUB-1) → Hub 0, etc.
    - Each hub gets ENGINES_PER_HUB * DEVICES_PER_ENGINE devices
    - Example: 5 hubs, 5 engines/hub, 200K devices/engine = 5M total devices

    The user provisions devices via DPS (which distributes to hubs), then
    sends certificate renewal requests directly to the assigned hub.

    Environment Variables:
        AZURE_LOAD_TEST_ENGINE_INSTANCE: Engine index (0 to N-1), auto-provided by Azure Load Testing
        AZURE_LOAD_TEST_ENGINE_COUNT: Total engines, auto-provided by Azure Load Testing
        ENGINES_PER_HUB: Number of engines assigned to each hub (default: 1)
        DEVICES_PER_ENGINE: Total devices for this engine to manage (default: 200000)
        DEVICES_PER_USER: Number of devices per Locust user instance (default: 1)
        CERT_REQUEST_INTERVAL: Seconds between certificate requests (default: 90)
        DEVICE_NAME_PREFIX: Prefix for device names (default: "device")
        CERT_REPLACE_ENABLED: Enable certificate replacement mode (default: "false")
    """

    wait_time = constant_pacing(cert_request_interval / devices_per_user)  # type: ignore[no-untyped-call]
    _storage_initialized: bool = False  # Class-level flag for one-time storage initialization

    # Deterministic device ID allocation (per-engine, shared across all MultiHubUser instances)
    _id_lock: threading.Lock = threading.Lock()
    _device_ids: list[int] = []  # Pre-computed device IDs for this engine
    _next_device_index: int = 0  # Index into _device_ids for next allocation
    _ids_initialized: bool = False

    @classmethod
    def _ensure_device_ids_initialized(cls) -> None:
        """Initialize the device ID list for this engine (must hold _id_lock).

        This is called once per engine to compute the deterministic device IDs.
        """
        if not cls._ids_initialized:
            cls._device_ids = get_engine_device_ids()
            cls._ids_initialized = True
            logger.info(
                f"Engine {engine_index}/{engine_count} (hub {hub_index}, engine {engine_index_within_hub} of {engines_per_hub}): "
                f"initialized with {len(cls._device_ids)} device IDs [{cls._device_ids[0]} - {cls._device_ids[-1]}]"
            )

    @classmethod
    def get_device_name(cls) -> str:
        """Generate a unique device name from the pre-computed device ID list.

        Device names are assigned sequentially from the engine's device ID range.
        If all device IDs are exhausted, wraps around to the beginning.

        Thread-safe: Uses a lock to prevent concurrent access from multiple threads.

        Returns:
            A unique device name in the format "{prefix}{id}"
        """
        with cls._id_lock:
            cls._ensure_device_ids_initialized()

            if not cls._device_ids:
                raise RuntimeError("No device IDs available for this engine")

            # Get next device ID, wrapping around if needed
            device_id = cls._device_ids[cls._next_device_index % len(cls._device_ids)]
            cls._next_device_index += 1

        device_name = f"{device_name_prefix}{device_id}"
        logger.debug(f"Generated device name: {device_name}")
        return device_name

    @classmethod
    def get_remaining_device_count(cls) -> int:
        """Get the number of device IDs remaining to be allocated.

        Returns:
            Number of device IDs not yet allocated, or 0 if all allocated.
        """
        with cls._id_lock:
            cls._ensure_device_ids_initialized()
            remaining = len(cls._device_ids) - cls._next_device_index
            return max(0, remaining)

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)

        # Initialize storage once globally
        if not MultiHubUser._storage_initialized:
            logger.info("Initializing storage (one-time setup)")
            initialize_storage()
            MultiHubUser._storage_initialized = True

        # List of devices managed by this user
        self.devices: list[HubCertDevice] = []
        self._current_device_index: int = 0  # For round-robin message sending
        self._devices_pending_init: int = devices_per_user  # Track how many devices still need creation

        logger.info(
            f"Starting MultiHubUser on engine {engine_index} (hub {hub_index}) " f"with {devices_per_user} device(s)"
        )

        logger.info(f"MultiHubUser initialized, will lazily provision {devices_per_user} device(s)")

    def on_start(self) -> None:
        """Called when the user starts.

        Devices are lazily provisioned in the task loop, not eagerly here.
        This ensures certificate requests start flowing as soon as each device
        is individually ready, rather than waiting for all devices to provision.
        """
        logger.info(
            f"MultiHubUser starting on engine {engine_index} (hub {hub_index}), "
            f"devices will be provisioned lazily as tasks execute"
        )

    def _get_next_device(self) -> HubCertDevice | None:
        """Get the next device in round-robin fashion, creating new devices lazily.

        If there are pending devices to initialize and all current devices are busy
        or we have fewer devices than configured, creates a new device.

        Returns:
            The next device, or None if no devices exist and none can be created.
        """
        # Try to create a new device if we have pending slots
        if self._devices_pending_init > 0:
            device = self._create_and_provision_device()
            if device is not None:
                self._devices_pending_init -= 1
                return device
            # If creation failed but we have existing devices, fall through to use them

        if not self.devices:
            return None

        # Round-robin selection across existing devices
        device = self.devices[self._current_device_index % len(self.devices)]
        self._current_device_index += 1
        return device

    def _create_and_provision_device(self) -> HubCertDevice | None:
        """Create a new device and provision it immediately.

        Returns:
            The provisioned and connected device, or None if creation/provisioning failed.
        """
        # Check if we have remaining device IDs
        if self.get_remaining_device_count() <= 0:
            logger.warning(f"Engine {engine_index} (hub {hub_index}): exhausted all {devices_per_engine} device IDs")
            return None

        device_name = self.get_device_name()
        logger.info(f"Creating and provisioning device: {device_name}")

        try:
            device = HubCertDevice(device_name, self.environment)

            # Provision immediately - this includes connecting
            if not device.provision():
                logger.warning(f"Failed to provision device {device_name}")
                return None

            # Connect if not already connected from provision()
            if not device.is_connected:
                if not device.connect():
                    logger.warning(f"Failed to connect device {device_name}")
                    # Still add to list - request_new_certificate handles reconnection
                    pass

            self.devices.append(device)
            logger.info(f"Device {device_name} provisioned and ready")
            return device

        except Exception as e:
            logger.error(f"Failed to create device {device_name}: {e}")
            return None

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

        Devices are lazily provisioned: new devices are created and provisioned
        inline as this task executes. This ensures certificate requests start
        flowing as soon as each device is individually ready.

        If a device has reached the 20 certificate request limit, it will be
        replaced with a new device before making the request.
        """
        device = self._get_next_device()

        if device is None:
            logger.warning("No devices available and cannot create new ones, skipping certificate request")
            return

        # Find the index of the current device for potential replacement
        try:
            device_index = self.devices.index(device)
        except ValueError:
            # Device was just created and is valid
            device_index = len(self.devices) - 1

        # Check if device has reached the 20 certificate request limit
        if device.has_reached_cert_limit():
            logger.info(f"Device {device.device_name} reached 20 request limit, replacing")
            device = self._replace_device(device_index)
            if device is None:
                return  # No replacement available, skip this iteration

        # Emit time since last certificate response (if available)
        time_since_last = device.get_time_since_last_cert_response()
        if time_since_last is not None:
            logger.debug(f"Device {device.device_name}: {time_since_last:.2f}s since last cert response")

        # Ensure device is provisioned (handles edge cases)
        if not self._is_device_provisioned(device):
            logger.debug(f"Device {device.device_name} not provisioned, attempting to provision")
            if not device.provision():
                logger.warning(f"Failed to provision device {device.device_name}")
                return

        device.request_new_certificate(replace=cert_replace_enabled)

    def _replace_device(self, device_index: int) -> HubCertDevice | None:
        """Replace a device that has reached its certificate request limit.

        Disconnects the old device, allocates a new device ID, creates and
        provisions a new device, and replaces it in the devices list.

        Args:
            device_index: Index of the device to replace in self.devices

        Returns:
            The new device if replacement succeeded, None if no IDs available or failed.
        """
        old_device = self.devices[device_index]

        # Check if we have remaining device IDs
        if self.get_remaining_device_count() <= 0:
            logger.warning(
                f"Engine {engine_index}: no device IDs remaining, " f"cannot replace {old_device.device_name}"
            )
            return None

        # Disconnect the old device
        try:
            old_device.disconnect()
        except Exception as e:
            logger.warning(f"Error disconnecting {old_device.device_name}: {e}")

        # Create new device
        new_device_name = self.get_device_name()
        logger.info(f"Replacing {old_device.device_name} with {new_device_name}")

        try:
            new_device = HubCertDevice(new_device_name, self.environment)

            # Provision and connect the new device
            if not new_device.provision():
                logger.warning(f"Failed to provision replacement device {new_device_name}")
                # Keep old device in list (already disconnected, will be skipped)
                return None

            if not new_device.is_connected and not new_device.connect():
                logger.warning(f"Failed to connect replacement device {new_device_name}")
                # Device is provisioned but not connected, still usable
                # request_new_certificate will handle reconnection

            # Replace in the list
            self.devices[device_index] = new_device
            return new_device

        except Exception as e:
            logger.error(f"Failed to create replacement device {new_device_name}: {e}")
            return None

    def on_stop(self) -> None:
        """Cleanup method called when the user stops."""
        logger.info(f"Stopping MultiHubUser with {len(self.devices)} device(s)")

        for device in self.devices:
            try:
                device.disconnect()
            except Exception as e:
                logger.error(f"Error disconnecting device {device.device_name}: {e}")
