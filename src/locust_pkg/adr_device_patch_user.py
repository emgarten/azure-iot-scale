"""Locust user for Azure Device Registry (ADR) PATCH operations.

This module provides a Locust user that creates a device on startup, then repeatedly
patches the operatingSystemVersion field to measure latency and throughput.
"""

import logging
import secrets
import time
from typing import Any

import requests
from locust import User, constant_pacing, task

from adr_utils import create_adr_device, delete_adr_device, get_adr_token, patch_adr_device_os_version
from utils import log_all_env_vars, require_env

logger = logging.getLogger("locust.adr_device_patch_user")

# Log all environment variables for debugging
log_all_env_vars()

# Environment configuration (all required)
adr_subscription_id = require_env("ADR_SUBSCRIPTION_ID")
adr_resource_group = require_env("ADR_RESOURCE_GROUP")
adr_namespace = require_env("ADR_NAMESPACE")
adr_location = require_env("ADR_LOCATION")
adr_device_prefix = require_env("ADR_DEVICE_PREFIX")
adr_patch_interval = int(require_env("ADR_PATCH_INTERVAL"))  # seconds


class AdrDevicePatchUser(User):
    """Locust user that creates an ADR device and repeatedly patches it.

    This user provisions a device on startup, then patches the operatingSystemVersion
    field at a configurable interval to measure ARM API latency and throughput.

    Environment Variables:
        ADR_SUBSCRIPTION_ID (required): Azure subscription ID
        ADR_RESOURCE_GROUP (required): Resource group name
        ADR_NAMESPACE (required): ADR namespace name
        ADR_LOCATION (required): Azure location for devices
        ADR_DEVICE_PREFIX (optional): Device name prefix (default: "adrdev")
        ADR_PATCH_INTERVAL (optional): Seconds between patches (default: 5)
    """

    wait_time = constant_pacing(adr_patch_interval)  # type: ignore[no-untyped-call]

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)

        # Generate unique device name with random hex suffix
        suffix = secrets.token_hex(4)  # 8 hex characters
        self.device_name = f"{adr_device_prefix}-{suffix}"
        self._device_created = False

        logger.info(f"Initialized AdrDevicePatchUser with device: {self.device_name}")

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

    def on_start(self) -> None:
        """Create the device on startup.

        Reports creation time to Locust metrics.
        """
        logger.info(f"Creating device: {self.device_name}")
        start_time = time.time()

        try:
            # Pre-fetch token to ensure auth is working
            get_adr_token()

            create_adr_device(
                subscription_id=adr_subscription_id,
                resource_group=adr_resource_group,
                namespace=adr_namespace,
                device_name=self.device_name,
                location=adr_location,
            )
            self._device_created = True
            self._fire_request_event("create_device", start_time)
            logger.info(f"Device created: {self.device_name}")

        except Exception as e:
            logger.error(f"Failed to create device {self.device_name}: {e}")
            self._fire_request_event("create_device", start_time, exception=e)
            # Don't raise - let the user continue and fail on patch attempts

    @task
    def patch_device(self) -> None:
        """Patch the device's operatingSystemVersion field.

        Reports latency to Locust metrics.
        """
        if not self._device_created:
            logger.debug(f"Device {self.device_name} not created, skipping patch")
            return

        start_time = time.time()

        try:
            _, os_version = patch_adr_device_os_version(
                subscription_id=adr_subscription_id,
                resource_group=adr_resource_group,
                namespace=adr_namespace,
                device_name=self.device_name,
            )
            self._fire_request_event("patch_device", start_time)
            logger.debug(f"Patched device {self.device_name} with OS version: {os_version}")

        except Exception as e:
            logger.error(f"Failed to patch device {self.device_name}: {e}")
            self._fire_request_event("patch_device", start_time, exception=e)

    def on_stop(self) -> None:
        """Delete the device on cleanup.

        Reports deletion time to Locust metrics.
        """
        if not self._device_created:
            logger.debug(f"Device {self.device_name} was not created, skipping delete")
            return

        logger.info(f"Deleting device: {self.device_name}")
        start_time = time.time()

        try:
            delete_adr_device(
                subscription_id=adr_subscription_id,
                resource_group=adr_resource_group,
                namespace=adr_namespace,
                device_name=self.device_name,
            )
            self._fire_request_event("delete_device", start_time)
            logger.info(f"Device deleted: {self.device_name}")

        except Exception as e:
            logger.error(f"Failed to delete device {self.device_name}: {e}")
            self._fire_request_event("delete_device", start_time, exception=e)
