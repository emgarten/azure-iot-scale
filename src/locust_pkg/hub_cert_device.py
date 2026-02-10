"""Utility module for IoT Hub certificate-based device operations.

This module provides the HubCertDevice class which encapsulates all functionality
for provisioning and connecting to Azure IoT Hub using X.509 certificates.
It uses DPS for initial provisioning and Paho MQTT for hub connections.
Designed for load testing certificate renewal operations.
"""

import base64
import hashlib
import hmac
import json
import logging
import os
import random
import ssl
import tempfile
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Optional, cast

import gevent
import paho.mqtt.client as mqtt
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
from cryptography.x509.oid import NameOID
from gevent.event import Event as GeventEvent

from storage import delete_device_data as _delete_device_data
from storage import load_device_data as _load_device_data
from storage import save_device_data as _save_device_data
from utils import parse_request_id_from_topic, retry_with_backoff, x509_certificate_list_to_pem

logger = logging.getLogger("locust.hub_cert_device")

# Environment configuration
provisioning_host = os.getenv("PROVISIONING_HOST")
id_scope = os.getenv("PROVISIONING_IDSCOPE")
dps_sas_key = os.getenv("PROVISIONING_SAS_KEY")

# MQTT configuration for credential management
MQTT_PORT = 8883
API_VERSION = "2025-08-01-preview"
credential_response_timeout = int(os.getenv("CREDENTIAL_RESPONSE_TIMEOUT", "300"))  # Default 5 minutes

# MQTT keepalive in seconds - Azure IoT Hub recommends 230s for reliable connections
# Lower values (like 60s) can cause frequent rc=7 (MQTT_ERR_CONN_LOST) under load
MQTT_KEEPALIVE = int(os.getenv("MQTT_KEEPALIVE", "230"))


class RegistrationState:
    """Represents the registration state from DPS."""

    def __init__(self, assigned_hub: str, device_id: str):
        self.assigned_hub = assigned_hub
        self.device_id = device_id
        self.issued_client_certificate: Optional[list[str]] = None


class RegistrationResult:
    """Represents the result of a DPS registration."""

    def __init__(self, status: str, registration_state: Optional[RegistrationState]):
        self.status = status
        self.registration_state = registration_state


class HubCertDevice:
    """Self-contained IoT Hub device with X.509 certificate authentication.

    This class encapsulates all functionality for a single IoT Hub device including:
    - Device provisioning via DPS
    - Hub connection with X.509 certificates via Paho MQTT
    - Certificate renewal requests
    - State persistence to Azure Blob Storage
    - Locust metrics emission

    Example usage:
        device = HubCertDevice("device-001", environment)
        if device.provision():
            if device.connect():
                device.request_new_certificate()
        device.disconnect()
    """

    def __init__(self, device_name: str, environment: Any):
        """Initialize a new HubCertDevice.

        Args:
            device_name: Unique name for this device
            environment: Locust environment for event firing
        """
        self.device_name = device_name
        self.environment = environment
        # Private key is lazily generated or restored from storage
        # This prevents key mismatch when DPS has cached registrations
        self._private_key: Optional[EllipticCurvePrivateKey] = None
        self.issued_cert_data: str = ""
        self.registration_result: Optional[RegistrationResult] = None

        # Paho MQTT client for hub connection
        self.client: Optional[mqtt.Client] = None
        self.is_connected: bool = False
        # Note: Temp files are now cleaned up immediately after SSL context loading
        # to minimize disk usage at scale

        # Track last certificate chain response time (ticks from time.time())
        self.last_cert_chain_response_time: Optional[float] = None

        # Track pending requests: request_id (UUID string) -> send_time (ticks from time.time())
        self.pending_requests: dict[str, float] = {}

        # Track disconnect reason for debugging
        self._last_disconnect_rc: Optional[int] = None

        # Event for connection synchronization (replaces busy-wait loop)
        # Uses gevent.Event instead of threading.Event to yield to other greenlets during wait()
        self._connect_event: GeventEvent = GeventEvent()

        # Track successful certificate requests (Azure IoT Hub limits to 20 per device)
        self.successful_cert_requests: int = 0

        # Guard to prevent concurrent reconnection attempts
        self._reconnecting: bool = False

    @property
    def private_key(self) -> EllipticCurvePrivateKey:
        """Get the private key, generating one if needed.

        The private key is lazily generated to allow restoration from storage
        before DPS provisioning. This prevents key mismatch errors when DPS
        has cached registrations from previous runs.

        Returns:
            The device's EC private key.
        """
        if self._private_key is None:
            self._private_key = ec.generate_private_key(ec.SECP256R1())
            logger.debug(f"Generated new private key for {self.device_name}")
        return self._private_key

    @private_key.setter
    def private_key(self, value: EllipticCurvePrivateKey) -> None:
        """Set the private key (used when restoring from storage)."""
        self._private_key = value

    def has_reached_cert_limit(self) -> bool:
        """Check if this device has reached the 20 certificate request limit.

        Returns:
            True if the device has reached or exceeded 20 successful requests, False otherwise.
        """
        return self.successful_cert_requests >= 20

    def _is_actually_connected(self) -> bool:
        """Check if MQTT client is actually connected.

        This method checks both the internal flag and the actual MQTT client state
        to provide an accurate picture of connectivity. This is important for
        detecting unexpected disconnections.

        Returns:
            True if the client is actually connected, False otherwise.
        """
        if not self.is_connected:
            return False
        if self.client is None:
            return False
        return bool(self.client.is_connected())

    def _cleanup_pending_requests(self, max_age_seconds: float = 600) -> None:
        """Clean up stale pending requests that have timed out.

        This prevents memory leaks from requests that never received responses
        due to disconnections or other issues.

        Args:
            max_age_seconds: Maximum age in seconds before a request is considered stale.
                           Default is 600 seconds (10 minutes).
        """
        if not self.pending_requests:
            return

        current_time = time.time()
        stale_request_ids = [
            request_id
            for request_id, send_time in self.pending_requests.items()
            if (current_time - send_time) > max_age_seconds
        ]

        for request_id in stale_request_ids:
            del self.pending_requests[request_id]

        if stale_request_ids:
            logger.debug(f"Cleaned up {len(stale_request_ids)} stale pending requests for {self.device_name}")

    def _on_connect(
        self,
        client: mqtt.Client,
        userdata: Any,
        flags: dict[str, Any],
        rc: int,
    ) -> None:
        """Handle MQTT connection events.

        This callback is invoked when the MQTT client connects or fails to connect.

        Args:
            client: The MQTT client instance
            userdata: User data (unused)
            flags: Response flags from the broker
            rc: Result code (0 = success, non-zero = failure)
        """
        if rc == 0:
            self.is_connected = True
            self._last_disconnect_rc = None
            self._connect_event.set()  # Signal successful connection
            logger.info(f"MQTT connected for {self.device_name}")
        else:
            self.is_connected = False
            logger.error(f"MQTT connection failed for {self.device_name}, rc={rc}")
            self.environment.events.request.fire(
                request_type="Hub",
                name="connect_callback_error",
                response_time=0,
                response_length=0,
                exception=f"Connection callback failed with rc={rc}",
                context={"device_name": self.device_name, "rc": rc},
            )

    def _on_disconnect(
        self,
        client: mqtt.Client,
        userdata: Any,
        rc: int,
    ) -> None:
        """Handle MQTT disconnection events.

        This callback is invoked when the MQTT client disconnects, either
        expectedly (rc=0) or unexpectedly (rc!=0).

        For unexpected disconnects (rc != 0), this method spawns an automatic
        reconnection attempt using gevent to marshal back to the greenlet context.

        Args:
            client: The MQTT client instance
            userdata: User data (unused)
            rc: Result code (0 = expected disconnect, non-zero = unexpected)
        """
        was_connected = self.is_connected
        self.is_connected = False
        self._last_disconnect_rc = rc

        if rc != 0:
            # Unexpected disconnection - log at debug level to reduce noise
            # (reconnection will be attempted automatically)
            logger.debug(f"Unexpected MQTT disconnect for {self.device_name}, rc={rc}")
            if was_connected:
                self.environment.events.request.fire(
                    request_type="Hub",
                    name="disconnect_error",
                    response_time=0,
                    response_length=0,
                    exception=f"Unexpected disconnect with rc={rc}",
                    context={"device_name": self.device_name, "rc": rc},
                )
                # Spawn automatic reconnection attempt using gevent
                # This marshals to the greenlet context and avoids blocking the Paho thread
                gevent.spawn(self._auto_reconnect)
        else:
            logger.debug(f"MQTT disconnected for {self.device_name} (expected)")

        # Clean up all pending requests on disconnect since they won't receive responses
        if self.pending_requests:
            logger.debug(f"Clearing {len(self.pending_requests)} pending requests on disconnect for {self.device_name}")
            self.pending_requests.clear()

    def _auto_reconnect(self) -> None:
        """Attempt automatic reconnection after an unexpected disconnect.

        This method is called via gevent.spawn() from _on_disconnect to handle
        automatic reconnection in the greenlet context. It uses exponential
        backoff with jitter to avoid thundering herd problems when many devices
        disconnect simultaneously.

        The reconnection is fire-and-forget - if it fails, the next call to
        request_new_certificate() will also attempt to reconnect.
        """
        # Guard against concurrent reconnection attempts
        if self._reconnecting:
            logger.debug(f"Reconnection already in progress for {self.device_name}, skipping")
            return
        self._reconnecting = True

        try:
            # Add random initial delay to spread out reconnection attempts
            # This prevents thundering herd when many devices disconnect at once
            initial_delay = random.uniform(1.0, 10.0)
            gevent.sleep(initial_delay)

            # Clean up the old client before reconnecting
            # Store in local variable to prevent race conditions
            old_client = self.client
            if old_client is not None:
                try:
                    old_client.loop_stop()
                except Exception:
                    pass
                self.client = None

            # Attempt reconnection with limited retries
            max_attempts = 3
            base_wait = 5.0

            for attempt in range(1, max_attempts + 1):
                if self.is_connected:
                    # Already reconnected (possibly by another path)
                    return

                logger.debug(f"Auto-reconnect attempt {attempt}/{max_attempts} for {self.device_name}")

                if self.connect():
                    logger.info(f"Auto-reconnect successful for {self.device_name}")
                    return

                if attempt < max_attempts:
                    # Exponential backoff with jitter
                    wait_time = base_wait * (2 ** (attempt - 1)) + random.uniform(0, 5.0)
                    gevent.sleep(wait_time)

            logger.debug(f"Auto-reconnect failed after {max_attempts} attempts for {self.device_name}")
        finally:
            self._reconnecting = False

    def save_device_data(self, data_dict: dict[str, Any]) -> None:
        """Save device data to Azure Blob Storage with Locust event tracking.

        Args:
            data_dict: Dictionary containing device data to save
        """
        start_time = time.time()
        json_data_size = len(str(data_dict))  # Approximate size

        try:
            _save_device_data(self.device_name, data_dict)

            # Fire success event
            total_time = int((time.time() - start_time) * 1000)
            self.environment.events.request.fire(
                request_type="Storage",
                name="save_device_data",
                response_time=total_time,
                response_length=json_data_size,
                exception=None,
                context={"device_name": self.device_name, "status": "success"},
            )
        except Exception as e:
            logger.error(f"Failed to save device data for {self.device_name}: {e}")

            # Fire failure event
            total_time = int((time.time() - start_time) * 1000)
            self.environment.events.request.fire(
                request_type="Storage",
                name="save_device_data",
                response_time=total_time,
                response_length=json_data_size,
                exception=str(e),
                context={"device_name": self.device_name, "status": "error"},
            )
            # Don't raise - graceful degradation

    def load_device_data(self) -> Optional[dict[str, Any]]:
        """Load device data from Azure Blob Storage with Locust event tracking.

        Returns:
            Dictionary containing device data if found and valid, None otherwise.
        """
        start_time = time.time()
        blob_data_size = 0

        try:
            result: Optional[dict[str, Any]] = _load_device_data(self.device_name)

            if result is None:
                # Fire event for blob not found (not an error, but tracked)
                total_time = int((time.time() - start_time) * 1000)
                self.environment.events.request.fire(
                    request_type="Storage",
                    name="load_device_data",
                    response_time=total_time,
                    response_length=0,
                    exception=None,
                    context={"device_name": self.device_name, "status": "not_found"},
                )
            else:
                blob_data_size = len(str(result))  # Approximate size
                # Fire success event
                total_time = int((time.time() - start_time) * 1000)
                self.environment.events.request.fire(
                    request_type="Storage",
                    name="load_device_data",
                    response_time=total_time,
                    response_length=blob_data_size,
                    exception=None,
                    context={"device_name": self.device_name, "status": "success"},
                )

            return result

        except Exception as e:
            logger.warning(f"Failed to load device data for {self.device_name}: {e}")

            # Fire failure event
            total_time = int((time.time() - start_time) * 1000)
            self.environment.events.request.fire(
                request_type="Storage",
                name="load_device_data",
                response_time=total_time,
                response_length=blob_data_size,
                exception=str(e),
                context={"device_name": self.device_name, "status": "error"},
            )
            return None

    def delete_device_data(self) -> None:
        """Delete device data from Azure Blob Storage with Locust event tracking.

        This method is a no-op if the device data doesn't exist.
        """
        start_time = time.time()

        try:
            _delete_device_data(self.device_name)

            # Fire success event
            total_time = int((time.time() - start_time) * 1000)
            self.environment.events.request.fire(
                request_type="Storage",
                name="delete_device_data",
                response_time=total_time,
                response_length=0,
                exception=None,
                context={"device_name": self.device_name, "status": "success"},
            )
        except Exception as e:
            logger.error(f"Failed to delete device data for {self.device_name}: {e}")

            # Fire failure event
            total_time = int((time.time() - start_time) * 1000)
            self.environment.events.request.fire(
                request_type="Storage",
                name="delete_device_data",
                response_time=total_time,
                response_length=0,
                exception=str(e),
                context={"device_name": self.device_name, "status": "error"},
            )
            # Don't raise - graceful degradation

    def _restore_from_storage(self, device_data: dict[str, Any]) -> bool:
        """Restore device state from storage data.

        This method loads the private key FIRST to ensure consistency. If any
        part of the restoration fails, all state is cleaned up to prevent
        key/certificate mismatches.

        Args:
            device_data: Dictionary containing stored device data

        Returns:
            True if restoration was successful, False otherwise
        """
        try:
            # Load private key FIRST - this is the most critical piece
            # If this fails, we don't want to set any other state
            loaded_key = serialization.load_pem_private_key(
                device_data["private_key_pem"].encode("utf-8"), password=None
            )
            # Type assertion - we know this is an EC key
            restored_private_key = cast(EllipticCurvePrivateKey, loaded_key)

            # Load certificate
            restored_cert_data = device_data["issued_cert_pem"]

            # Build registration state
            reg_state = RegistrationState(
                assigned_hub=device_data["assigned_hub"],
                device_id=device_data["device_id"],
            )
            restored_registration = RegistrationResult(
                status=device_data["registration_status"],
                registration_state=reg_state,
            )

            # Only set instance state after ALL parsing succeeded
            # This prevents partial state on failure
            self._private_key = restored_private_key
            self.issued_cert_data = restored_cert_data
            self.registration_result = restored_registration

            logger.info(f"Restored device state from storage for {self.device_name}")
            return True

        except Exception as e:
            logger.warning(f"Failed to restore device state from storage: {e}")
            # Clean up any partial state to ensure consistency
            self._private_key = None
            self.issued_cert_data = ""
            self.registration_result = None
            return False

    def _provision_inner(self) -> None:
        """Inner provisioning logic to be wrapped with retry."""
        # Import azure.iot.device after wheel is loaded
        from azure.iot.device import ProvisioningDeviceClient

        # Set start time, but override it later for the relevant time.
        start_time = time.time()

        try:
            device_key: str = ""

            # Handle optional dps_sas_key
            if dps_sas_key is not None:
                key_bytes = base64.b64decode(dps_sas_key)
                derived_key = hmac.new(key_bytes, self.device_name.encode("utf-8"), hashlib.sha256).digest()
                device_key = base64.b64encode(derived_key).decode("utf-8")

            if device_key:
                logger.debug("Using symmetric-key authentication")
                # Validate required environment variables
                if provisioning_host is None or id_scope is None:
                    raise Exception("Missing required environment variables: PROVISIONING_HOST or PROVISIONING_IDSCOPE")
                provisioning_device_client = ProvisioningDeviceClient.create_from_symmetric_key(
                    provisioning_host=provisioning_host,
                    registration_id=self.device_name,
                    id_scope=id_scope,
                    symmetric_key=device_key,
                )
            else:
                raise Exception(
                    "Either provide PROVISIONING_X509_CERT_FILE and PROVISIONING_X509_KEY_FILE or PROVISIONING_SAS_KEY"
                )

            # Generate CSR (Certificate Signing Request) using the existing private key
            csr_builder = x509.CertificateSigningRequestBuilder()
            csr_builder = csr_builder.subject_name(
                x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, self.device_name)])
            )

            # Sign the CSR with the private key
            csr = csr_builder.sign(self.private_key, hashes.SHA256())

            # Convert CSR to DER format and then base64 encode it
            csr_der = csr.public_bytes(serialization.Encoding.DER)
            csr_data = base64.b64encode(csr_der).decode("utf-8")

            # Set the CSR on the client
            provisioning_device_client.client_certificate_signing_request = csr_data

            # Start tracking time here
            start_time = time.time()

            # Use synchronous register() instead of async await (gevent style for locust)
            dps_result = provisioning_device_client.register()

            # Validate registration state exists
            if dps_result.registration_state is None:
                # Log as a locust error instead of raising an exception
                total_time = int((time.time() - start_time) * 1000)
                error_msg = "Registration failed: no registration state returned"
                logger.debug(error_msg)
                self.environment.events.request.fire(
                    request_type="DPS",
                    name="device_provision",
                    response_time=total_time,
                    response_length=0,
                    exception=error_msg,
                    context={"registration_id": self.device_name, "status": "error"},
                )
                return

            # Create our internal registration result
            reg_state = RegistrationState(
                assigned_hub=dps_result.registration_state.assigned_hub,
                device_id=dps_result.registration_state.device_id,
            )
            self.registration_result = RegistrationResult(
                status=dps_result.status,
                registration_state=reg_state,
            )

            # Store the issued certificate data
            if dps_result.registration_state.issued_client_certificate:
                self.issued_cert_data = x509_certificate_list_to_pem(
                    dps_result.registration_state.issued_client_certificate
                )

            # Log success
            total_time = int((time.time() - start_time) * 1000)
            logger.debug(f"Device {self.device_name} provisioned successfully")
            self.environment.events.request.fire(
                request_type="DPS",
                name="device_provision",
                response_time=total_time,
                response_length=0,
                exception=None,
                context={
                    "registration_id": self.device_name,
                    "status": dps_result.status,
                },
            )

            if dps_result.status == "assigned":
                # Save the registration result to device data storage
                logger.info("Registration assigned, saving to storage")
                if self.private_key is not None:
                    private_key_pem = self.private_key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.PKCS8,
                        encryption_algorithm=serialization.NoEncryption(),
                    ).decode("utf-8")

                    device_data = {
                        "device_name": self.device_name,
                        "registration_status": dps_result.status,
                        "assigned_hub": dps_result.registration_state.assigned_hub,
                        "device_id": dps_result.registration_state.device_id,
                        "private_key_pem": private_key_pem,
                        "issued_cert_pem": self.issued_cert_data,
                        "registration_timestamp": datetime.now(tz=timezone.utc).isoformat(),
                    }
                    self.save_device_data(device_data)

        except Exception as e:
            # Log as a locust error
            total_time = int((time.time() - start_time) * 1000)
            logger.error(f"Device {self.device_name} provisioning failed: {str(e)}")
            self.environment.events.request.fire(
                request_type="DPS",
                name="device_provision",
                response_time=total_time,
                response_length=0,
                exception=str(e),
                context={"registration_id": self.device_name, "status": "error"},
            )
            # Re-raise to trigger retry
            raise

    def _connect_with_retry(
        self,
        max_attempts: int = 3,
        base_wait: int = 30,
        max_jitter: int = 15,
        total_timeout: float = 300,
    ) -> bool:
        """Attempt to connect with retry logic and total timeout.

        This method wraps the connect() method with retry logic to handle
        transient connection failures. It will retry multiple times before
        giving up, but will also respect a total timeout to prevent blocking
        indefinitely.

        Args:
            max_attempts: Maximum number of connection attempts (default: 3)
            base_wait: Base wait time in seconds between retries (default: 30)
            max_jitter: Maximum random jitter in seconds to add to wait time (default: 15)
            total_timeout: Maximum total time in seconds before giving up (default: 300 = 5 minutes)

        Returns:
            True if connection was successful, False after all retries exhausted or timeout.
        """
        start_time = time.time()

        for attempt in range(1, max_attempts + 1):
            # Check if we've exceeded total timeout before attempting
            elapsed = time.time() - start_time
            if elapsed >= total_timeout:
                logger.warning(
                    f"Connection timed out after {elapsed:.1f}s for {self.device_name} " f"(before attempt {attempt})"
                )
                return False

            if self.connect():
                if attempt > 1:
                    logger.info(f"Connection succeeded on attempt {attempt} for {self.device_name}")
                return True

            if attempt < max_attempts:
                jitter = random.uniform(0, max_jitter)
                wait_time = base_wait + jitter

                # Check if waiting would exceed total timeout
                elapsed = time.time() - start_time
                if (elapsed + wait_time) >= total_timeout:
                    logger.warning(
                        f"Connection timed out after {elapsed:.1f}s for {self.device_name} " f"({attempt} attempts)"
                    )
                    return False

                logger.warning(
                    f"Connection attempt {attempt}/{max_attempts} failed for {self.device_name}, "
                    f"retrying in {wait_time:.1f}s..."
                )
                gevent.sleep(wait_time)
            else:
                logger.error(f"All {max_attempts} connection attempts failed for {self.device_name}")

        return False

    def provision(self, storage_only: bool = False) -> bool:
        """Provision the device with DPS.

        This method first tries to load existing registration from storage.
        If found, it validates the data by attempting to connect to the hub.
        If the connection fails after multiple retries (e.g., expired certificate),
        it deletes the bad data and falls back to DPS provisioning (unless storage_only=True).

        After successful DPS provisioning, it also validates by connecting.
        The connection is kept open for efficiency.

        Args:
            storage_only: If True, only load from storage and don't provision via DPS.
                         Returns False if no stored data exists. Useful for load testing
                         with pre-provisioned devices.

        Returns:
            True if device is successfully provisioned and connected,
            False otherwise.
        """
        # Check if a registration result already exists in device data storage
        device_data = self.load_device_data()

        if device_data is not None:
            logger.info(f"Loaded existing registration for {self.device_name}")
            if self._restore_from_storage(device_data):
                if device_data.get("registration_status") == "assigned":
                    # Validate the loaded data by attempting to connect (with retries)
                    logger.info(f"Validating loaded registration for {self.device_name} by connecting")
                    if self._connect_with_retry():
                        logger.info(f"Using existing registration for {self.device_name}, connection verified")
                        # Keep connection open for efficiency
                        return True
                    else:
                        # Connection failed after retries - certificate may be expired or invalid
                        logger.warning(
                            f"Failed to connect with loaded registration for {self.device_name} after retries, "
                            "deleting bad data and re-provisioning"
                        )
                        self.delete_device_data()
                        # Clear registration and cert but KEEP the private key
                        # This ensures the CSR sent to DPS uses the same key, which
                        # prevents key/cert mismatch if DPS returns cached data
                        self.registration_result = None
                        self.issued_cert_data = ""
            else:
                # Restoration failed - delete corrupted storage data to prevent future mismatches
                logger.warning(
                    f"Failed to restore from storage for {self.device_name}, "
                    "deleting corrupted data and re-provisioning"
                )
                self.delete_device_data()
                # _restore_from_storage already cleared all state on failure

        # If storage_only mode is enabled and we got here, there's no valid stored data
        if storage_only:
            logger.debug(f"Storage-only mode: no valid stored data for {self.device_name}, skipping DPS")
            return False

        # Provision with DPS (with retry logic, max 5 minutes)
        try:
            retry_with_backoff(
                operation_name=f"provision_device({self.device_name})",
                operation_func=self._provision_inner,
                base_wait=60,
                max_jitter=30,
                max_timeout=300,  # 5 minutes max
                max_attempts=10,
            )
        except TimeoutError as e:
            logger.warning(f"Provisioning timed out for {self.device_name}: {e}")
            return False
        except Exception as e:
            logger.error(f"Provisioning failed for {self.device_name}: {e}")
            return False

        # Check if provisioning was successful
        if self.registration_result is None or self.registration_result.status != "assigned":
            return False

        # Validate the newly provisioned data by attempting to connect (with retries)
        logger.info(f"Validating new provisioning for {self.device_name} by connecting")
        if self._connect_with_retry():
            logger.info(f"New provisioning for {self.device_name} validated, connection established")
            # Keep connection open for efficiency
            return True
        else:
            # Connection failed after provisioning and retries - delete the saved data
            logger.error(
                f"Failed to connect after provisioning {self.device_name} (after retries), deleting saved data"
            )
            self.delete_device_data()
            return False

    def disconnect(self) -> None:
        """Disconnect from IoT Hub and clean up resources."""
        self._disconnect()

    def _disconnect(self) -> None:
        """Disconnect the MQTT client and clean up resources."""
        # Store in local variable to prevent race conditions with concurrent access
        client = self.client
        if client is not None:
            self.client = None  # Clear immediately to prevent other code from using it
            try:
                logger.info(f"Disconnecting {self.device_name} from IoT Hub")
                client.loop_stop()
                client.disconnect()
            except Exception as e:
                logger.debug(f"Error disconnecting MQTT client: {e}")

        self.is_connected = False
        # Note: Temp files are now cleaned up immediately after SSL context loading
        # so no cleanup needed here

    def _create_csr(self) -> str:
        """Create a CSR using the existing private key.

        Returns:
            Base64-encoded DER format CSR string.
        """
        csr_builder = x509.CertificateSigningRequestBuilder()
        csr_builder = csr_builder.subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, self.device_name)]))
        csr = csr_builder.sign(self.private_key, hashes.SHA256())

        # Convert CSR to DER format and then base64 encode it
        csr_der = csr.public_bytes(serialization.Encoding.DER)
        return base64.b64encode(csr_der).decode("utf-8")

    def _fire_locust_event(
        self,
        name: str,
        response_time: int,
        response_length: int,
        exception: Optional[str],
        status_code: str,
    ) -> None:
        """Fire a Locust event for credential operations.

        This method is called via gevent.spawn() to ensure events are fired
        from the gevent context rather than the Paho MQTT thread.

        Args:
            name: The event name (e.g., "credential_accept", "credential_certificate")
            response_time: Response time in milliseconds
            response_length: Response payload size in bytes
            exception: Exception message if this is a failure event, None otherwise
            status_code: HTTP-like status code from the MQTT topic
        """
        self.environment.events.request.fire(
            request_type="Hub",
            name=name,
            response_time=response_time,
            response_length=response_length,
            exception=exception,
            context={"device_name": self.device_name, "status_code": status_code},
        )

    def _credential_on_message(
        self,
        client: mqtt.Client,
        userdata: Any,
        msg: mqtt.MQTTMessage,
    ) -> None:
        """Handle credential response messages from IoT Hub (observer pattern).

        This callback is invoked from the Paho MQTT thread when messages arrive
        on the credential response topic. To avoid thread/greenlet issues with
        Locust's gevent-based event system, we use gevent.spawn() to marshal
        event firing to the gevent context.

        Event types emitted:
        - credential_accept: Status 202 (request accepted, waiting for certificate)
        - credential_certificate: Status 200 (certificate chain received)
        - credential_parse_error: Failed to parse JSON response
        - credential_unexpected_status: Unexpected status code
        - credential_missing_certificates: Status 200 but no certificates in payload

        Args:
            client: The MQTT client instance
            userdata: User data (unused)
            msg: The MQTT message containing the credential response
        """
        logger.debug(f"Credential response received on topic: {msg.topic}")

        # Extract status code from topic
        # Topic format: $iothub/credentials/res/202/?$rid=999888777&$version=1
        parts = msg.topic.split("/")
        status_code = ""
        if len(parts) >= 4:
            status_code = parts[3]

        # Extract request_id from topic using helper function
        request_id = parse_request_id_from_topic(msg.topic)

        # Calculate response time from pending requests
        response_time_ms = 0
        if request_id is not None and request_id in self.pending_requests:
            send_time = self.pending_requests[request_id]
            response_time_ms = int((time.time() - send_time) * 1000)

        payload_size = len(msg.payload) if msg.payload else 0

        # Parse payload
        payload_data: Optional[dict[str, Any]] = None
        if msg.payload:
            try:
                payload_str = msg.payload.decode("utf-8")
                payload_data = json.loads(payload_str)
            except (json.JSONDecodeError, UnicodeDecodeError) as e:
                # Emit parse error event via gevent to marshal to greenlet context
                logger.error(f"Error parsing credential response: {e}")
                gevent.spawn(
                    self._fire_locust_event,
                    name="credential_parse_error",
                    response_time=0,
                    response_length=payload_size,
                    exception=f"Failed to parse response: {e}",
                    status_code=status_code,
                )
                return

        # Handle based on status code
        if status_code == "202":
            # Request accepted, waiting for certificate (don't remove from pending_requests)
            logger.debug(f"Credential request accepted for {self.device_name}")
            gevent.spawn(
                self._fire_locust_event,
                name="credential_accept",
                response_time=response_time_ms,
                response_length=payload_size,
                exception=None,
                status_code=status_code,
            )

        elif status_code == "200":
            # Certificate response - check if certificates are present
            if payload_data and "certificates" in payload_data:
                cert_data = payload_data["certificates"]
                if isinstance(cert_data, list) and len(cert_data) > 0:
                    # Certificate chain received - record timestamp and increment counter
                    self.last_cert_chain_response_time = time.time()
                    self.successful_cert_requests += 1
                    logger.info(
                        f"Certificate chain received for {self.device_name} "
                        f"({self.successful_cert_requests}/20 requests)"
                    )
                    gevent.spawn(
                        self._fire_locust_event,
                        name="credential_certificate",
                        response_time=response_time_ms,
                        response_length=payload_size,
                        exception=None,
                        status_code=status_code,
                    )
                else:
                    # Empty certificates array
                    logger.warning(f"Empty certificates array for {self.device_name}")
                    gevent.spawn(
                        self._fire_locust_event,
                        name="credential_missing_certificates",
                        response_time=response_time_ms,
                        response_length=payload_size,
                        exception="Certificates array is empty",
                        status_code=status_code,
                    )
            else:
                # No certificates field in response
                logger.warning(f"No certificates field in response for {self.device_name}")
                gevent.spawn(
                    self._fire_locust_event,
                    name="credential_missing_certificates",
                    response_time=response_time_ms,
                    response_length=payload_size,
                    exception="No certificates field in response",
                    status_code=status_code,
                )

            # Remove from pending_requests for non-202 responses
            if request_id is not None and request_id in self.pending_requests:
                del self.pending_requests[request_id]

        elif status_code == "429":
            # Rate limited - log and continue (no backoff, just drop and keep sending)
            logger.warning(f"Rate limited (429) for {self.device_name}, dropping and continuing")
            gevent.spawn(
                self._fire_locust_event,
                name="credential_rate_limited",
                response_time=response_time_ms,
                response_length=payload_size,
                exception=None,  # Not an error - expected under load
                status_code=status_code,
            )

            # Remove from pending_requests
            if request_id is not None and request_id in self.pending_requests:
                del self.pending_requests[request_id]

        elif status_code == "412":
            # Precondition Failed - expected when using invalid "replace" field
            # This is normal operation - the invalid replace ensures no 409 conflicts
            logger.warning(f"Precondition failed (412) for {self.device_name} - expected with invalid replace")
            gevent.spawn(
                self._fire_locust_event,
                name="credential_invalid_replace",
                response_time=response_time_ms,
                response_length=payload_size,
                exception=None,  # Not an error - expected behavior
                status_code=status_code,
            )

            # Remove from pending_requests
            if request_id is not None and request_id in self.pending_requests:
                del self.pending_requests[request_id]

        elif status_code in ("400", "401", "403", "404", "409", "500", "503"):
            # Known error status codes - log with payload details
            error_message = None
            if payload_data:
                error_message = payload_data.get("message") or payload_data.get("error")
            logger.warning(
                f"Credential request failed with status {status_code} for {self.device_name}: "
                f"error={error_message}, payload={payload_data}"
            )
            gevent.spawn(
                self._fire_locust_event,
                name=f"credential_error_{status_code}",
                response_time=response_time_ms,
                response_length=payload_size,
                exception=f"Error {status_code}: {error_message}",
                status_code=status_code,
            )

            # Remove from pending_requests
            if request_id is not None and request_id in self.pending_requests:
                del self.pending_requests[request_id]

        else:
            # Unexpected status code - log full details for debugging
            logger.warning(
                f"Credential request returned unexpected status {status_code} for {self.device_name}, "
                f"payload={payload_data}"
            )
            gevent.spawn(
                self._fire_locust_event,
                name="credential_unexpected_status",
                response_time=response_time_ms,
                response_length=payload_size,
                exception=f"Unexpected status code: {status_code}",
                status_code=status_code,
            )

            # Remove from pending_requests for non-202 responses
            if request_id is not None and request_id in self.pending_requests:
                del self.pending_requests[request_id]

    def connect(self) -> bool:
        """Connect to IoT Hub via Paho MQTT.

        This method establishes a persistent MQTT connection and subscribes to the
        credential response topic. The connection remains open for the lifetime of the
        device to handle multiple certificate requests using the observer pattern.

        If called when already connected, it verifies the connection is still active.
        If the connection was lost, it will clean up and reconnect.

        If a KEY_VALUES_MISMATCH error occurs (certificate/key mismatch), this method
        clears all state and deletes stored data, requiring a full re-provision.

        Returns:
            True if connection and subscription were successful, False otherwise.
        """
        # Check if we're actually connected (not just think we are)
        if self._is_actually_connected():
            logger.debug(f"Already connected for {self.device_name}")
            return True

        # If we thought we were connected but aren't, clean up first
        if self.is_connected or self.client is not None:
            logger.info(f"Stale connection detected for {self.device_name}, cleaning up before reconnect")
            self._disconnect()

        if self.registration_result is None or self.registration_result.registration_state is None:
            logger.error("Cannot connect: no registration result")
            return False

        if not self.issued_cert_data:
            logger.error("Cannot connect: missing certificate")
            return False

        hostname = self.registration_result.registration_state.assigned_hub
        device_id = self.registration_result.registration_state.device_id

        start_time = time.time()

        try:
            # Serialize the private key to PEM format (in-memory, no temp files)
            private_key_pem = self.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )

            # Load certificate and key directly into SSL context (no temp files)
            # This is critical for scale - temp files create disk I/O and inode pressure
            ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ssl_context.check_hostname = True
            # Write certificate and key to temporary files, load into SSL context,
            # then immediately delete the temp files. This is necessary because
            # ssl.SSLContext.load_cert_chain() doesn't support loading from memory
            # in Python < 3.13. Immediate cleanup minimizes disk/inode pressure at scale.
            cert_fd, temp_cert_file = tempfile.mkstemp(suffix=".pem", text=True)
            key_fd, temp_key_file = tempfile.mkstemp(suffix=".pem", text=True)
            try:
                with os.fdopen(cert_fd, "w") as f:
                    f.write(self.issued_cert_data)
                with os.fdopen(key_fd, "wb") as f:
                    f.write(private_key_pem)

                # Create SSL context and load certs
                ssl_context = ssl.create_default_context()
                ssl_context.load_cert_chain(certfile=temp_cert_file, keyfile=temp_key_file)
            finally:
                # Clean up temp files immediately after loading into SSL context
                # This minimizes disk usage and inode consumption at scale
                try:
                    os.unlink(temp_cert_file)
                except OSError:
                    pass
                try:
                    os.unlink(temp_key_file)
                except OSError:
                    pass

            # Create MQTT client
            self.client = mqtt.Client(
                client_id=device_id,
                protocol=mqtt.MQTTv311,
            )

            # Set username for Azure IoT Hub
            username = f"{hostname}/{device_id}/?api-version={API_VERSION}"
            self.client.username_pw_set(username=username)

            # Configure TLS with loaded SSL context
            self.client.tls_set_context(ssl_context)

            # Set callbacks for connection state tracking
            self.client.on_connect = self._on_connect
            self.client.on_disconnect = self._on_disconnect
            self.client.on_message = self._credential_on_message

            # Connect to IoT Hub
            logger.debug(f"Connecting to {hostname} via MQTT")
            self._connect_event.clear()  # Reset event before connection attempt
            self.client.connect(hostname, MQTT_PORT, keepalive=60)
            self.client.loop_start()

            # Wait for connection using event-based synchronization (avoids busy-wait)
            connect_timeout = 120
            if not self._connect_event.wait(timeout=connect_timeout):
                raise Exception("Failed to connect to IoT Hub via MQTT (timeout)")

            # Subscribe to response topic (once, for the lifetime of the connection)
            subscribe_topic = "$iothub/credentials/res/#"
            result, _ = self.client.subscribe(subscribe_topic, qos=1)
            if result != mqtt.MQTT_ERR_SUCCESS:
                raise Exception(f"Failed to subscribe to {subscribe_topic}")

            self.is_connected = True

            # Log success
            total_time = int((time.time() - start_time) * 1000)
            logger.info(f"Connected to IoT Hub for {self.device_name}")
            self.environment.events.request.fire(
                request_type="Hub",
                name="connect",
                response_time=total_time,
                response_length=0,
                exception=None,
                context={"device_name": self.device_name, "status": "connected"},
            )
            return True

        except Exception as e:
            # Log failure
            total_time = int((time.time() - start_time) * 1000)
            logger.error(f"Failed to connect for {self.device_name}: {e}")
            self.environment.events.request.fire(
                request_type="Hub",
                name="connect",
                response_time=total_time,
                response_length=0,
                exception=str(e),
                context={"device_name": self.device_name, "status": "error"},
            )

            # Clean up on failure
            self._disconnect()

            # Handle KEY_VALUES_MISMATCH error by deleting storage and triggering full re-provision
            # This is the nuclear option - the key and cert are out of sync somewhere
            error_str = str(e)
            if "KEY_VALUES_MISMATCH" in error_str:
                logger.warning(
                    f"Key/certificate mismatch for {self.device_name}, "
                    "deleting stored data for re-provision on next attempt"
                )
                # Delete the bad storage data so next provision() call will re-provision from DPS
                self.delete_device_data()
                # Clear ALL in-memory state including private key
                # This forces a completely fresh provision next time
                self._private_key = None
                self.registration_result = None
                self.issued_cert_data = ""

            return False

    def get_time_since_last_cert_response(self) -> Optional[float]:
        """Get the time elapsed since the last certificate chain response.

        Returns:
            Seconds since the last certificate chain was received, or None if
            no certificate chain has been received yet.
        """
        if self.last_cert_chain_response_time is None:
            return None
        return time.time() - self.last_cert_chain_response_time

    def request_new_certificate(self, replace: bool = False, use_invalid_replace: bool = False) -> bool:
        """Request a new certificate from IoT Hub via MQTT credential management API.

        This method sends a CSR to request a new certificate using the persistent
        MQTT connection. It is fire-and-forget - responses are handled asynchronously
        by the observer pattern via _credential_on_message callback.

        This method handles automatic reconnection if the connection was lost.
        It checks the actual MQTT connection state (not just the flag) and will
        reconnect if needed.

        Args:
            replace: If True, include "replace": "*" in the payload to replace existing certificates.
            use_invalid_replace: If True, include "replace": "invalid" to avoid 409 conflicts
                               (used for throttle testing). Takes precedence over `replace`.

        Returns:
            True if the request was successfully sent, False otherwise.
        """
        if self.registration_result is None or self.registration_result.registration_state is None:
            logger.error("Cannot request new certificate: no registration result")
            self.environment.events.request.fire(
                request_type="Hub",
                name="credential_request",
                response_time=0,
                response_length=0,
                exception="No registration result",
                context={"device_name": self.device_name, "status": "error"},
            )
            return False

        # Check actual connection state and reconnect if needed
        # This handles both "never connected" and "connection was lost" cases
        if not self._is_actually_connected():
            # Clean up stale pending requests before reconnect
            self._cleanup_pending_requests()

            logger.info(f"Device {self.device_name} not connected, attempting to connect")
            if not self.connect():
                logger.error("Cannot request new certificate: connection failed")
                self.environment.events.request.fire(
                    request_type="Hub",
                    name="credential_request",
                    response_time=0,
                    response_length=0,
                    exception="Connection failed",
                    context={"device_name": self.device_name, "status": "error"},
                )
                return False

        device_id = self.registration_result.registration_state.device_id

        start_time = time.time()

        try:
            # Create CSR and publish request
            csr_data = self._create_csr()
            request_id = str(uuid.uuid4())
            publish_topic = f"$iothub/credentials/POST/issueCertificate/?$rid={request_id}"
            payload_dict: dict[str, str] = {"id": device_id, "csr": csr_data}
            if use_invalid_replace:
                # Use invalid replace to avoid 409 conflicts (for throttle testing)
                payload_dict["replace"] = "invalid"
            elif replace:
                payload_dict["replace"] = "*"
            payload = json.dumps(payload_dict)

            logger.debug(f"Sending credential request to {publish_topic}")
            # At this point client is guaranteed to be non-None (checked above)
            assert self.client is not None

            # Always re-subscribe before publishing to ensure subscription is active
            # (subscriptions are idempotent - subscribing twice is harmless)
            subscribe_topic = "$iothub/credentials/res/#"
            self.client.subscribe(subscribe_topic, qos=1)

            result = self.client.publish(publish_topic, payload=payload, qos=1)
            if result.rc != mqtt.MQTT_ERR_SUCCESS:
                raise Exception(f"Failed to publish CSR request: {result.rc}")

            # Store the request_id and send time for response time calculation
            self.pending_requests[request_id] = time.time()

            # Log success (request sent, not waiting for response)
            total_time = int((time.time() - start_time) * 1000)
            logger.info(f"Certificate request sent for {self.device_name}")
            self.environment.events.request.fire(
                request_type="Hub",
                name="credential_request",
                response_time=total_time,
                response_length=len(payload),
                exception=None,
                context={"device_name": self.device_name, "status": "sent"},
            )
            return True

        except Exception as e:
            # Log failure
            total_time = int((time.time() - start_time) * 1000)
            logger.error(f"Failed to send certificate request for {self.device_name}: {e}")
            self.environment.events.request.fire(
                request_type="Hub",
                name="credential_request",
                response_time=total_time,
                response_length=0,
                exception=str(e),
                context={"device_name": self.device_name, "status": "error"},
            )
            return False
