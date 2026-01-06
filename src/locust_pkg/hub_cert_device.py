"""Utility module for IoT Hub certificate-based device operations.

This module provides the HubCertDevice class which encapsulates all functionality
for provisioning, connecting, and communicating with Azure IoT Hub using X.509
certificates. It is designed to be used by Locust users for load testing.
"""

import base64
import hashlib
import hmac
import logging
import os
import tempfile
import time
from datetime import datetime, timezone
from typing import Any, Optional, cast

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
from cryptography.x509.oid import NameOID

from storage import load_device_data as _load_device_data
from storage import save_device_data as _save_device_data
from utils import create_msg, retry_with_backoff, x509_certificate_list_to_pem

logger = logging.getLogger("locust.hub_cert_device")

# Environment configuration
provisioning_host = os.getenv("PROVISIONING_HOST")
id_scope = os.getenv("PROVISIONING_IDSCOPE")
dps_sas_key = os.getenv("PROVISIONING_SAS_KEY")


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
    - Hub connection with X.509 certificates
    - Message sending
    - State persistence to Azure Blob Storage
    - Locust metrics emission

    Example usage:
        device = HubCertDevice("device-001", environment)
        if device.provision():
            if device.connect():
                device.send_message(256)
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
        self.private_key: Optional[EllipticCurvePrivateKey] = None
        self.issued_cert_data: str = ""
        self.registration_result: Optional[RegistrationResult] = None
        self.device_client: Optional[Any] = None  # IoTHubDeviceClient loaded dynamically
        self.is_connected: bool = False
        self.cert_file: Optional[str] = None
        self.key_file: Optional[str] = None

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

    def _restore_from_storage(self, device_data: dict[str, Any]) -> bool:
        """Restore device state from storage data.

        Args:
            device_data: Dictionary containing stored device data

        Returns:
            True if restoration was successful, False otherwise
        """
        try:
            reg_state = RegistrationState(
                assigned_hub=device_data["assigned_hub"],
                device_id=device_data["device_id"],
            )
            self.registration_result = RegistrationResult(
                status=device_data["registration_status"],
                registration_state=reg_state,
            )

            # Deserialize private key from PEM
            loaded_key = serialization.load_pem_private_key(
                device_data["private_key_pem"].encode("utf-8"), password=None
            )
            # Type assertion - we know this is an EC key
            self.private_key = cast(EllipticCurvePrivateKey, loaded_key)

            # Load certificate
            self.issued_cert_data = device_data["issued_cert_pem"]

            logger.info(f"Restored device state from storage for {self.device_name}")
            return True

        except Exception as e:
            logger.warning(f"Failed to restore device state from storage: {e}")
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

            # Generate EC private key (prime256v1 = SECP256R1)
            self.private_key = ec.generate_private_key(ec.SECP256R1())

            # Generate CSR (Certificate Signing Request)
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

    def provision(self) -> bool:
        """Provision the device with DPS.

        This method first tries to load existing registration from storage.
        If not found, it provisions a new device with DPS using retry logic.

        Returns:
            True if device is successfully provisioned (or loaded from storage),
            False otherwise.
        """
        # Check if a registration result already exists in device data storage
        device_data = self.load_device_data()

        if device_data is not None:
            logger.info(f"Loaded existing registration for {self.device_name}")
            if self._restore_from_storage(device_data):
                if device_data.get("registration_status") == "assigned":
                    logger.info(f"Using existing registration for {self.device_name}, skipping provisioning")
                    return True

        # Provision with DPS (with retry logic)
        try:
            retry_with_backoff(
                operation_name=f"provision_device({self.device_name})",
                operation_func=self._provision_inner,
                base_wait=60,
                max_jitter=30,
            )
        except Exception as e:
            logger.error(f"Provisioning failed for {self.device_name}: {e}")
            return False

        return self.registration_result is not None and self.registration_result.status == "assigned"

    def _connect_inner(self) -> None:
        """Inner hub connection logic to be wrapped with retry."""
        # Import azure.iot.device after wheel is loaded
        from azure.iot.device import IoTHubDeviceClient, X509

        # Load registration data from storage if not already in memory
        if self.registration_result is None or self.private_key is None or not self.issued_cert_data:
            device_data = self.load_device_data()
            if device_data is not None:
                logger.info("Loading device data from storage for connection")
                if not self._restore_from_storage(device_data):
                    raise Exception("Failed to restore device state from storage")

        if self.registration_result is None or self.registration_result.registration_state is None:
            raise Exception("Cannot connect to hub: no registration result")

        if self.private_key is None:
            raise Exception("Cannot connect to hub: no private key")

        start_time = time.time()

        try:
            # Serialize the private key to PEM format
            private_key_pem = self.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            ).decode("utf-8")

            # Write certificate and key to temporary files
            # X509 class expects file paths, not file contents
            cert_fd, self.cert_file = tempfile.mkstemp(suffix=".pem", text=True)
            key_fd, self.key_file = tempfile.mkstemp(suffix=".pem", text=True)

            try:
                with os.fdopen(cert_fd, "w") as f:
                    f.write(self.issued_cert_data)
                with os.fdopen(key_fd, "w") as f:
                    f.write(private_key_pem)

                # Create X509 object with file paths
                iot_hub_x509 = X509(self.cert_file, self.key_file)  # type: ignore[no-untyped-call]

                # Create device client
                self.device_client = IoTHubDeviceClient.create_from_x509_certificate(
                    hostname=self.registration_result.registration_state.assigned_hub,
                    device_id=self.registration_result.registration_state.device_id,
                    x509=iot_hub_x509,
                )

                # Connect the client (synchronous for gevent compatibility)
                self.device_client.connect()
                self.is_connected = True

                # Log success
                total_time = int((time.time() - start_time) * 1000)
                logger.info(f"Device connected to IoT Hub: {self.registration_result.registration_state.assigned_hub}")
                self.environment.events.request.fire(
                    request_type="Hub",
                    name="connect",
                    response_time=total_time,
                    response_length=0,
                    exception=None,
                    context={
                        "device_id": self.registration_result.registration_state.device_id,
                        "status": "connected",
                    },
                )

            except Exception:
                # Clean up temp files on error
                if self.cert_file and os.path.exists(self.cert_file):
                    os.unlink(self.cert_file)
                if self.key_file and os.path.exists(self.key_file):
                    os.unlink(self.key_file)
                self.cert_file = None
                self.key_file = None
                raise

        except Exception as e:
            # Log as a locust error
            total_time = int((time.time() - start_time) * 1000)
            logger.error(f"Failed to connect to IoT Hub: {str(e)}")
            self.environment.events.request.fire(
                request_type="Hub",
                name="connect",
                response_time=total_time,
                response_length=0,
                exception=str(e),
                context={"status": "error"},
            )
            self.is_connected = False
            # Re-raise to trigger retry
            raise

    def connect(self) -> bool:
        """Connect to IoT Hub using X.509 certificate from provisioning.

        Uses retry logic for resilience.

        Returns:
            True if connection is successful, False otherwise.
        """
        try:
            retry_with_backoff(
                operation_name=f"connect_hub({self.device_name})",
                operation_func=self._connect_inner,
                base_wait=60,
                max_jitter=30,
            )
            return self.is_connected
        except Exception as e:
            logger.error(f"Connection failed for {self.device_name}: {e}")
            return False

    def send_message(self, message_size: int) -> bool:
        """Send a single telemetry message to IoT Hub.

        Args:
            message_size: Size of the message payload in bytes

        Returns:
            True if message was sent successfully, False otherwise.
        """
        # Import azure.iot.device after wheel is loaded
        from azure.iot.device import Message

        # Ensure device is connected before sending
        if not self.is_connected or self.device_client is None:
            logger.warning(f"Device {self.device_name} not connected, skipping message send")
            return False

        start_time = time.time()

        try:
            # Create and send message
            message_data = create_msg(message_size)
            msg = Message(message_data)  # type: ignore[no-untyped-call]

            # Send message (synchronous for gevent compatibility)
            self.device_client.send_message(msg)

            # Log success
            total_time = int((time.time() - start_time) * 1000)
            logger.debug(f"Message sent successfully from {self.device_name}")
            self.environment.events.request.fire(
                request_type="Hub",
                name="send_message",
                response_time=total_time,
                response_length=len(msg.data),
                exception=None,
                context={"device_name": self.device_name, "status": "sent"},
            )
            return True

        except Exception as e:
            # Log as a locust error
            total_time = int((time.time() - start_time) * 1000)
            logger.error(f"Failed to send message from {self.device_name}: {str(e)}")
            self.environment.events.request.fire(
                request_type="Hub",
                name="send_message",
                response_time=total_time,
                response_length=0,
                exception=str(e),
                context={"device_name": self.device_name, "status": "error"},
            )
            return False

    def disconnect(self) -> None:
        """Disconnect from IoT Hub and clean up resources."""
        if self.device_client is not None and self.is_connected:
            try:
                logger.info(f"Disconnecting {self.device_name} from IoT Hub")
                self.device_client.shutdown()
                self.is_connected = False
            except Exception as e:
                logger.error(f"Error during shutdown for {self.device_name}: {str(e)}")

        # Clean up temporary certificate and key files
        if self.cert_file and os.path.exists(self.cert_file):
            try:
                os.unlink(self.cert_file)
            except Exception as e:
                logger.error(f"Error removing cert file: {str(e)}")
            self.cert_file = None

        if self.key_file and os.path.exists(self.key_file):
            try:
                os.unlink(self.key_file)
            except Exception as e:
                logger.error(f"Error removing key file: {str(e)}")
            self.key_file = None
