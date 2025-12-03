import base64
import hashlib
import hmac
import os
import tempfile
import time
from datetime import datetime, timezone
from locust import User, task, constant_pacing
import logging
from typing import Any, Optional, cast

import sys
import zipfile
from pathlib import Path

wheel_path = Path("azure_iot_device-2.14.0-py3-none-any.whl")
if wheel_path.exists():
    print(f"Wheel file found at: {wheel_path.resolve()}")
    extract_dir = Path(tempfile.mkdtemp(prefix="wheel_"))
    with zipfile.ZipFile(wheel_path) as zf:
        zf.extractall(extract_dir)
    # The package top-level is typically a directory next to *.dist-info inside the wheel
    sys.path.insert(0, str(extract_dir))

# azure.iot.device imports are deferred to inside methods to ensure wheel is loaded first
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey  # noqa: E402
from cryptography import x509  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402
from cryptography.hazmat.primitives import hashes  # noqa: E402

from utils import x509_certificate_list_to_pem, retry_with_backoff, create_msg  # noqa: E402
from storage import (  # noqa: E402
    save_device_data as _save_device_data,
    load_device_data as _load_device_data,
    initialize_storage,
)

logger = logging.getLogger("locust.cert_user")


def save_device_data(
    device_name: str,
    data_dict: dict[str, Any],
    environment: Any,
) -> None:
    """Save device data to Azure Blob Storage with locust event tracking.

    Args:
        device_name: Name of the device
        data_dict: Dictionary containing device data to save
        environment: Locust environment for event firing
    """
    start_time = time.time()
    json_data_size = len(str(data_dict))  # Approximate size

    try:
        _save_device_data(device_name, data_dict)

        # Fire success event
        total_time = int((time.time() - start_time) * 1000)
        environment.events.request.fire(
            request_type="Storage",
            name="save_device_data",
            response_time=total_time,
            response_length=json_data_size,
            exception=None,
            context={"device_name": device_name, "status": "success"},
        )
    except Exception as e:
        logger.error(f"Failed to save device data for {device_name}: {e}")

        # Fire failure event
        total_time = int((time.time() - start_time) * 1000)
        environment.events.request.fire(
            request_type="Storage",
            name="save_device_data",
            response_time=total_time,
            response_length=json_data_size,
            exception=str(e),
            context={"device_name": device_name, "status": "error"},
        )
        # Don't raise - graceful degradation


def load_device_data(
    device_name: str,
    environment: Any,
) -> Optional[dict[str, Any]]:
    """Load device data from Azure Blob Storage with locust event tracking.

    Args:
        device_name: Name of the device
        environment: Locust environment for event firing

    Returns:
        Dictionary containing device data if found and valid, None otherwise.
    """
    start_time = time.time()
    blob_data_size = 0

    try:
        result: Optional[dict[str, Any]] = _load_device_data(device_name)

        if result is None:
            # Fire event for blob not found (not an error, but tracked)
            total_time = int((time.time() - start_time) * 1000)
            environment.events.request.fire(
                request_type="Storage",
                name="load_device_data",
                response_time=total_time,
                response_length=0,
                exception=None,
                context={"device_name": device_name, "status": "not_found"},
            )
        else:
            blob_data_size = len(str(result))  # Approximate size
            # Fire success event
            total_time = int((time.time() - start_time) * 1000)
            environment.events.request.fire(
                request_type="Storage",
                name="load_device_data",
                response_time=total_time,
                response_length=blob_data_size,
                exception=None,
                context={"device_name": device_name, "status": "success"},
            )

        return result

    except Exception as e:
        logger.warning(f"Failed to load device data for {device_name}: {e}")

        # Fire failure event
        total_time = int((time.time() - start_time) * 1000)
        environment.events.request.fire(
            request_type="Storage",
            name="load_device_data",
            response_time=total_time,
            response_length=blob_data_size,
            exception=str(e),
            context={"device_name": device_name, "status": "error"},
        )
        return None


provisioning_host = os.getenv("PROVISIONING_HOST")
id_scope = os.getenv("PROVISIONING_IDSCOPE")
dps_sas_key = os.getenv("PROVISIONING_SAS_KEY")

hub_message_interval = int(os.getenv("HUB_MESSAGE_INTERVAL", "5"))  # seconds
device_name_prefix = os.getenv("DEVICE_NAME_PREFIX", "device-")
hub_message_size = int(os.getenv("HUB_MESSAGE_SIZE", "256"))  # bytes


class CertUser(User):
    wait_time = constant_pacing(hub_message_interval)  # type: ignore[no-untyped-call]  # Time between tasks execution
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

        self.device_name = self.get_device_name()
        logger.info(f"Starting CertUser: {self.device_name}")
        self.issued_cert_data: str = ""
        self.private_key: Optional[EllipticCurvePrivateKey] = None
        self.registration_result: Optional[Any] = None
        self.device_client: Optional[Any] = None  # IoTHubDeviceClient loaded dynamically
        self.is_connected: bool = False
        self.cert_file: Optional[str] = None
        self.key_file: Optional[str] = None

        # Check if a registration result already exists in device data storage
        device_data = load_device_data(self.device_name, self.environment)

        if device_data is not None:
            # Restore device state from storage
            logger.info(f"Loaded existing registration for {self.device_name}")
            try:
                # Reconstruct registration result (simplified object)
                class RegistrationState:
                    def __init__(self, assigned_hub: str, device_id: str):
                        self.assigned_hub = assigned_hub
                        self.device_id = device_id
                        self.issued_client_certificate = None

                class RegistrationResult:
                    def __init__(self, status: str, registration_state: RegistrationState):
                        self.status = status
                        self.registration_state = registration_state

                reg_state = RegistrationState(
                    assigned_hub=device_data["assigned_hub"], device_id=device_data["device_id"]
                )
                self.registration_result = RegistrationResult(
                    status=device_data["registration_status"], registration_state=reg_state
                )

                # Deserialize private key from PEM
                loaded_key = serialization.load_pem_private_key(
                    device_data["private_key_pem"].encode("utf-8"), password=None
                )
                # Type assertion - we know this is an EC key
                self.private_key = cast(EllipticCurvePrivateKey, loaded_key)

                # Load certificate
                self.issued_cert_data = device_data["issued_cert_pem"]

                # If assigned, skip provisioning and go straight to connect
                if device_data["registration_status"] == "assigned":
                    logger.info(f"Using existing registration for {self.device_name}, skipping provisioning")
                    self.connect_hub()
                    return
            except Exception as e:
                logger.warning(f"Failed to restore device state from storage: {e}, will re-provision")
                # Fall through to provisioning

        # Provision with DPS (with retry logic)
        self.provision_device()

        # Connect to IoT Hub if provisioning succeeded
        if self.registration_result is not None and self.registration_result.status == "assigned":
            self.connect_hub()

    def _provision_device_inner(self) -> None:
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

            if device_key is not None:
                print("Using symmetric-key authentication")
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
            # Equivalent to: openssl ecparam -name prime256v1 -genkey -noout | openssl pkcs8 -topk8 -nocrypt
            self.private_key = ec.generate_private_key(ec.SECP256R1())

            # Generate CSR (Certificate Signing Request)
            # Equivalent to: openssl req -new -key $key -subj "/CN=$device_name" -outform DER | openssl base64 -A
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
            self.registration_result = provisioning_device_client.register()

            # Validate registration state exists
            if self.registration_result.registration_state is None:
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

            # Store the issued certificate data instead of writing to disk
            if self.registration_result.registration_state.issued_client_certificate:
                self.issued_cert_data = x509_certificate_list_to_pem(
                    self.registration_result.registration_state.issued_client_certificate
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
                context={"registration_id": self.device_name, "status": self.registration_result.status},
            )

            if self.registration_result.status == "assigned":
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
                        "registration_status": self.registration_result.status,
                        "assigned_hub": self.registration_result.registration_state.assigned_hub,
                        "device_id": self.registration_result.registration_state.device_id,
                        "private_key_pem": private_key_pem,
                        "issued_cert_pem": self.issued_cert_data,
                        "registration_timestamp": datetime.now(tz=timezone.utc).isoformat(),
                    }
                    save_device_data(self.device_name, device_data, self.environment)

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

    def provision_device(self) -> None:
        """Provision a device with DPS using retry logic."""
        retry_with_backoff(
            operation_name=f"provision_device({self.device_name})",
            operation_func=self._provision_device_inner,
            base_wait=60,
            max_jitter=30,
        )

    def _connect_hub_inner(self) -> None:
        """Inner hub connection logic to be wrapped with retry."""
        # Import azure.iot.device after wheel is loaded
        from azure.iot.device import IoTHubDeviceClient, X509

        # Load registration data from storage if not already in memory
        if self.registration_result is None or self.private_key is None or not self.issued_cert_data:
            device_data = load_device_data(self.device_name, self.environment)
            if device_data is not None:
                logger.info("Loading device data from storage for connection")

                # Reconstruct registration result
                class RegistrationState:
                    def __init__(self, assigned_hub: str, device_id: str):
                        self.assigned_hub = assigned_hub
                        self.device_id = device_id
                        self.issued_client_certificate = None

                class RegistrationResult:
                    def __init__(self, status: str, registration_state: RegistrationState):
                        self.status = status
                        self.registration_state = registration_state

                reg_state = RegistrationState(
                    assigned_hub=device_data["assigned_hub"], device_id=device_data["device_id"]
                )
                self.registration_result = RegistrationResult(
                    status=device_data["registration_status"], registration_state=reg_state
                )

                # Deserialize private key from PEM
                loaded_key = serialization.load_pem_private_key(
                    device_data["private_key_pem"].encode("utf-8"), password=None
                )
                # Type assertion - we know this is an EC key
                self.private_key = cast(EllipticCurvePrivateKey, loaded_key)

                # Load certificate
                self.issued_cert_data = device_data["issued_cert_pem"]

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

    def connect_hub(self) -> None:
        """Connect to IoT Hub using X.509 certificate from provisioning with retry logic."""
        retry_with_backoff(
            operation_name=f"connect_hub({self.device_name})",
            operation_func=self._connect_hub_inner,
            base_wait=60,
            max_jitter=30,
        )

    @task
    def send_message(self) -> None:
        """Send a single telemetry message to IoT Hub."""
        # Import azure.iot.device after wheel is loaded
        from azure.iot.device import Message

        # Ensure device is connected before sending
        if not self.is_connected or self.device_client is None:
            logger.warning("Device not connected, skipping message send")
            return

        start_time = time.time()

        try:
            # Create and send message
            message_data = create_msg(hub_message_size)
            msg = Message(message_data)  # type: ignore[no-untyped-call]

            # Send message (synchronous for gevent compatibility)
            self.device_client.send_message(msg)

            # Log success
            total_time = int((time.time() - start_time) * 1000)
            logger.debug("Message sent successfully")
            self.environment.events.request.fire(
                request_type="Hub",
                name="send_message",
                response_time=total_time,
                response_length=len(msg.data),
                exception=None,
                context={"status": "sent"},
            )

        except Exception as e:
            # Log as a locust error
            total_time = int((time.time() - start_time) * 1000)
            logger.error(f"Failed to send message: {str(e)}")
            self.environment.events.request.fire(
                request_type="Hub",
                name="send_message",
                response_time=total_time,
                response_length=0,
                exception=str(e),
                context={"status": "error"},
            )

    def on_stop(self) -> None:
        """Cleanup method called when the user stops."""
        if self.device_client is not None and self.is_connected:
            try:
                logger.info("Disconnecting from IoT Hub")
                self.device_client.shutdown()
                self.is_connected = False
            except Exception as e:
                logger.error(f"Error during shutdown: {str(e)}")

        # Clean up temporary certificate and key files
        if self.cert_file and os.path.exists(self.cert_file):
            try:
                os.unlink(self.cert_file)
            except Exception as e:
                logger.error(f"Error removing cert file: {str(e)}")

        if self.key_file and os.path.exists(self.key_file):
            try:
                os.unlink(self.key_file)
            except Exception as e:
                logger.error(f"Error removing key file: {str(e)}")
