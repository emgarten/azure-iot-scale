import base64
import hashlib
import hmac
import os
import tempfile
import time
import uuid
from datetime import datetime, timezone
from locust import User, task, constant_pacing
import logging
from typing import Any, Optional, cast

from azure.iot.device import ProvisioningDeviceClient, IoTHubDeviceClient, Message, X509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes

from utils import x509_certificate_list_to_pem, retry_with_backoff
from storage import save_device_data, load_device_data

logger = logging.getLogger("locust.cert_user")

provisioning_host = os.getenv("PROVISIONING_HOST")
id_scope = os.getenv("PROVISIONING_IDSCOPE")
dps_sas_key = os.getenv("PROVISIONING_SAS_KEY")

hub_message_interval = int(os.getenv("HUB_MESSAGE_INTERVAL", "5"))  # seconds
device_name_prefix = os.getenv("DEVICE_NAME_PREFIX", "device-")


class CertUser(User):
    wait_time = constant_pacing(hub_message_interval)  # type: ignore[no-untyped-call]  # Time between tasks execution
    _device_counter: int = 0  # Class-level counter for unique device numbering

    @classmethod
    def get_device_name(cls) -> str:
        """Generate a unique device name using the prefix and an incrementing counter."""
        device_name = f"{device_name_prefix}{cls._device_counter}"
        cls._device_counter += 1
        return device_name

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.device_name = self.get_device_name()
        logger.info(f"Starting CertUser: {self.device_name}")
        self.issued_cert_data: str = ""
        self.private_key: Optional[EllipticCurvePrivateKey] = None
        self.registration_result: Optional[Any] = None
        self.device_client: Optional[IoTHubDeviceClient] = None
        self.is_connected: bool = False
        self.cert_file: Optional[str] = None
        self.key_file: Optional[str] = None

        # Check if a registration result already exists in device data storage
        device_data = load_device_data(self.device_name)

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
                    save_device_data(self.device_name, device_data)

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
        # Load registration data from storage if not already in memory
        if self.registration_result is None or self.private_key is None or not self.issued_cert_data:
            device_data = load_device_data(self.device_name)
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
                    request_type="IoTHub",
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
        # Ensure device is connected before sending
        if not self.is_connected or self.device_client is None:
            logger.warning("Device not connected, skipping message send")
            return

        start_time = time.time()
        message_id = str(uuid.uuid4())

        try:
            # Create and send message
            msg = Message(f"test wind speed {time.time()}")  # type: ignore[no-untyped-call]
            msg.message_id = message_id

            # Send message (synchronous for gevent compatibility)
            self.device_client.send_message(msg)

            # Log success
            total_time = int((time.time() - start_time) * 1000)
            logger.debug(f"Message {message_id} sent successfully")
            self.environment.events.request.fire(
                request_type="Hub",
                name="send_message",
                response_time=total_time,
                response_length=len(msg.data),
                exception=None,
                context={"message_id": message_id, "status": "sent"},
            )

        except Exception as e:
            # Log as a locust error
            total_time = int((time.time() - start_time) * 1000)
            logger.error(f"Failed to send message {message_id}: {str(e)}")
            self.environment.events.request.fire(
                request_type="Hub",
                name="send_message",
                response_time=total_time,
                response_length=0,
                exception=str(e),
                context={"message_id": message_id, "status": "error"},
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
