import base64
import hashlib
import hmac
import logging
import os
import tempfile
import time
import uuid
from locust import User, task, between
from typing import Any, Optional

from azure.iot.device import ProvisioningDeviceClient, IoTHubDeviceClient, Message, X509
from azure.iot.device.models import RegistrationResult
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

messages_to_send = 10
provisioning_host = os.getenv("PROVISIONING_HOST")
id_scope = os.getenv("PROVISIONING_IDSCOPE")
registration_id = os.getenv("PROVISIONING_REGISTRATION_ID")

dps_sas_key = os.getenv("PROVISIONING_SAS_KEY")


def x509_certificate_list_to_pem(cert_list: list[str]) -> str:
    begin_cert_header = "-----BEGIN CERTIFICATE-----\r\n"
    end_cert_footer = "\r\n-----END CERTIFICATE-----"
    separator = end_cert_footer + "\r\n" + begin_cert_header
    return begin_cert_header + separator.join(cert_list) + end_cert_footer


class CertUser(User):
    wait_time = between(5, 10)  # type: ignore[no-untyped-call]  # Time between tasks execution

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        logger.info("Starting CertUser")
        self.issued_cert_data: str = ""
        self.private_key: Optional[EllipticCurvePrivateKey] = None
        self.registration_result: Optional[RegistrationResult] = None
        self.device_client: Optional[IoTHubDeviceClient] = None
        self.is_connected: bool = False
        self.cert_file: Optional[str] = None
        self.key_file: Optional[str] = None

        # Provision with DPS
        self.provision_device()

        # Connect to IoT Hub if provisioning succeeded
        if self.registration_result is not None and self.registration_result.status == "assigned":
            self.connect_hub()

    # Provision a device with DPS
    def provision_device(self) -> None:
        # Set start time, but override it later for the relevant time.
        start_time = time.time()

        try:
            device_key: str = ""

            # Handle optional dps_sas_key and registration_id
            if dps_sas_key is not None and registration_id is not None:
                key_bytes = base64.b64decode(dps_sas_key)
                derived_key = hmac.new(key_bytes, registration_id.encode("utf-8"), hashlib.sha256).digest()
                device_key = base64.b64encode(derived_key).decode("utf-8")

            if device_key is not None:
                print("Using symmetric-key authentication")
                # Validate required environment variables
                if provisioning_host is None or registration_id is None or id_scope is None:
                    raise Exception(
                        "Missing required environment variables: PROVISIONING_HOST, PROVISIONING_IDSCOPE, or PROVISIONING_REGISTRATION_ID"
                    )
                provisioning_device_client = ProvisioningDeviceClient.create_from_symmetric_key(
                    provisioning_host=provisioning_host,
                    registration_id=registration_id,
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
            # Equivalent to: openssl req -new -key $key -subj "/CN=$registration_id" -outform DER | openssl base64 -A
            if registration_id is None:
                raise Exception("PROVISIONING_REGISTRATION_ID is required")

            csr_builder = x509.CertificateSigningRequestBuilder()
            csr_builder = csr_builder.subject_name(
                x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, registration_id)])
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
                    request_type="DPS_CSR",
                    name="device_provision",
                    response_time=total_time,
                    response_length=0,
                    exception=error_msg,
                    context={"registration_id": registration_id, "status": "error"},
                )
                return

            # Store the issued certificate data instead of writing to disk
            if self.registration_result.registration_state.issued_client_certificate:
                self.issued_cert_data = x509_certificate_list_to_pem(
                    self.registration_result.registration_state.issued_client_certificate
                )

            # Log success
            total_time = int((time.time() - start_time) * 1000)
            logger.debug(f"Device {registration_id} provisioned successfully")
            self.environment.events.request.fire(
                request_type="DPS_CSR",
                name="device_provision",
                response_time=total_time,
                response_length=0,
                exception=None,
                context={"registration_id": registration_id, "status": self.registration_result.status},
            )

            if self.registration_result.status == "assigned":
                logger.info("Registration assigned")

        except Exception as e:
            # Log as a locust error
            total_time = int((time.time() - start_time) * 1000)
            logger.error(f"Device {registration_id} provisioning failed: {str(e)}")
            self.environment.events.request.fire(
                request_type="DPS_CSR",
                name="device_provision",
                response_time=total_time,
                response_length=0,
                exception=str(e),
                context={"registration_id": registration_id, "status": "error"},
            )

    def connect_hub(self) -> None:
        """Connect to IoT Hub using X.509 certificate from provisioning."""
        if self.registration_result is None or self.registration_result.registration_state is None:
            logger.error("Cannot connect to hub: no registration result")
            return

        if self.private_key is None:
            logger.error("Cannot connect to hub: no private key")
            return

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
                request_type="IoTHub",
                name="connect",
                response_time=total_time,
                response_length=0,
                exception=str(e),
                context={"status": "error"},
            )
            self.is_connected = False

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
                request_type="IoTHub",
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
                request_type="IoTHub",
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
