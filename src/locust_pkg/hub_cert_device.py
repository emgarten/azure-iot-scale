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
from datetime import datetime, timezone
from typing import Any, Optional, cast

import paho.mqtt.client as mqtt
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
from cryptography.x509.oid import NameOID

from storage import load_device_data as _load_device_data
from storage import save_device_data as _save_device_data
from utils import retry_with_backoff, x509_certificate_list_to_pem

logger = logging.getLogger("locust.hub_cert_device")

# Environment configuration
provisioning_host = os.getenv("PROVISIONING_HOST")
id_scope = os.getenv("PROVISIONING_IDSCOPE")
dps_sas_key = os.getenv("PROVISIONING_SAS_KEY")

# MQTT configuration for credential management
MQTT_PORT = 8883
API_VERSION = "2025-08-01-preview"
credential_response_timeout = int(os.getenv("CREDENTIAL_RESPONSE_TIMEOUT", "300"))  # Default 5 minutes


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
        self.private_key: Optional[EllipticCurvePrivateKey] = None
        self.issued_cert_data: str = ""
        self.registration_result: Optional[RegistrationResult] = None

        # Paho MQTT client for hub connection
        self.client: Optional[mqtt.Client] = None
        self.is_connected: bool = False
        self.cert_file: Optional[str] = None
        self.key_file: Optional[str] = None

        # Track last certificate chain response time (ticks from time.time())
        self.last_cert_chain_response_time: Optional[float] = None

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

    def disconnect(self) -> None:
        """Disconnect from IoT Hub and clean up resources."""
        self._disconnect()

    def _disconnect(self) -> None:
        """Disconnect the MQTT client and clean up resources."""
        if self.client is not None:
            try:
                logger.info(f"Disconnecting {self.device_name} from IoT Hub")
                self.client.loop_stop()
                self.client.disconnect()
            except Exception as e:
                logger.debug(f"Error disconnecting MQTT client: {e}")
            self.client = None

        self.is_connected = False

        # Clean up temporary certificate and key files
        if self.cert_file and os.path.exists(self.cert_file):
            try:
                os.unlink(self.cert_file)
            except Exception as e:
                logger.debug(f"Error removing cert file: {e}")
            self.cert_file = None

        if self.key_file and os.path.exists(self.key_file):
            try:
                os.unlink(self.key_file)
            except Exception as e:
                logger.debug(f"Error removing key file: {e}")
            self.key_file = None

    def _create_csr(self) -> str:
        """Create a CSR using the existing private key.

        Returns:
            Base64-encoded DER format CSR string.

        Raises:
            Exception: If no private key is available.
        """
        if self.private_key is None:
            raise Exception("Cannot create CSR: no private key available")

        csr_builder = x509.CertificateSigningRequestBuilder()
        csr_builder = csr_builder.subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, self.device_name)]))
        csr = csr_builder.sign(self.private_key, hashes.SHA256())

        # Convert CSR to DER format and then base64 encode it
        csr_der = csr.public_bytes(serialization.Encoding.DER)
        return base64.b64encode(csr_der).decode("utf-8")

    def _credential_on_message(
        self,
        client: mqtt.Client,
        userdata: Any,
        msg: mqtt.MQTTMessage,
    ) -> None:
        """Handle credential response messages from IoT Hub (observer pattern).

        This callback is invoked when messages arrive on the credential response topic.
        It emits different Locust events based on the response type:
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

        payload_size = len(msg.payload) if msg.payload else 0

        # Parse payload
        payload_data: Optional[dict[str, Any]] = None
        if msg.payload:
            try:
                payload_str = msg.payload.decode("utf-8")
                payload_data = json.loads(payload_str)
            except (json.JSONDecodeError, UnicodeDecodeError) as e:
                # Emit parse error event
                logger.error(f"Error parsing credential response: {e}")
                self.environment.events.request.fire(
                    request_type="Hub",
                    name="credential_parse_error",
                    response_time=0,
                    response_length=payload_size,
                    exception=f"Failed to parse response: {e}",
                    context={"device_name": self.device_name, "status_code": status_code},
                )
                return

        # Handle based on status code
        if status_code == "202":
            # Request accepted, waiting for certificate
            logger.debug(f"Credential request accepted for {self.device_name}")
            self.environment.events.request.fire(
                request_type="Hub",
                name="credential_accept",
                response_time=0,
                response_length=payload_size,
                exception=None,
                context={"device_name": self.device_name, "status_code": status_code},
            )

        elif status_code == "200":
            # Certificate response - check if certificates are present
            if payload_data and "certificates" in payload_data:
                cert_data = payload_data["certificates"]
                if isinstance(cert_data, list) and len(cert_data) > 0:
                    # Certificate chain received - record timestamp
                    self.last_cert_chain_response_time = time.time()
                    logger.info(f"Certificate chain received for {self.device_name}")
                    self.environment.events.request.fire(
                        request_type="Hub",
                        name="credential_certificate",
                        response_time=0,
                        response_length=payload_size,
                        exception=None,
                        context={"device_name": self.device_name, "status_code": status_code},
                    )
                else:
                    # Empty certificates array
                    logger.warning(f"Empty certificates array for {self.device_name}")
                    self.environment.events.request.fire(
                        request_type="Hub",
                        name="credential_missing_certificates",
                        response_time=0,
                        response_length=payload_size,
                        exception="Certificates array is empty",
                        context={"device_name": self.device_name, "status_code": status_code},
                    )
            else:
                # No certificates field in response
                logger.warning(f"No certificates field in response for {self.device_name}")
                self.environment.events.request.fire(
                    request_type="Hub",
                    name="credential_missing_certificates",
                    response_time=0,
                    response_length=payload_size,
                    exception="No certificates field in response",
                    context={"device_name": self.device_name, "status_code": status_code},
                )

        else:
            # Unexpected status code
            logger.warning(f"Credential request returned unexpected status {status_code} for {self.device_name}")
            self.environment.events.request.fire(
                request_type="Hub",
                name="credential_unexpected_status",
                response_time=0,
                response_length=payload_size,
                exception=f"Unexpected status code: {status_code}",
                context={"device_name": self.device_name, "status_code": status_code},
            )

    def connect(self) -> bool:
        """Connect to IoT Hub via Paho MQTT.

        This method establishes a persistent MQTT connection and subscribes to the
        credential response topic. The connection remains open for the lifetime of the
        device to handle multiple certificate requests using the observer pattern.

        Returns:
            True if connection and subscription were successful, False otherwise.
        """
        if self.is_connected and self.client is not None:
            logger.debug(f"Already connected for {self.device_name}")
            return True

        if self.registration_result is None or self.registration_result.registration_state is None:
            logger.error("Cannot connect: no registration result")
            return False

        if self.private_key is None or not self.issued_cert_data:
            logger.error("Cannot connect: missing private key or certificate")
            return False

        hostname = self.registration_result.registration_state.assigned_hub
        device_id = self.registration_result.registration_state.device_id

        start_time = time.time()

        try:
            # Serialize the private key to PEM format
            private_key_pem = self.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            ).decode("utf-8")

            # Write certificate and key to temporary files for MQTT TLS
            cert_fd, self.cert_file = tempfile.mkstemp(suffix=".pem", text=True)
            key_fd, self.key_file = tempfile.mkstemp(suffix=".pem", text=True)

            with os.fdopen(cert_fd, "w") as f:
                f.write(self.issued_cert_data)
            with os.fdopen(key_fd, "w") as f:
                f.write(private_key_pem)

            # Create MQTT client
            self.client = mqtt.Client(
                client_id=device_id,
                protocol=mqtt.MQTTv311,
            )

            # Set username for Azure IoT Hub
            username = f"{hostname}/{device_id}/?api-version={API_VERSION}"
            self.client.username_pw_set(username=username)

            # Configure TLS with client certificate
            ssl_context = ssl.create_default_context()
            ssl_context.load_cert_chain(certfile=self.cert_file, keyfile=self.key_file)
            self.client.tls_set_context(ssl_context)

            # Set message callback (observer pattern)
            self.client.on_message = self._credential_on_message

            # Connect to IoT Hub
            logger.debug(f"Connecting to {hostname} via MQTT")
            self.client.connect(hostname, MQTT_PORT, keepalive=60)
            self.client.loop_start()

            # Wait for connection
            connect_timeout = 120
            connect_start = time.time()
            while not self.client.is_connected() and (time.time() - connect_start) < connect_timeout:
                time.sleep(0.1)

            if not self.client.is_connected():
                raise Exception("Failed to connect to IoT Hub via MQTT")

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

    def request_new_certificate(self, replace: bool = False) -> bool:
        """Request a new certificate from IoT Hub via MQTT credential management API.

        This method sends a CSR to request a new certificate using the persistent
        MQTT connection. It is fire-and-forget - responses are handled asynchronously
        by the observer pattern via _credential_on_message callback.

        The MQTT connection must be established first via connect().

        Args:
            replace: If True, include "replace": "*" in the payload to replace existing certificates.

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

        if self.private_key is None:
            logger.error("Cannot request new certificate: no private key")
            self.environment.events.request.fire(
                request_type="Hub",
                name="credential_request",
                response_time=0,
                response_length=0,
                exception="No private key",
                context={"device_name": self.device_name, "status": "error"},
            )
            return False

        # Ensure MQTT client is connected
        if not self.is_connected or self.client is None:
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
            request_id = random.randint(1, 99999999)
            publish_topic = f"$iothub/credentials/POST/issueCertificate/?$rid={request_id}"
            payload_dict: dict[str, str] = {"id": device_id, "csr": csr_data}
            if replace:
                payload_dict["replace"] = "*"
            payload = json.dumps(payload_dict)

            logger.debug(f"Sending credential request to {publish_topic}")
            # At this point client is guaranteed to be non-None (checked above)
            assert self.client is not None
            result = self.client.publish(publish_topic, payload=payload, qos=1)
            if result.rc != mqtt.MQTT_ERR_SUCCESS:
                raise Exception(f"Failed to publish CSR request: {result.rc}")

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
