"""
Locust load testing script for Azure IoT Hub Device Provisioning Service (DPS).
This script simulates multiple devices attempting to provision using X.509 certificates.

Written by Pratik
"""

import os
import time
import logging
import uuid
import json
from datetime import datetime, timedelta, timezone
from dataclasses import dataclass
from typing import Any
from locust import User, task, between
from azure.iot.device import ProvisioningDeviceClient, X509
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

# Configure logging
logging.basicConfig(
    level=logging.DEBUG, format="%(asctime)s - %(levelname)s - %(message)s"  # Changed to DEBUG for more detailed logs
)
logger = logging.getLogger(__name__)


@dataclass
class DPSConfig:
    """Configuration class for DPS settings"""

    provisioning_host: str = "global.azure-devices-provisioning.net"
    id_scope: str = "0ne00C7FA7D"  # Replace with your ID scope
    key_size: int = 2048
    cert_validity_days: int = 30
    organization_name: str = "Test Organization"
    country_name: str = "US"
    state: str = "WA"
    locality: str = "Redmond"


class X509CertGenerator:
    """Handles X.509 certificate generation for device authentication"""

    def __init__(self, key_size: int = 2048) -> None:
        """Initialize the certificate generator"""
        self.key_size = key_size
        self.load_ca_certificates()

    def load_ca_certificates(self) -> None:
        """Load the intermediate CA certificate and private key"""
        try:
            # Load intermediate CA key
            with open("intermediate_ca.key", "rb") as key_file:
                key_data = key_file.read()
                self.ca_key = serialization.load_pem_private_key(
                    key_data,
                    password=None,
                )

            # Load intermediate CA cert
            with open("intermediate_ca.cer", "rb") as cert_file:
                cert_data = cert_file.read()
                self.ca_cert = x509.load_pem_x509_certificate(cert_data)
                logger.debug(f"Loaded intermediate CA with subject: {self.ca_cert.subject}")

            # Load root CA cert (for chain)
            with open("root_ca.cer", "rb") as root_file:
                root_data = root_file.read()
                self.root_cert = x509.load_pem_x509_certificate(root_data)
                logger.debug(f"Loaded root CA with subject: {self.root_cert.subject}")

            # Verify certificate chain
            logger.debug("Verifying certificate chain...")
            logger.debug(f"Root CA: {self.root_cert.subject}")
            logger.debug(f"Root CA Serial: {self.root_cert.serial_number}")
            logger.debug(f"Intermediate CA: {self.ca_cert.subject}")
            logger.debug(f"Intermediate CA Serial: {self.ca_cert.serial_number}")
            logger.debug(f"Intermediate CA Issuer: {self.ca_cert.issuer}")

            logger.info("Successfully loaded CA certificates")
        except Exception as e:
            logger.error(f"Failed to load CA certificates: {str(e)}")
            raise

    def create_name(self, common_name: str, org_name: str, country: str, state: str, locality: str) -> x509.Name:
        """Create X509 Name object"""
        return x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, common_name),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, org_name),
                x509.NameAttribute(NameOID.COUNTRY_NAME, country),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state),
                x509.NameAttribute(NameOID.LOCALITY_NAME, locality),
            ]
        )

    def generate_cert(
        self,
        device_id: str,
        validity_days: int = 30,
        org_name: str = "Test Organization",
        country: str = "US",
        state: str = "WA",
        locality: str = "Redmond",
    ) -> tuple[x509.Certificate, RSAPrivateKey]:
        """Generate a device certificate signed by the intermediate CA"""
        # Generate device key pair
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=self.key_size)

        # Create name attributes
        name = self.create_name(device_id, org_name, country, state, locality)

        # Create timestamps
        now = datetime.now(timezone.utc)

        # Build certificate
        builder = x509.CertificateBuilder()
        builder = builder.subject_name(name)
        builder = builder.issuer_name(self.ca_cert.subject)
        builder = builder.public_key(private_key.public_key())
        builder = builder.serial_number(x509.random_serial_number())
        builder = builder.not_valid_before(now)
        builder = builder.not_valid_after(now + timedelta(days=validity_days))

        # Add extensions
        builder = builder.add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)

        # Add Key Usage
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )

        # Add Extended Key Usage
        builder = builder.add_extension(
            x509.ExtendedKeyUsage(
                [
                    x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,
                ]
            ),
            critical=True,
        )

        # Add Authority Key Identifier
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(self.ca_cert.public_key()),  # type: ignore[arg-type]
            critical=False,
        )

        # Add Subject Key Identifier
        builder = builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()), critical=False
        )

        # Sign the certificate with intermediate CA
        certificate = builder.sign(private_key=self.ca_key, algorithm=hashes.SHA256())  # type: ignore[arg-type]

        logger.debug(f"Generated device certificate for {device_id}")
        logger.debug(f"Device cert subject: {certificate.subject}")
        logger.debug(f"Device cert issuer: {certificate.issuer}")
        logger.debug(f"Device cert serial: {certificate.serial_number}")

        return certificate, private_key


class DeviceProvisioningUser(User):
    """Locust user class that simulates device provisioning with DPS"""

    wait_time = between(1, 2)  # type: ignore[no-untyped-call]  # Time between tasks execution

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Initialize the device provisioning user"""
        super().__init__(*args, **kwargs)
        self.config = DPSConfig()
        self.cert_generator = X509CertGenerator(key_size=self.config.key_size)
        logger.info(f"Using DPS host: {self.config.provisioning_host}")
        logger.info(f"Using ID scope: {self.config.id_scope}")

    def generate_device_cert(self, registration_id: str) -> tuple[str, str]:
        """Generate and save device certificate and private key"""
        cert, key = self.cert_generator.generate_cert(
            registration_id,  # Use registration_id as the CN
            validity_days=self.config.cert_validity_days,
            org_name=self.config.organization_name,
            country=self.config.country_name,
            state=self.config.state,
            locality=self.config.locality,
        )

        # Save cert and key to files with certificate chain
        cert_path = f"device_{registration_id}_cert.pem"
        key_path = f"device_{registration_id}_key.pem"

        try:
            # Save certificate with full chain
            with open(cert_path, "wb") as f:
                # Write device certificate
                cert_bytes = cert.public_bytes(serialization.Encoding.PEM)
                f.write(cert_bytes)
                # Write intermediate CA certificate
                ca_bytes = self.cert_generator.ca_cert.public_bytes(serialization.Encoding.PEM)
                f.write(ca_bytes)
                # Write root CA certificate
                root_bytes = self.cert_generator.root_cert.public_bytes(serialization.Encoding.PEM)
                f.write(root_bytes)

                logger.debug(f"Certificate chain for {registration_id}:")
                logger.debug(f"Device cert: {cert_bytes.decode()}")
                logger.debug(f"Intermediate CA: {ca_bytes.decode()}")
                logger.debug(f"Root CA: {root_bytes.decode()}")

            # Save private key
            with open(key_path, "wb") as f:
                f.write(
                    key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.PKCS8,
                        encryption_algorithm=serialization.NoEncryption(),
                    )
                )

            logger.debug(f"Generated certificates for device {registration_id}")
            return cert_path, key_path

        except Exception as e:
            logger.error(f"Failed to save certificates: {str(e)}")
            raise

    def on_mqtt_publish(self, payload: Any) -> None:
        """Log the MQTT payload being published"""
        try:
            payload_dict = json.loads(payload)
            logger.debug(f"Registration payload: {json.dumps(payload_dict, indent=2)}")
        except (json.JSONDecodeError, Exception):
            logger.debug(f"Raw registration payload: {payload}")

    @task
    def provision_device(self) -> None:
        """Device provisioning task"""
        start_time = time.time()
        registration_id = f"dev{str(uuid.uuid4())[:8]}"  # Shorter, simpler ID
        cert_path = key_path = None

        try:
            # Generate device certificates
            cert_path, key_path = self.generate_device_cert(registration_id)

            # Create provisioning client
            x509 = X509(cert_file=cert_path, key_file=key_path)  # type: ignore[no-untyped-call]
            provisioning_device_client = ProvisioningDeviceClient.create_from_x509_certificate(
                provisioning_host=self.config.provisioning_host,
                registration_id=registration_id,
                id_scope=self.config.id_scope,
                x509=x509,
            )

            logger.debug(f"Attempting to provision device {registration_id}")
            logger.debug(f"Using registration ID: {registration_id}")

            # Attempt to provision the device
            registration_result = provisioning_device_client.register()
            total_time = int((time.time() - start_time) * 1000)

            # Record the result
            if registration_result.status == "assigned":
                logger.info(f"Device {registration_id} provisioned successfully")
                self.environment.events.request.fire(
                    request_type="DPS",
                    name="device_provision",
                    response_time=total_time,
                    response_length=0,
                    exception=None,
                    context={"device_id": registration_id, "status": registration_result.status},
                )
            else:
                error_msg = f"Registration failed with status: {registration_result.status}"
                logger.error(f"Device {registration_id}: {error_msg}")
                logger.error(f"Registration details: {registration_result}")
                self.environment.events.request.fire(
                    request_type="DPS",
                    name="device_provision",
                    response_time=total_time,
                    response_length=0,
                    exception=error_msg,
                    context={"device_id": registration_id, "status": registration_result.status},
                )

        except Exception as e:
            total_time = int((time.time() - start_time) * 1000)
            logger.error(f"Device {registration_id} provisioning failed: {str(e)}")
            self.environment.events.request.fire(
                request_type="DPS",
                name="device_provision",
                response_time=total_time,
                response_length=0,
                exception=str(e),
                context={"device_id": registration_id, "status": "error"},
            )

        finally:
            # Cleanup temporary cert files
            if cert_path and key_path:
                try:
                    os.remove(cert_path)
                    os.remove(key_path)
                    logger.debug(f"Cleaned up certificates for device {registration_id}")
                except Exception as e:
                    logger.warning(f"Failed to cleanup certificates: {str(e)}")
