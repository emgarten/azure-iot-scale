import base64
import hashlib
import hmac
import logging
import os
import time
from locust import User, task, between
from typing import Any

from azure.iot.device import ProvisioningDeviceClient
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
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
device_key: str = ""

# Handle optional dps_sas_key and registration_id
if dps_sas_key is not None and registration_id is not None:
    key_bytes = base64.b64decode(dps_sas_key)
    derived_key = hmac.new(key_bytes, registration_id.encode("utf-8"), hashlib.sha256).digest()
    device_key = base64.b64encode(derived_key).decode("utf-8")


def x509_certificate_list_to_pem(cert_list: list[str]) -> str:
    begin_cert_header = "-----BEGIN CERTIFICATE-----\r\n"
    end_cert_footer = "\r\n-----END CERTIFICATE-----"
    separator = end_cert_footer + "\r\n" + begin_cert_header
    return begin_cert_header + separator.join(cert_list) + end_cert_footer


class CertUser(User):
    wait_time = between(1, 2)  # type: ignore[no-untyped-call]  # Time between tasks execution

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        logger.info("Starting CertUser")
        self.issued_cert_data: str = ""

    @task
    def provision_device(self) -> None:
        # Set start time, but override it later for the relevant time.
        start_time = time.time()

        try:
            if dps_sas_key is not None:
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
            private_key = ec.generate_private_key(ec.SECP256R1())

            # Generate CSR (Certificate Signing Request)
            # Equivalent to: openssl req -new -key $key -subj "/CN=$registration_id" -outform DER | openssl base64 -A
            if registration_id is None:
                raise Exception("PROVISIONING_REGISTRATION_ID is required")

            csr_builder = x509.CertificateSigningRequestBuilder()
            csr_builder = csr_builder.subject_name(
                x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, registration_id)])
            )

            # Sign the CSR with the private key
            csr = csr_builder.sign(private_key, hashes.SHA256())

            # Convert CSR to DER format and then base64 encode it
            csr_der = csr.public_bytes(serialization.Encoding.DER)
            csr_data = base64.b64encode(csr_der).decode("utf-8")

            # Set the CSR on the client
            provisioning_device_client.client_certificate_signing_request = csr_data

            # Start tracking time here
            start_time = time.time()

            # Use synchronous register() instead of async await (gevent style for locust)
            registration_result = provisioning_device_client.register()

            # Validate registration state exists
            if registration_result.registration_state is None:
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
            if registration_result.registration_state.issued_client_certificate:
                self.issued_cert_data = x509_certificate_list_to_pem(
                    registration_result.registration_state.issued_client_certificate
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
                context={"registration_id": registration_id, "status": registration_result.status},
            )

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

        # Connect to hub
        # if registration_result.status == "assigned":
        #     print("Will send telemetry from the provisioned device")

        #     iot_hub_x509 = X509(
        #         cert_file=issued_cert_file,
        #         key_file=csr_key_file,
        #     )  # type: ignore[no-untyped-call]

        #     device_client = IoTHubDeviceClient.create_from_x509_certificate(
        #         hostname=registration_result.registration_state.assigned_hub,
        #         device_id=registration_result.registration_state.device_id,
        #         x509=iot_hub_x509,
        #     )

        #     # Connect the client.
        #     await device_client.connect()

        #     async def send_test_message(i: int) -> None:
        #         print("sending message #" + str(i))
        #         msg = Message("test wind speed " + str(i))  # type: ignore[no-untyped-call]
        #         msg.message_id = uuid.uuid4()
        #         await device_client.send_message(msg)
        #         print("done sending message #" + str(i))

        #     # send `messages_to_send` messages in parallel
        #     await asyncio.gather(*[send_test_message(i) for i in range(1, messages_to_send + 1)])

        #     # finally, disconnect
        #     await device_client.shutdown()
        # else:
        #     print("Can not send telemetry from the provisioned device")
