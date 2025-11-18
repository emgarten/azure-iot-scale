import asyncio
import base64
import hashlib
import hmac
import logging
import os
import sys
import uuid

from azure.iot.device import Message, X509
from azure.iot.device.aio import IoTHubDeviceClient, ProvisioningDeviceClient

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

messages_to_send = 10
provisioning_host = os.getenv("PROVISIONING_HOST")
id_scope = os.getenv("PROVISIONING_IDSCOPE")
registration_id = os.getenv("PROVISIONING_REGISTRATION_ID")

dps_sas_key = os.getenv("PROVISIONING_SAS_KEY")

csr_data = os.getenv("PROVISIONING_CSR")
csr_key_file = os.getenv("PROVISIONING_CSR_KEY_FILE")
issued_cert_file = os.getenv("PROVISIONING_ISSUED_CERT_FILE")
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


async def main() -> None:
    if dps_sas_key is not None:
        print("Using symmetric-key authentication")
        provisioning_device_client = ProvisioningDeviceClient.create_from_symmetric_key(
            provisioning_host=provisioning_host,
            registration_id=registration_id,
            id_scope=id_scope,
            symmetric_key=device_key,
        )
    else:
        print("Either provide PROVISIONING_X509_CERT_FILE and PROVISIONING_X509_KEY_FILE or PROVISIONING_SAS_KEY")
        sys.exit(1)

    # set the CSR on the client
    provisioning_device_client.client_certificate_signing_request = csr_data

    registration_result = await provisioning_device_client.register()

    print("The complete registration result is")
    print(vars(registration_result.registration_state))

    if issued_cert_file is not None:
        with open(issued_cert_file, "w") as out_ca_pem:
            # Write the issued certificate on the file.
            out_ca_pem.write(
                x509_certificate_list_to_pem(registration_result.registration_state.issued_client_certificate)
            )

    if registration_result.status == "assigned":
        print("Will send telemetry from the provisioned device")

        iot_hub_x509 = X509(
            cert_file=issued_cert_file,
            key_file=csr_key_file,
        )

        device_client = IoTHubDeviceClient.create_from_x509_certificate(
            hostname=registration_result.registration_state.assigned_hub,
            device_id=registration_result.registration_state.device_id,
            x509=iot_hub_x509,
        )

        # Connect the client.
        await device_client.connect()

        async def send_test_message(i: int) -> None:
            print("sending message #" + str(i))
            msg = Message("test wind speed " + str(i))
            msg.message_id = uuid.uuid4()
            await device_client.send_message(msg)
            print("done sending message #" + str(i))

        # send `messages_to_send` messages in parallel
        await asyncio.gather(*[send_test_message(i) for i in range(1, messages_to_send + 1)])

        # finally, disconnect
        await device_client.shutdown()
    else:
        print("Can not send telemetry from the provisioned device")


if __name__ == "__main__":
    asyncio.run(main())
