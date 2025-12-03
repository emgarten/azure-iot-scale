#!/usr/bin/env python3
"""Simple IoT device test script using certificate authentication.

This script provisions a device with Azure DPS, saves the issued certificate
to local disk, connects to IoT Hub, and sends telemetry messages in a loop.
"""

import argparse
import base64
import hashlib
import hmac
import os
import signal
import sys
import time
from typing import Any

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402

# Constants
MESSAGE_INTERVAL = 5  # seconds
MESSAGE_SIZE = 256  # bytes
DEFAULT_PROVISIONING_HOST = "global.azure-devices-provisioning.net"
DEFAULT_DEVICE_NAME = "test-device"

# Global flag for graceful shutdown
_running = True


def signal_handler(signum: int, frame: object) -> None:
    """Handle Ctrl+C for graceful shutdown."""
    global _running
    print("\nShutdown requested, finishing current operation...")
    _running = False


def x509_certificate_list_to_pem(cert_list: list[str]) -> str:
    """Convert a list of base64-encoded certificates to PEM format."""
    begin_cert_header = "-----BEGIN CERTIFICATE-----\r\n"
    end_cert_footer = "\r\n-----END CERTIFICATE-----"
    separator = end_cert_footer + "\r\n" + begin_cert_header
    return begin_cert_header + separator.join(cert_list) + end_cert_footer


def create_msg(size: int) -> bytes:
    """Create a message of the given size with the current UTC timestamp."""
    import orjson
    from datetime import datetime, timezone

    now = datetime.now(tz=timezone.utc).isoformat() + "Z"
    return orjson.dumps({"date": now, "val": "A" * size})


def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="IoT device test script using certificate authentication",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Example usage:
  python cert_test.py --output-dir ./certs --id-scope 0ne00ABCDEF --sas-key <key>
  python cert_test.py --output-dir ./certs --id-scope 0ne00ABCDEF --sas-key <key> --device-name my-device
        """,
    )
    parser.add_argument(
        "--output-dir",
        required=True,
        help="Directory to save certificate and key files",
    )
    parser.add_argument(
        "--provisioning-host",
        default=DEFAULT_PROVISIONING_HOST,
        help=f"DPS provisioning host (default: {DEFAULT_PROVISIONING_HOST})",
    )
    parser.add_argument(
        "--id-scope",
        required=True,
        help="DPS ID scope",
    )
    parser.add_argument(
        "--sas-key",
        required=True,
        help="DPS SAS key for symmetric key authentication",
    )
    parser.add_argument(
        "--device-name",
        default=DEFAULT_DEVICE_NAME,
        help=f"Device registration ID (default: {DEFAULT_DEVICE_NAME})",
    )
    return parser.parse_args()


def provision_device(
    provisioning_host: str,
    id_scope: str,
    sas_key: str,
    device_name: str,
    output_dir: str,
) -> tuple[str, str, str, str]:
    """Provision device with DPS and save certificates to disk.

    Returns:
        Tuple of (assigned_hub, device_id, cert_path, key_path)
    """
    from azure.iot.device import ProvisioningDeviceClient

    print(f"Provisioning device '{device_name}' with DPS...")

    # Derive device key from SAS key
    key_bytes = base64.b64decode(sas_key)
    derived_key = hmac.new(key_bytes, device_name.encode("utf-8"), hashlib.sha256).digest()
    device_key = base64.b64encode(derived_key).decode("utf-8")

    # Create provisioning client
    provisioning_client = ProvisioningDeviceClient.create_from_symmetric_key(
        provisioning_host=provisioning_host,
        registration_id=device_name,
        id_scope=id_scope,
        symmetric_key=device_key,
    )

    # Generate EC private key (prime256v1 = SECP256R1)
    print("Generating EC private key...")
    private_key = ec.generate_private_key(ec.SECP256R1())

    # Generate CSR (Certificate Signing Request)
    print("Creating certificate signing request...")
    csr_builder = x509.CertificateSigningRequestBuilder()
    csr_builder = csr_builder.subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, device_name)]))
    csr = csr_builder.sign(private_key, hashes.SHA256())

    # Convert CSR to DER format and then base64 encode it
    csr_der = csr.public_bytes(serialization.Encoding.DER)
    csr_data = base64.b64encode(csr_der).decode("utf-8")

    # Set the CSR on the client
    provisioning_client.client_certificate_signing_request = csr_data

    # Register with DPS
    print("Registering with DPS...")
    registration_result = provisioning_client.register()

    if registration_result.registration_state is None:
        raise RuntimeError("Registration failed: no registration state returned")

    if registration_result.status != "assigned":
        raise RuntimeError(f"Registration failed with status: {registration_result.status}")

    assigned_hub = registration_result.registration_state.assigned_hub
    device_id = registration_result.registration_state.device_id

    print(f"Device assigned to hub: {assigned_hub}")
    print(f"Device ID: {device_id}")

    # Get issued certificate
    issued_cert_data = ""
    if registration_result.registration_state.issued_client_certificate:
        issued_cert_data = x509_certificate_list_to_pem(
            registration_result.registration_state.issued_client_certificate
        )

    if not issued_cert_data:
        raise RuntimeError("No certificate issued by DPS")

    # Serialize private key to PEM
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")

    # Create output directory if it doesn't exist
    os.makedirs(output_dir, exist_ok=True)

    # Save certificate and key to disk
    cert_path = os.path.join(output_dir, f"{device_name}.cert.pem")
    key_path = os.path.join(output_dir, f"{device_name}.key.pem")

    print(f"Saving certificate to: {cert_path}")
    with open(cert_path, "w") as f:
        f.write(issued_cert_data)

    print(f"Saving private key to: {key_path}")
    with open(key_path, "w") as f:
        f.write(private_key_pem)

    # Set restrictive permissions on key file
    os.chmod(key_path, 0o600)

    return assigned_hub, device_id, cert_path, key_path


def connect_hub(
    hostname: str,
    device_id: str,
    cert_file: str,
    key_file: str,
) -> Any:
    """Connect to IoT Hub using X.509 certificate."""
    from azure.iot.device import IoTHubDeviceClient, X509

    print(f"Connecting to IoT Hub: {hostname}...")

    x509_cert = X509(cert_file, key_file)  # type: ignore[no-untyped-call]

    client = IoTHubDeviceClient.create_from_x509_certificate(
        hostname=hostname,
        device_id=device_id,
        x509=x509_cert,
    )

    client.connect()
    print("Connected to IoT Hub successfully!")

    return client


def send_messages(client: Any) -> None:
    """Send messages in a loop until interrupted."""
    from azure.iot.device import Message

    global _running
    message_count = 0

    print(f"\nSending messages every {MESSAGE_INTERVAL} seconds (Ctrl+C to stop)...")

    while _running:
        try:
            message_data = create_msg(MESSAGE_SIZE)
            msg = Message(message_data)  # type: ignore[no-untyped-call]

            client.send_message(msg)
            message_count += 1
            print(f"Message {message_count} sent ({len(message_data)} bytes)")

            # Sleep in small increments to allow faster Ctrl+C response
            for _ in range(MESSAGE_INTERVAL * 10):
                if not _running:
                    break
                time.sleep(0.1)

        except Exception as e:
            print(f"Error sending message: {e}")
            if _running:
                print("Retrying in 5 seconds...")
                time.sleep(5)

    print(f"\nTotal messages sent: {message_count}")


def main() -> int:
    """Main entry point."""
    args = parse_args()

    # Set up signal handler for graceful shutdown
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    client = None

    try:
        # Provision device
        assigned_hub, device_id, cert_path, key_path = provision_device(
            provisioning_host=args.provisioning_host,
            id_scope=args.id_scope,
            sas_key=args.sas_key,
            device_name=args.device_name,
            output_dir=args.output_dir,
        )

        # Connect to IoT Hub
        client = connect_hub(
            hostname=assigned_hub,
            device_id=device_id,
            cert_file=cert_path,
            key_file=key_path,
        )

        # Send messages in loop
        send_messages(client)

    except Exception as e:
        print(f"Error: {e}")
        return 1

    finally:
        if client is not None:
            print("Disconnecting from IoT Hub...")
            try:
                client.shutdown()
                print("Disconnected successfully.")
            except Exception as e:
                print(f"Error during disconnect: {e}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
