#!/usr/bin/env python3
"""Simple IoT device test script using certificate authentication.

This script provisions a device with Azure DPS, saves the issued certificate
to local disk, connects to IoT Hub using Paho MQTT, requests a new certificate
via the credential management API, and sends telemetry messages in a loop.
"""

import argparse
import base64
import hashlib
import hmac
import json
import os
import random
import signal
import ssl
import sys
import time
import warnings
from typing import Any

import paho.mqtt.client as mqtt
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

# Constants
MESSAGE_INTERVAL = 5  # seconds
MESSAGE_SIZE = 256  # bytes
DEFAULT_PROVISIONING_HOST = "global.azure-devices-provisioning.net"
DEFAULT_DEVICE_NAME = "test-device"
MQTT_PORT = 8883
API_VERSION = "2025-08-01-preview"
CREDENTIAL_RESPONSE_TIMEOUT = 60 * 60 * 6  # seconds

# Global flags for graceful shutdown
_running = True
_shutdown_requested = False


def signal_handler(signum: int, frame: object) -> None:
    """Handle Ctrl+C for graceful shutdown.

    First Ctrl+C: Request graceful shutdown.
    Second Ctrl+C: Force immediate exit.
    """
    global _running, _shutdown_requested
    if _shutdown_requested:
        print("\nForced shutdown, exiting immediately...")
        sys.exit(1)
    print("\nShutdown requested, finishing current operation... (Ctrl+C again to force quit)")
    _shutdown_requested = True
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


def create_csr(private_key: ec.EllipticCurvePrivateKey, device_name: str) -> tuple[str, x509.CertificateSigningRequest]:
    """Create a CSR using an existing private key.

    Args:
        private_key: The EC private key to use for signing the CSR.
        device_name: The device name to use as the Common Name.

    Returns:
        Tuple of (Base64-encoded DER format CSR string, CSR object).
    """
    csr_builder = x509.CertificateSigningRequestBuilder()
    csr_builder = csr_builder.subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, device_name)]))
    csr = csr_builder.sign(private_key, hashes.SHA256())

    # Convert CSR to DER format and then base64 encode it
    csr_der = csr.public_bytes(serialization.Encoding.DER)
    return base64.b64encode(csr_der).decode("utf-8"), csr


def print_csr_details(csr: x509.CertificateSigningRequest) -> None:
    """Print CSR subject/common name.

    Args:
        csr: The CSR object to display.
    """
    # Extract Common Name from subject
    common_name = None
    for attr in csr.subject:
        if attr.oid == NameOID.COMMON_NAME:
            common_name = attr.value
            break

    print(f"  Subject CN: {common_name or 'N/A'}")


def print_certificate_chain(cert_pem_list: list[str]) -> None:
    """Print certificate chain with subject CN and validity.

    Args:
        cert_pem_list: List of base64-encoded certificates.
    """
    from cryptography.utils import CryptographyDeprecationWarning

    print(f"\n=== Certificate Chain ({len(cert_pem_list)} certificate(s)) ===")

    for i, cert_b64 in enumerate(cert_pem_list):
        try:
            # Decode base64 and parse certificate
            cert_der = base64.b64decode(cert_b64)
            # Suppress warning for certificates with NULL parameter in signature algorithm
            # (common with certain Java-generated certificates, see pyca/cryptography#8996)
            with warnings.catch_warnings():
                warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)
                cert = x509.load_der_x509_certificate(cert_der)

            # Extract Common Name from subject
            common_name = None
            for attr in cert.subject:
                if attr.oid == NameOID.COMMON_NAME:
                    common_name = attr.value
                    break

            print(f"\n  Certificate [{i + 1}]:")
            print(f"    Subject CN: {common_name or 'N/A'}")
            print(f"    Not Before: {cert.not_valid_before_utc.strftime('%Y-%m-%d %H:%M:%S UTC')}")
            print(f"    Not After:  {cert.not_valid_after_utc.strftime('%Y-%m-%d %H:%M:%S UTC')}")

        except Exception as e:
            print(f"\n  Certificate [{i + 1}]: Failed to parse - {e}")

    print()


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
) -> tuple[str, str, str, str, ec.EllipticCurvePrivateKey]:
    """Provision device with DPS and save certificates to disk.

    Returns:
        Tuple of (assigned_hub, device_id, cert_path, key_path, private_key)
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
    csr_data, _ = create_csr(private_key, device_name)

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

    # Save metadata to JSON file
    metadata_path = os.path.join(output_dir, f"{device_name}.json")
    metadata = {
        "assigned_hub": assigned_hub,
        "device_id": device_id,
    }
    print(f"Saving metadata to: {metadata_path}")
    with open(metadata_path, "w") as f:
        json.dump(metadata, f, indent=2)

    return assigned_hub, device_id, cert_path, key_path, private_key


def load_existing_credentials(
    output_dir: str,
    device_name: str,
) -> tuple[str, str, str, str, ec.EllipticCurvePrivateKey] | None:
    """Load existing credentials from disk if they exist.

    Args:
        output_dir: Directory containing credential files.
        device_name: Device name used for file naming.

    Returns:
        Tuple of (assigned_hub, device_id, cert_path, key_path, private_key) if all files exist,
        None otherwise.
    """
    cert_path = os.path.join(output_dir, f"{device_name}.cert.pem")
    key_path = os.path.join(output_dir, f"{device_name}.key.pem")
    metadata_path = os.path.join(output_dir, f"{device_name}.json")

    # Check if all required files exist
    if not os.path.exists(cert_path):
        return None
    if not os.path.exists(key_path):
        return None
    if not os.path.exists(metadata_path):
        return None

    print(f"Found existing credentials in {output_dir}")

    # Load metadata
    print(f"Loading metadata from: {metadata_path}")
    with open(metadata_path) as f:
        metadata = json.load(f)

    assigned_hub = metadata["assigned_hub"]
    device_id = metadata["device_id"]

    # Load private key
    print(f"Loading private key from: {key_path}")
    with open(key_path, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)

    if not isinstance(private_key, ec.EllipticCurvePrivateKey):
        raise RuntimeError("Private key is not an EC key")

    print(f"Device ID: {device_id}")
    print(f"Assigned hub: {assigned_hub}")

    return assigned_hub, device_id, cert_path, key_path, private_key


def connect_mqtt_with_cert(
    hostname: str,
    device_id: str,
    cert_file: str,
    key_file: str,
) -> mqtt.Client:
    """Connect to IoT Hub using Paho MQTT with X.509 certificate.

    Args:
        hostname: IoT Hub hostname.
        device_id: Device ID.
        cert_file: Path to the certificate PEM file.
        key_file: Path to the private key PEM file.

    Returns:
        Connected MQTT client.
    """
    print(f"Connecting to IoT Hub via MQTT: {hostname}...")

    # Print full paths and credentials for debugging
    print(f"  Certificate file: {os.path.abspath(cert_file)}")
    print(f"  Key file: {os.path.abspath(key_file)}")

    # Create MQTT client (paho-mqtt 1.x API)
    client = mqtt.Client(
        client_id=device_id,
        protocol=mqtt.MQTTv311,
    )

    # Set username for Azure IoT Hub
    username = f"{hostname}/{device_id}/?api-version={API_VERSION}"
    print(f"  Username: {username}")
    client.username_pw_set(username=username)

    # Configure TLS with system CA bundle and client certificate
    ssl_context = ssl.create_default_context()
    ssl_context.load_cert_chain(certfile=cert_file, keyfile=key_file)
    client.tls_set_context(ssl_context)

    # Connect
    client.connect(hostname, MQTT_PORT, keepalive=60)
    client.loop_start()

    # Wait for connection
    timeout = 10
    start = time.time()
    while not client.is_connected() and (time.time() - start) < timeout:
        time.sleep(0.1)

    if not client.is_connected():
        raise RuntimeError("Failed to connect to IoT Hub via MQTT")

    print("Connected to IoT Hub via MQTT successfully!")
    return client


def request_new_certificate(
    client: mqtt.Client,
    device_id: str,
    csr_data: str,
    output_dir: str,
    device_name: str,
) -> str:
    """Request a new certificate from IoT Hub via MQTT.

    Args:
        client: Connected MQTT client.
        device_id: Device ID.
        csr_data: Base64-encoded DER format CSR.
        output_dir: Directory to save the renewed certificate.
        device_name: Device name for the output file.

    Returns:
        Path to the saved renewed certificate file.
    """
    request_id = random.randint(1, 99999999)
    subscribe_topic = "$iothub/credentials/res/#"
    publish_topic = f"$iothub/credentials/POST/issueCertificate/?$rid={request_id}"

    # State for tracking response
    response_received = False
    response_cert: list[str] = []
    response_error: str = ""

    def on_message(
        client: mqtt.Client,
        userdata: Any,
        msg: mqtt.MQTTMessage,
    ) -> None:
        nonlocal response_received, response_cert, response_error

        print(f"\n{'=' * 70}")
        print("CREDENTIAL RESPONSE RECEIVED!")
        print(f"{'=' * 70}")

        # Extract status code from topic
        # Topic format: $iothub/credentials/res/202/?$rid=999888777&$version=1
        parts = msg.topic.split("/")
        status_code = ""
        if len(parts) >= 4:
            status_code = parts[3]
            print(f"Status Code: {status_code}")

        # Show topic and pretty print payload
        print(f"Topic: {msg.topic}")
        if msg.payload:
            try:
                payload_str = msg.payload.decode("utf-8")
                payload_data = json.loads(payload_str)
                print(f"Payload:\n{json.dumps(payload_data, indent=2)}")

                # Extract certificate from response
                if "certificates" in payload_data:
                    cert_data = payload_data["certificates"]
                    if isinstance(cert_data, list):
                        response_cert.extend(cert_data)
                    elif isinstance(cert_data, str):
                        response_cert.append(cert_data)

            except (json.JSONDecodeError, UnicodeDecodeError) as e:
                response_error = f"Failed to parse response: {e}"
                print(f"Error parsing response: {e}")
                print(f"Payload (raw): {msg.payload}")

        if status_code == "202" or status_code == "200":
            print(f"SUCCESS: Received certificate response (status {status_code})")
        else:
            response_error = f"Unexpected status code: {status_code}"
            print(f"WARNING: Unexpected status code {status_code}")

        print(f"{'=' * 70}\n")
        response_received = True

    # Set message callback
    client.on_message = on_message

    # Subscribe to response topic
    print(f"Subscribing to: {subscribe_topic}")
    result, mid = client.subscribe(subscribe_topic, qos=1)
    if result != mqtt.MQTT_ERR_SUCCESS:
        raise RuntimeError(f"Failed to subscribe to {subscribe_topic}")

    # Wait a moment for subscription to be established
    time.sleep(0.5)

    # Send a test message first to verify connectivity before CSR request
    test_topic = f"devices/{device_id}/messages/events/"
    test_payload = json.dumps({"type": "pre-csr-test", "device_id": device_id})
    print("Sending test message to verify connectivity...")
    test_result = client.publish(test_topic, payload=test_payload, qos=1)
    if test_result.rc != mqtt.MQTT_ERR_SUCCESS:
        raise RuntimeError(f"Failed to publish test message: {test_result.rc}")

    print(f"Test message sent (mid: {test_result.mid})")

    # Publish CSR request
    payload_dict = {"id": device_id, "csr": csr_data}
    payload = json.dumps(payload_dict)
    print(f"Topic: {publish_topic}")
    print(f"Payload:\n{json.dumps(payload_dict, indent=2)}")

    result = client.publish(publish_topic, payload=payload, qos=1)
    if result.rc != mqtt.MQTT_ERR_SUCCESS:
        raise RuntimeError(f"Failed to publish CSR request: {result.rc}")

    print(f"CSR request sent (mid: {result.mid})")

    # Wait for response with progress updates, sending keepalive messages every 5 seconds
    start_time = time.time()
    last_keepalive = start_time
    keepalive_topic = f"devices/{device_id}/messages/events/"
    keepalive_count = 0

    print(f"\nWaiting for credential response (timeout: {CREDENTIAL_RESPONSE_TIMEOUT}s)...")
    print("Sending keepalive messages every 5 seconds...")

    while _running and not response_cert and not response_error:
        elapsed = time.time() - start_time
        if elapsed >= CREDENTIAL_RESPONSE_TIMEOUT:
            raise RuntimeError(f"Timeout waiting for credential response after {CREDENTIAL_RESPONSE_TIMEOUT} seconds")

        # Send keepalive message every 5 seconds
        if time.time() - last_keepalive >= 5:
            keepalive_count += 1
            keepalive_payload = json.dumps({"type": "keepalive", "seq": keepalive_count})
            keepalive_result = client.publish(keepalive_topic, payload=keepalive_payload, qos=1)
            print(f"  Keepalive {keepalive_count} sent (mid: {keepalive_result.mid}, {int(elapsed)}s elapsed)")
            last_keepalive = time.time()

        time.sleep(0.1)

    if not _running:
        raise RuntimeError("Shutdown requested while waiting for credential response")

    if response_error:
        raise RuntimeError(f"Credential request failed: {response_error}")

    if not response_cert:
        raise RuntimeError("No certificate received in response")

    # Print friendly view of the certificate chain
    print_certificate_chain(response_cert)

    # Convert certificate to PEM format
    cert_pem = x509_certificate_list_to_pem(response_cert)

    # Save renewed certificate
    renewed_cert_path = os.path.join(output_dir, f"{device_name}_renewed.cert.pem")
    print(f"Saving renewed certificate to: {renewed_cert_path}")
    with open(renewed_cert_path, "w") as f:
        f.write(cert_pem)

    return renewed_cert_path


def send_messages_mqtt(client: mqtt.Client, device_id: str, message_count: int = 3) -> None:
    """Send telemetry messages using MQTT.

    Args:
        client: Connected MQTT client.
        device_id: Device ID.
        message_count: Number of messages to send (default: 3).
    """
    global _running

    # Telemetry topic for Azure IoT Hub
    telemetry_topic = f"devices/{device_id}/messages/events/"

    print(f"\nSending {message_count} messages...")

    sent_count = 0
    for i in range(message_count):
        if not _running:
            break

        try:
            message_data = create_msg(MESSAGE_SIZE)

            result = client.publish(telemetry_topic, payload=message_data, qos=1)
            sent_count += 1
            print(f"Message {sent_count}/{message_count} sent ({len(message_data)} bytes, mid: {result.mid})")

            # Brief pause between messages (except after the last one)
            if i < message_count - 1:
                time.sleep(1)

        except Exception as e:
            print(f"Error sending message: {e}")

    print(f"\nTotal messages sent: {sent_count}")


def main() -> int:
    """Main entry point."""
    args = parse_args()

    # Set up signal handler for graceful shutdown
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    client: mqtt.Client | None = None

    try:
        # Step 1: Load existing credentials or provision device with DPS
        print("=" * 70)
        print("STEP 1: Loading credentials")
        print("=" * 70)

        existing_credentials = load_existing_credentials(
            output_dir=args.output_dir,
            device_name=args.device_name,
        )

        if existing_credentials is not None:
            assigned_hub, device_id, cert_path, key_path, private_key = existing_credentials
            print("Using existing credentials, skipping DPS provisioning")
        else:
            print("No existing credentials found, provisioning with DPS...")
            assigned_hub, device_id, cert_path, key_path, private_key = provision_device(
                provisioning_host=args.provisioning_host,
                id_scope=args.id_scope,
                sas_key=args.sas_key,
                device_name=args.device_name,
                output_dir=args.output_dir,
            )

        # Step 2: Connect to IoT Hub with DPS-issued certificate using Paho MQTT
        print("\n" + "=" * 70)
        print("STEP 2: Connecting to IoT Hub with DPS certificate")
        print("=" * 70)
        client = connect_mqtt_with_cert(
            hostname=assigned_hub,
            device_id=device_id,
            cert_file=cert_path,
            key_file=key_path,
        )

        # Step 3: Create new CSR using the same private key
        print("\n" + "=" * 70)
        print("STEP 3: Creating new CSR for certificate renewal")
        print("=" * 70)
        csr_data, csr_obj = create_csr(private_key, args.device_name)
        print(f"CSR created (length: {len(csr_data)} chars)")
        print_csr_details(csr_obj)

        # Step 4: Request new certificate via MQTT
        print("\n" + "=" * 70)
        print("STEP 4: Requesting new certificate from IoT Hub")
        print("=" * 70)
        renewed_cert_path = request_new_certificate(
            client=client,
            device_id=device_id,
            csr_data=csr_data,
            output_dir=args.output_dir,
            device_name=args.device_name,
        )

        # Step 5: Disconnect and reconnect with renewed certificate
        print("\n" + "=" * 70)
        print("STEP 5: Reconnecting with renewed certificate")
        print("=" * 70)
        print("Disconnecting from IoT Hub...")
        client.loop_stop()
        client.disconnect()
        time.sleep(1)  # Brief pause before reconnecting

        client = connect_mqtt_with_cert(
            hostname=assigned_hub,
            device_id=device_id,
            cert_file=renewed_cert_path,
            key_file=key_path,  # Same private key
        )

        # Step 6: Send telemetry messages in a loop
        print("\n" + "=" * 70)
        print("STEP 6: Sending telemetry messages")
        print("=" * 70)
        send_messages_mqtt(client, device_id)

    except Exception as e:
        print(f"Error: {e}")
        return 1

    finally:
        if client is not None:
            print("Disconnecting from IoT Hub...")
            try:
                client.loop_stop()
                client.disconnect()
                print("Disconnected successfully.")
            except Exception as e:
                print(f"Error during disconnect: {e}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
