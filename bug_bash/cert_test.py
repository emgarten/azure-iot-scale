#!/usr/bin/env python3
"""Bug Bash IoT Device Test Script.

This script tests Azure IoT device certificate provisioning and renewal.
It supports configuration via YAML file, multiple test scenarios, and
verbose logging for debugging.

Usage:
    python cert_test.py --config config.yaml
    python cert_test.py --config config.yaml --scenario renew-only --verbose
"""

import argparse
import base64
import hashlib
import hmac
import json
import logging
import os
import random
import signal
import ssl
import sys
import time
import warnings
from typing import Any, cast

import paho.mqtt.client as mqtt
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

# =============================================================================
# CONFIGURATION DEFAULTS
# =============================================================================
# These can be overridden via config.json or command-line arguments

DEFAULT_PROVISIONING_HOST = "global.azure-devices-provisioning.net"
DEFAULT_DEVICE_NAME = "test-device"
DEFAULT_OUTPUT_DIR = "./certs"
DEFAULT_SCENARIO = "success"
DEFAULT_MESSAGE_COUNT = 3
DEFAULT_CREDENTIAL_TIMEOUT = 60 * 60 * 6  # 6 hours

# MQTT settings
MQTT_PORT = 8883
API_VERSION = "2025-08-01-preview"

# =============================================================================
# AVAILABLE TEST SCENARIOS
# =============================================================================
SCENARIOS = {
    "success": "Full happy path: provision → connect → renew → reconnect → telemetry",
    "provision-only": "Only provision device with DPS and save credentials",
    "renew-only": "Load existing credentials and renew certificate",
    "telemetry-only": "Load existing credentials and send telemetry messages",
}

# =============================================================================
# LOGGING SETUP
# =============================================================================
logger = logging.getLogger("cert_test")


def setup_logging(verbose: bool = False) -> None:
    """Configure logging based on verbosity level."""
    level = logging.DEBUG if verbose else logging.INFO
    format_str = "%(asctime)s [%(levelname)s] %(message)s" if verbose else "%(message)s"

    logging.basicConfig(
        level=level,
        format=format_str,
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # Reduce noise from third-party libraries unless verbose
    if not verbose:
        logging.getLogger("paho").setLevel(logging.WARNING)
        logging.getLogger("urllib3").setLevel(logging.WARNING)
        logging.getLogger("azure").setLevel(logging.WARNING)


# =============================================================================
# GLOBAL STATE
# =============================================================================
_running = True
_shutdown_requested = False


def signal_handler(signum: int, frame: object) -> None:
    """Handle Ctrl+C for graceful shutdown."""
    global _running, _shutdown_requested
    if _shutdown_requested:
        logger.warning("Forced shutdown, exiting immediately...")
        sys.exit(1)
    logger.info("Shutdown requested, finishing current operation... (Ctrl+C again to force quit)")
    _shutdown_requested = True
    _running = False


# =============================================================================
# CONFIGURATION LOADING
# =============================================================================


def load_config(config_path: str) -> dict[str, Any]:
    """Load configuration from JSON file.

    Args:
        config_path: Path to the JSON configuration file.

    Returns:
        Dictionary with configuration values.
    """
    logger.debug(f"Loading configuration from: {config_path}")

    with open(config_path) as f:
        config = json.load(f)

    if config is None:
        return {}

    return cast(dict[str, Any], config)


def merge_config(args: argparse.Namespace, config: dict[str, Any]) -> argparse.Namespace:
    """Merge JSON config with command-line arguments.

    Command-line arguments take precedence over config file values.

    Args:
        args: Parsed command-line arguments.
        config: Configuration from JSON file.

    Returns:
        Updated namespace with merged configuration.
    """
    # Extract from nested sections
    connection = config.get("connection", {})
    device = config.get("device", {})
    test = config.get("test", {})
    telemetry = config.get("telemetry", {})
    renewal = config.get("renewal", {})

    # Build flat config from sections
    config_values = {
        "provisioning_host": connection.get("provisioning_host"),
        "id_scope": connection.get("id_scope"),
        "sas_key": connection.get("sas_key"),
        "device_name": device.get("device_name"),
        "output_dir": device.get("output_dir"),
        "scenario": test.get("scenario"),
        "verbose": test.get("verbose"),
        "message_count": telemetry.get("message_count"),
    }

    for arg_name, config_value in config_values.items():
        arg_value = getattr(args, arg_name, None)

        # Use config value if arg was not explicitly set (is None or default)
        if config_value is not None:
            # For boolean flags, check if it was explicitly set
            if arg_name == "verbose" and not args.verbose:
                setattr(args, arg_name, config_value)
            elif arg_value is None:
                setattr(args, arg_name, config_value)

    # Handle renewal payload template (dict, not a simple value)
    args.renewal_payload = renewal.get("payload")

    return args


# =============================================================================
# CERTIFICATE UTILITIES
# =============================================================================


def x509_certificate_list_to_pem(cert_list: list[str]) -> str:
    """Convert a list of base64-encoded certificates to PEM format."""
    begin_cert_header = "-----BEGIN CERTIFICATE-----\r\n"
    end_cert_footer = "\r\n-----END CERTIFICATE-----"
    separator = end_cert_footer + "\r\n" + begin_cert_header
    return begin_cert_header + separator.join(cert_list) + end_cert_footer


def create_msg() -> bytes:
    """Create a telemetry message with the current UTC timestamp."""
    import orjson
    from datetime import datetime, timezone

    now = datetime.now(tz=timezone.utc).isoformat()
    return orjson.dumps({"timestamp": now, "message": "test telemetry"})


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

    csr_der = csr.public_bytes(serialization.Encoding.DER)
    return base64.b64encode(csr_der).decode("utf-8"), csr


def print_csr_details(csr: x509.CertificateSigningRequest) -> None:
    """Print CSR subject/common name."""
    common_name = None
    for attr in csr.subject:
        if attr.oid == NameOID.COMMON_NAME:
            common_name = attr.value
            break
    logger.info(f"  Subject CN: {common_name or 'N/A'}")


def print_certificate_chain(cert_pem_list: list[str]) -> None:
    """Print certificate chain with subject CN and validity."""
    from cryptography.utils import CryptographyDeprecationWarning

    logger.info(f"\n=== Certificate Chain ({len(cert_pem_list)} certificate(s)) ===")

    for i, cert_b64 in enumerate(cert_pem_list):
        try:
            cert_der = base64.b64decode(cert_b64)
            with warnings.catch_warnings():
                warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)
                cert = x509.load_der_x509_certificate(cert_der)

            common_name = None
            for attr in cert.subject:
                if attr.oid == NameOID.COMMON_NAME:
                    common_name = attr.value
                    break

            logger.info(f"\n  Certificate [{i + 1}]:")
            logger.info(f"    Subject CN: {common_name or 'N/A'}")
            logger.info(f"    Not Before: {cert.not_valid_before_utc.strftime('%Y-%m-%d %H:%M:%S UTC')}")
            logger.info(f"    Not After:  {cert.not_valid_after_utc.strftime('%Y-%m-%d %H:%M:%S UTC')}")

        except Exception as e:
            logger.error(f"\n  Certificate [{i + 1}]: Failed to parse - {e}")

    logger.info("")


# =============================================================================
# ARGUMENT PARSING
# =============================================================================


def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Bug Bash IoT Device Test Script",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Available Scenarios:
  success        Full happy path (default)
  provision-only Only provision device with DPS
  renew-only     Load existing credentials and renew certificate
  telemetry-only Load existing credentials and send telemetry

Examples:
  python cert_test.py --config config.yaml
  python cert_test.py --config config.yaml --scenario renew-only
  python cert_test.py --config config.yaml --verbose
  python cert_test.py --id-scope 0ne00XXX --sas-key <key> --output-dir ./certs
        """,
    )

    # Config file (recommended way to run)
    parser.add_argument(
        "--config",
        help="Path to YAML configuration file (recommended)",
    )

    # Connection settings (can be overridden via CLI)
    parser.add_argument(
        "--provisioning-host",
        dest="provisioning_host",
        help=f"DPS provisioning host (default: {DEFAULT_PROVISIONING_HOST})",
    )
    parser.add_argument(
        "--id-scope",
        dest="id_scope",
        help="DPS ID scope (required if no config file)",
    )
    parser.add_argument(
        "--sas-key",
        dest="sas_key",
        help="DPS SAS key (required if no config file)",
    )
    parser.add_argument(
        "--device-name",
        dest="device_name",
        help=f"Device name/registration ID (default: {DEFAULT_DEVICE_NAME})",
    )
    parser.add_argument(
        "--output-dir",
        dest="output_dir",
        help=f"Directory to save certificates (default: {DEFAULT_OUTPUT_DIR})",
    )

    # Scenario selection
    parser.add_argument(
        "--scenario",
        choices=list(SCENARIOS.keys()),
        help="Test scenario to run (default: success)",
    )

    # Message settings
    parser.add_argument(
        "--message-count",
        dest="message_count",
        type=int,
        help=f"Number of telemetry messages to send (default: {DEFAULT_MESSAGE_COUNT})",
    )

    # Debugging
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable verbose debug logging",
    )

    # Hidden option for credential timeout
    parser.add_argument(
        "--credential-response-timeout",
        dest="credential_response_timeout",
        type=int,
        help=argparse.SUPPRESS,
    )

    return parser.parse_args()


def validate_args(args: argparse.Namespace) -> None:
    """Validate that required arguments are present."""
    errors = []

    if not args.id_scope:
        errors.append("--id-scope is required (or set id_scope in config.yaml)")
    if not args.sas_key:
        errors.append("--sas-key is required (or set sas_key in config.yaml)")

    if errors:
        logger.error("Configuration errors:")
        for error in errors:
            logger.error(f"  - {error}")
        sys.exit(1)


def apply_defaults(args: argparse.Namespace) -> None:
    """Apply default values for unset arguments."""
    if args.provisioning_host is None:
        args.provisioning_host = DEFAULT_PROVISIONING_HOST
    if args.device_name is None:
        args.device_name = DEFAULT_DEVICE_NAME
    if args.output_dir is None:
        args.output_dir = DEFAULT_OUTPUT_DIR
    if args.scenario is None:
        args.scenario = DEFAULT_SCENARIO
    if args.message_count is None:
        args.message_count = DEFAULT_MESSAGE_COUNT
    if args.credential_response_timeout is None:
        args.credential_response_timeout = DEFAULT_CREDENTIAL_TIMEOUT
    if not hasattr(args, "renewal_payload"):
        args.renewal_payload = None


# =============================================================================
# DPS PROVISIONING
# =============================================================================


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

    logger.info(f"Provisioning device '{device_name}' with DPS...")
    logger.debug(f"  Provisioning host: {provisioning_host}")
    logger.debug(f"  ID scope: {id_scope}")

    # Derive device key from SAS key
    key_bytes = base64.b64decode(sas_key)
    derived_key = hmac.new(key_bytes, device_name.encode("utf-8"), hashlib.sha256).digest()
    device_key = base64.b64encode(derived_key).decode("utf-8")
    logger.debug(f"  Derived device key: {device_key[:20]}...")

    # Create provisioning client
    provisioning_client = ProvisioningDeviceClient.create_from_symmetric_key(
        provisioning_host=provisioning_host,
        registration_id=device_name,
        id_scope=id_scope,
        symmetric_key=device_key,
    )

    # Generate EC private key
    logger.info("Generating EC private key (SECP256R1)...")
    private_key = ec.generate_private_key(ec.SECP256R1())

    # Generate CSR
    logger.info("Creating certificate signing request...")
    csr_data, csr_obj = create_csr(private_key, device_name)
    logger.debug(f"  CSR length: {len(csr_data)} chars")
    print_csr_details(csr_obj)

    # Set the CSR on the client
    provisioning_client.client_certificate_signing_request = csr_data

    # Register with DPS
    logger.info("Registering with DPS...")
    registration_result = provisioning_client.register()

    if registration_result.registration_state is None:
        raise RuntimeError("Registration failed: no registration state returned")

    if registration_result.status != "assigned":
        raise RuntimeError(f"Registration failed with status: {registration_result.status}")

    assigned_hub = registration_result.registration_state.assigned_hub
    device_id = registration_result.registration_state.device_id

    logger.info(f"Device assigned to hub: {assigned_hub}")
    logger.info(f"Device ID: {device_id}")

    # Get issued certificate
    issued_cert_data = ""
    if registration_result.registration_state.issued_client_certificate:
        issued_cert_data = x509_certificate_list_to_pem(
            registration_result.registration_state.issued_client_certificate
        )
        logger.debug(
            f"  Certificate chain length: {len(registration_result.registration_state.issued_client_certificate)}"
        )

    if not issued_cert_data:
        raise RuntimeError("No certificate issued by DPS")

    # Serialize private key to PEM
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")

    # Create output directory
    os.makedirs(output_dir, exist_ok=True)

    # Save files
    cert_path = os.path.join(output_dir, f"{device_name}.cert.pem")
    key_path = os.path.join(output_dir, f"{device_name}.key.pem")
    metadata_path = os.path.join(output_dir, f"{device_name}.json")

    logger.info(f"Saving certificate to: {cert_path}")
    with open(cert_path, "w") as f:
        f.write(issued_cert_data)

    logger.info(f"Saving private key to: {key_path}")
    with open(key_path, "w") as f:
        f.write(private_key_pem)
    os.chmod(key_path, 0o600)

    logger.info(f"Saving metadata to: {metadata_path}")
    metadata = {"assigned_hub": assigned_hub, "device_id": device_id}
    with open(metadata_path, "w") as f:
        json.dump(metadata, f, indent=2)

    return assigned_hub, device_id, cert_path, key_path, private_key


def load_existing_credentials(
    output_dir: str,
    device_name: str,
) -> tuple[str, str, str, str, ec.EllipticCurvePrivateKey] | None:
    """Load existing credentials from disk if they exist."""
    cert_path = os.path.join(output_dir, f"{device_name}.cert.pem")
    key_path = os.path.join(output_dir, f"{device_name}.key.pem")
    metadata_path = os.path.join(output_dir, f"{device_name}.json")

    if not all(os.path.exists(p) for p in [cert_path, key_path, metadata_path]):
        return None

    logger.info(f"Found existing credentials in {output_dir}")

    logger.debug(f"Loading metadata from: {metadata_path}")
    with open(metadata_path) as f:
        metadata = json.load(f)

    assigned_hub = metadata["assigned_hub"]
    device_id = metadata["device_id"]

    logger.debug(f"Loading private key from: {key_path}")
    with open(key_path, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)

    if not isinstance(private_key, ec.EllipticCurvePrivateKey):
        raise RuntimeError("Private key is not an EC key")

    logger.info(f"Device ID: {device_id}")
    logger.info(f"Assigned hub: {assigned_hub}")

    return assigned_hub, device_id, cert_path, key_path, private_key


# =============================================================================
# MQTT CONNECTION
# =============================================================================


def connect_mqtt_with_cert(
    hostname: str,
    device_id: str,
    cert_file: str,
    key_file: str,
    timeout: int = 10,
) -> mqtt.Client:
    """Connect to IoT Hub using Paho MQTT with X.509 certificate.

    Args:
        hostname: IoT Hub hostname.
        device_id: Device ID.
        cert_file: Path to certificate PEM file.
        key_file: Path to private key PEM file.
        timeout: Connection timeout in seconds (default: 10).

    Returns:
        Connected MQTT client.
    """
    logger.info(f"Connecting to IoT Hub via MQTT: {hostname}...")
    logger.debug(f"  Certificate file: {os.path.abspath(cert_file)}")
    logger.debug(f"  Key file: {os.path.abspath(key_file)}")

    client = mqtt.Client(client_id=device_id, protocol=mqtt.MQTTv311)

    # Track connection state for better error handling
    connection_error: list[str] = []

    def on_connect(client: mqtt.Client, userdata: Any, flags: dict[str, Any], rc: int) -> None:
        if rc != 0:
            error_msg = f"Connection failed with result code: {rc}"
            connection_error.append(error_msg)
            logger.error(error_msg)
        else:
            logger.debug("MQTT CONNACK received, connection established")

    def on_disconnect(client: mqtt.Client, userdata: Any, rc: int) -> None:
        if rc != 0:
            logger.warning(f"Unexpected disconnection with result code: {rc}")
        else:
            logger.debug("MQTT disconnected cleanly")

    client.on_connect = on_connect
    client.on_disconnect = on_disconnect

    username = f"{hostname}/{device_id}/?api-version={API_VERSION}"
    logger.debug(f"  Username: {username}")
    client.username_pw_set(username=username)

    ssl_context = ssl.create_default_context()
    ssl_context.load_cert_chain(certfile=cert_file, keyfile=key_file)
    client.tls_set_context(ssl_context)

    client.connect(hostname, MQTT_PORT, keepalive=60)
    client.loop_start()

    start = time.time()
    while not client.is_connected() and (time.time() - start) < timeout:
        if connection_error:
            raise RuntimeError(connection_error[0])
        time.sleep(0.1)

    if not client.is_connected():
        if connection_error:
            raise RuntimeError(connection_error[0])
        raise RuntimeError(f"Failed to connect to IoT Hub via MQTT (timeout after {timeout}s)")

    logger.info("Connected to IoT Hub via MQTT successfully!")
    return client


# =============================================================================
# CERTIFICATE RENEWAL
# =============================================================================


def request_new_certificate(
    client: mqtt.Client,
    device_id: str,
    csr_data: str,
    output_dir: str,
    device_name: str,
    credential_response_timeout: int,
    send_test_message: bool = True,
    payload_template: dict[str, Any] | None = None,
) -> str:
    """Request a new certificate from IoT Hub via MQTT.

    Args:
        client: Connected MQTT client.
        device_id: Device ID.
        csr_data: Base64-encoded CSR.
        output_dir: Directory to save renewed certificate.
        device_name: Device name for output file.
        credential_response_timeout: Timeout in seconds.
        send_test_message: Send test message before CSR (default: True).
        payload_template: Custom payload template. Use {id} and {csr} as placeholders.
                         Default: {"id": device_id, "csr": csr_data}

    Returns:
        Path to renewed certificate file.
    """
    request_id = random.randint(1, 99999999)
    subscribe_topic = "$iothub/credentials/res/#"
    publish_topic = f"$iothub/credentials/POST/issueCertificate/?$rid={request_id}"

    # State for tracking response
    response_cert: list[str] = []
    response_error: list[str] = []  # Use list to allow modification in nested function
    subscription_confirmed = [False]  # Track SUBACK receipt

    def on_subscribe(client: mqtt.Client, userdata: Any, mid: int, granted_qos: tuple[int, ...]) -> None:
        """Callback when subscription is acknowledged by broker."""
        logger.debug(f"Subscription confirmed (mid: {mid}, qos: {granted_qos})")
        subscription_confirmed[0] = True

    def on_message(client: mqtt.Client, userdata: Any, msg: mqtt.MQTTMessage) -> None:
        """Handle credential response messages from IoT Hub."""
        logger.info(f"\n{'=' * 70}")
        logger.info("CREDENTIAL RESPONSE RECEIVED!")
        logger.info(f"{'=' * 70}")

        # Extract status code from topic
        # Topic format: $iothub/credentials/res/202/?$rid=999888777&$version=1
        parts = msg.topic.split("/")
        status_code = parts[3] if len(parts) >= 4 else ""
        logger.info(f"Status Code: {status_code}")
        logger.debug(f"Topic: {msg.topic}")

        if msg.payload:
            try:
                payload_str = msg.payload.decode("utf-8")
                payload_data = json.loads(payload_str)
                logger.debug(f"Payload:\n{json.dumps(payload_data, indent=2)}")

                # Extract certificate from response (usually in 200 response)
                if "certificates" in payload_data:
                    cert_data = payload_data["certificates"]
                    if isinstance(cert_data, list):
                        response_cert.extend(cert_data)
                    elif isinstance(cert_data, str):
                        response_cert.append(cert_data)

            except (json.JSONDecodeError, UnicodeDecodeError) as e:
                response_error.append(f"Failed to parse response: {e}")
                logger.error(f"Error parsing response: {e}")
                logger.error(f"Raw payload: {msg.payload}")
                return

        # Handle status codes
        if status_code == "202":
            # Request accepted - certificate is being generated
            # Continue waiting for 200 response with actual certificate
            logger.info("Request accepted (202) - waiting for certificate...")
        elif status_code == "200":
            if response_cert:
                logger.info(f"SUCCESS: Certificate received (status {status_code})")
            else:
                response_error.append("Status 200 received but no certificates in payload")
                logger.error("Status 200 received but no certificates in payload")
        else:
            response_error.append(f"Unexpected status code: {status_code}")
            logger.warning(f"Unexpected status code {status_code}")

        logger.info(f"{'=' * 70}\n")

    # Set callbacks
    client.on_subscribe = on_subscribe
    client.on_message = on_message

    # Subscribe to response topic
    logger.info(f"Subscribing to: {subscribe_topic}")
    result, sub_mid = client.subscribe(subscribe_topic, qos=1)
    if result != mqtt.MQTT_ERR_SUCCESS:
        raise RuntimeError(f"Failed to subscribe to {subscribe_topic}")

    # Wait for subscription acknowledgment (SUBACK)
    sub_wait_start = time.time()
    while not subscription_confirmed[0] and (time.time() - sub_wait_start) < 5:
        time.sleep(0.1)

    if not subscription_confirmed[0]:
        logger.warning("Subscription acknowledgment not received, continuing anyway...")
    else:
        logger.debug("Subscription acknowledged by broker")

    # Send test message to verify connectivity (optional)
    if send_test_message:
        test_topic = f"devices/{device_id}/messages/events/"
        test_payload = json.dumps({"type": "pre-csr-test", "device_id": device_id})
        logger.debug("Sending test message to verify connectivity...")
        test_result = client.publish(test_topic, payload=test_payload, qos=1)
        # Wait for publish acknowledgment (PUBACK)
        test_result.wait_for_publish(timeout=5)
        if test_result.is_published():
            logger.debug(f"Test message acknowledged (mid: {test_result.mid})")
        else:
            logger.warning("Test message not acknowledged within timeout")
    else:
        logger.debug("Skipping test message (send_test_message=false)")

    # Build renewal payload
    if payload_template is not None:
        # Use custom payload template - substitute {id} and {csr} placeholders
        payload_dict: dict[str, Any] = {}
        for key, value in payload_template.items():
            if value == "{id}":
                payload_dict[key] = device_id
            elif value == "{csr}":
                payload_dict[key] = csr_data
            else:
                payload_dict[key] = value
        logger.info("Using custom renewal payload template")
    else:
        # Default payload
        payload_dict = {"id": device_id, "csr": csr_data}

    payload = json.dumps(payload_dict)
    logger.info(f"Publishing CSR request to: {publish_topic}")
    logger.info(f"Payload:\n{json.dumps(payload_dict, indent=2)}")

    csr_result = client.publish(publish_topic, payload=payload, qos=1)
    if csr_result.rc != mqtt.MQTT_ERR_SUCCESS:
        raise RuntimeError(f"Failed to publish CSR request: {csr_result.rc}")

    # Wait for publish acknowledgment
    csr_result.wait_for_publish(timeout=10)
    if csr_result.is_published():
        logger.info(f"CSR request acknowledged by broker (mid: {csr_result.mid})")
    else:
        logger.warning(f"CSR request not acknowledged within timeout (mid: {csr_result.mid})")

    # Wait for response
    start_time = time.time()
    last_keepalive = start_time
    keepalive_topic = f"devices/{device_id}/messages/events/"
    keepalive_count = 0

    logger.info(f"\nWaiting for credential response (timeout: {credential_response_timeout}s)...")

    while _running and not response_cert and not response_error:
        elapsed = time.time() - start_time
        if elapsed >= credential_response_timeout:
            raise RuntimeError(f"Timeout waiting for credential response after {credential_response_timeout} seconds")

        # Send keepalive message every 5 seconds
        if time.time() - last_keepalive >= 5:
            keepalive_count += 1
            keepalive_payload = json.dumps({"type": "keepalive", "seq": keepalive_count})
            client.publish(keepalive_topic, payload=keepalive_payload, qos=1)
            logger.debug(f"  Keepalive {keepalive_count} sent ({int(elapsed)}s elapsed)")
            last_keepalive = time.time()

        time.sleep(0.1)

    if not _running:
        raise RuntimeError("Shutdown requested while waiting for credential response")

    if response_error:
        raise RuntimeError(f"Credential request failed: {response_error[0]}")

    if not response_cert:
        raise RuntimeError("No certificate received in response")

    print_certificate_chain(response_cert)

    cert_pem = x509_certificate_list_to_pem(response_cert)
    renewed_cert_path = os.path.join(output_dir, f"{device_name}_renewed.cert.pem")
    logger.info(f"Saving renewed certificate to: {renewed_cert_path}")
    with open(renewed_cert_path, "w") as f:
        f.write(cert_pem)

    return renewed_cert_path


# =============================================================================
# TELEMETRY
# =============================================================================


def send_messages_mqtt(
    client: mqtt.Client,
    device_id: str,
    message_count: int,
    message_interval: float = 1.0,
) -> None:
    """Send telemetry messages using MQTT.

    Args:
        client: Connected MQTT client.
        device_id: Device ID.
        message_count: Number of messages to send.
        message_interval: Delay between messages in seconds (default: 1.0).
    """
    global _running

    telemetry_topic = f"devices/{device_id}/messages/events/"

    logger.info("\nTelemetry Configuration:")
    logger.info(f"  Topic: {telemetry_topic}")
    logger.info(f"  Message count: {message_count}")
    logger.info(f"  Interval: {message_interval}s")
    logger.info("  QoS: 1 (at least once delivery)")
    logger.info("")

    sent_count = 0
    acked_count = 0
    failed_count = 0
    start_time = time.time()

    for i in range(message_count):
        if not _running:
            logger.warning("Shutdown requested, stopping telemetry...")
            break

        try:
            # Create message
            msg_start = time.time()
            message_data = create_msg()

            logger.debug(f"Publishing message {i + 1}/{message_count}...")

            # Publish with QoS 1
            result = client.publish(telemetry_topic, payload=message_data, qos=1)

            if result.rc != mqtt.MQTT_ERR_SUCCESS:
                failed_count += 1
                logger.error(f"Message {i + 1}: Publish failed with rc={result.rc}")
                continue

            sent_count += 1

            # Wait for broker acknowledgment (PUBACK)
            try:
                result.wait_for_publish(timeout=10)
                if result.is_published():
                    ack_time = (time.time() - msg_start) * 1000
                    acked_count += 1
                    logger.info(
                        f"Message {sent_count}/{message_count}: "
                        f"acknowledged (mid={result.mid}, ack_time={ack_time:.1f}ms)"
                    )
                else:
                    logger.warning(
                        f"Message {sent_count}/{message_count}: "
                        f"sent but NOT acknowledged within timeout (mid={result.mid})"
                    )
            except Exception as e:
                logger.warning(f"Message {sent_count}/{message_count}: error waiting for ack: {e}")

            # Wait before next message
            if i < message_count - 1:
                logger.debug(f"Waiting {message_interval}s before next message...")
                time.sleep(message_interval)

        except Exception as e:
            failed_count += 1
            logger.error(f"Message {i + 1}: Error - {e}")

    # Summary
    elapsed = time.time() - start_time
    logger.info("")
    logger.info("=" * 40)
    logger.info("Telemetry Summary:")
    logger.info(f"  Messages sent: {sent_count}/{message_count}")
    logger.info(f"  Messages acknowledged: {acked_count}")
    logger.info(f"  Messages failed: {failed_count}")
    logger.info(f"  Total time: {elapsed:.2f}s")
    if sent_count > 0:
        logger.info(f"  Avg rate: {sent_count / elapsed:.2f} msg/s")
    logger.info("=" * 40)


# =============================================================================
# SCENARIO RUNNERS
# =============================================================================


def run_scenario_success(args: argparse.Namespace) -> int:
    """Run full happy path: provision → connect → renew → reconnect → telemetry."""
    client: mqtt.Client | None = None

    try:
        # Step 1: Load or provision
        logger.info("=" * 70)
        logger.info("STEP 1: Loading credentials")
        logger.info("=" * 70)

        existing = load_existing_credentials(args.output_dir, args.device_name)
        if existing:
            assigned_hub, device_id, cert_path, key_path, private_key = existing
            logger.info("Using existing credentials")
        else:
            logger.info("No existing credentials, provisioning with DPS...")
            assigned_hub, device_id, cert_path, key_path, private_key = provision_device(
                args.provisioning_host,
                args.id_scope,
                args.sas_key,
                args.device_name,
                args.output_dir,
            )

        # Step 2: Connect
        logger.info("\n" + "=" * 70)
        logger.info("STEP 2: Connecting to IoT Hub with DPS certificate")
        logger.info("=" * 70)
        client = connect_mqtt_with_cert(assigned_hub, device_id, cert_path, key_path)

        # Step 3: Create CSR
        logger.info("\n" + "=" * 70)
        logger.info("STEP 3: Creating new CSR for certificate renewal")
        logger.info("=" * 70)
        csr_data, csr_obj = create_csr(private_key, args.device_name)
        logger.info(f"CSR created (length: {len(csr_data)} chars)")
        print_csr_details(csr_obj)

        # Step 4: Request renewal
        logger.info("\n" + "=" * 70)
        logger.info("STEP 4: Requesting new certificate from IoT Hub")
        logger.info("=" * 70)
        renewed_cert_path = request_new_certificate(
            client,
            device_id,
            csr_data,
            args.output_dir,
            args.device_name,
            args.credential_response_timeout,
            payload_template=args.renewal_payload,
        )

        time.sleep(5)

        # Step 5: Reconnect
        logger.info("\n" + "=" * 70)
        logger.info("STEP 5: Reconnecting with renewed certificate")
        logger.info("=" * 70)
        logger.info("Disconnecting from IoT Hub...")
        client.loop_stop()
        client.disconnect()
        time.sleep(1)

        client = connect_mqtt_with_cert(assigned_hub, device_id, renewed_cert_path, key_path)

        # Step 6: Send telemetry
        logger.info("\n" + "=" * 70)
        logger.info("STEP 6: Sending telemetry messages")
        logger.info("=" * 70)
        send_messages_mqtt(client, device_id, args.message_count)

        return 0

    finally:
        if client:
            logger.info("Disconnecting from IoT Hub...")
            try:
                client.loop_stop()
                client.disconnect()
                logger.info("Disconnected successfully.")
            except Exception as e:
                logger.error(f"Error during disconnect: {e}")


def run_scenario_provision_only(args: argparse.Namespace) -> int:
    """Run provision-only scenario."""
    logger.info("=" * 70)
    logger.info("SCENARIO: Provision Only")
    logger.info("=" * 70)

    existing = load_existing_credentials(args.output_dir, args.device_name)
    if existing:
        logger.info("Credentials already exist. Delete them to re-provision:")
        logger.info(f"  rm -rf {args.output_dir}/{args.device_name}.*")
        return 0

    provision_device(
        args.provisioning_host,
        args.id_scope,
        args.sas_key,
        args.device_name,
        args.output_dir,
    )

    logger.info("\nProvisioning complete! Credentials saved to disk.")
    return 0


def run_scenario_renew_only(args: argparse.Namespace) -> int:
    """Run renew-only scenario."""
    client: mqtt.Client | None = None

    try:
        logger.info("=" * 70)
        logger.info("SCENARIO: Renew Only")
        logger.info("=" * 70)

        existing = load_existing_credentials(args.output_dir, args.device_name)
        if not existing:
            logger.error("No existing credentials found!")
            logger.error("Run 'provision-only' or 'success' scenario first.")
            return 1

        assigned_hub, device_id, cert_path, key_path, private_key = existing

        logger.info("\nConnecting to IoT Hub...")
        client = connect_mqtt_with_cert(assigned_hub, device_id, cert_path, key_path)

        logger.info("\nCreating CSR...")
        csr_data, csr_obj = create_csr(private_key, args.device_name)
        print_csr_details(csr_obj)

        logger.info("\nRequesting certificate renewal...")
        request_new_certificate(
            client,
            device_id,
            csr_data,
            args.output_dir,
            args.device_name,
            args.credential_response_timeout,
            payload_template=args.renewal_payload,
        )

        logger.info("\nCertificate renewal complete!")
        return 0

    finally:
        if client:
            client.loop_stop()
            client.disconnect()


def run_scenario_telemetry_only(args: argparse.Namespace) -> int:
    """Run telemetry-only scenario."""
    client: mqtt.Client | None = None

    try:
        logger.info("=" * 70)
        logger.info("SCENARIO: Telemetry Only")
        logger.info("=" * 70)

        existing = load_existing_credentials(args.output_dir, args.device_name)
        if not existing:
            logger.error("No existing credentials found!")
            logger.error("Run 'provision-only' or 'success' scenario first.")
            return 1

        assigned_hub, device_id, cert_path, key_path, _ = existing

        logger.info("\nConnecting to IoT Hub...")
        client = connect_mqtt_with_cert(assigned_hub, device_id, cert_path, key_path)

        logger.info("\nSending telemetry...")
        send_messages_mqtt(client, device_id, args.message_count)

        logger.info("\nTelemetry complete!")
        return 0

    finally:
        if client:
            client.loop_stop()
            client.disconnect()


# =============================================================================
# MAIN
# =============================================================================


def main() -> int:
    """Main entry point."""
    args = parse_args()

    # Load config file if provided
    if args.config:
        config = load_config(args.config)
        args = merge_config(args, config)

    # Apply defaults and validate
    apply_defaults(args)

    # Set up logging (need to do this before validation messages)
    setup_logging(args.verbose)

    validate_args(args)

    # Show configuration
    logger.info("=" * 70)
    logger.info("Bug Bash IoT Certificate Test")
    logger.info("=" * 70)
    logger.info(f"Scenario: {args.scenario} - {SCENARIOS[args.scenario]}")
    logger.info(f"Device: {args.device_name}")
    logger.info(f"Output: {args.output_dir}")
    if args.verbose:
        logger.debug(f"Provisioning host: {args.provisioning_host}")
        logger.debug(f"ID scope: {args.id_scope}")
        logger.debug(f"Message count: {args.message_count}")
    logger.info("")

    # Set up signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Run selected scenario
    scenario_runners = {
        "success": run_scenario_success,
        "provision-only": run_scenario_provision_only,
        "renew-only": run_scenario_renew_only,
        "telemetry-only": run_scenario_telemetry_only,
    }

    try:
        runner = scenario_runners[args.scenario]
        return runner(args)
    except Exception as e:
        logger.error(f"Error: {e}")
        if args.verbose:
            import traceback

            traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
