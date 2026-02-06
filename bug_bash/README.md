# Bug Bash: IoT Certificate Test Script

This folder contains a self-contained test script for the Azure IoT certificate provisioning and renewal flow.

## Quick Start

### 1. Install Dependencies

```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Configure Your Test

Edit `config.json` and set your Azure credentials:

```json
{
  "connection": {
    "id_scope": "0ne00XXXXXX",
    "sas_key": "your-key-here"
  },
  "device": {
    "device_name": "bugbash-yourname"
  }
}
```

### 3. Run a Test

```bash
python cert_test.py --config config.json
```

## Test Steps

The `success` scenario runs all steps in order:

| Step | Name | Description |
|------|------|-------------|
| 1 | **Provision** | Register device with DPS using symmetric key, get X.509 certificate |
| 2 | **Connect** | Connect to IoT Hub via MQTT using the certificate |
| 3 | **Create CSR** | Generate a new Certificate Signing Request |
| 4 | **Renew** | Send CSR to IoT Hub, receive new certificate |
| 5 | **Reconnect** | Disconnect and reconnect using the renewed certificate |
| 6 | **Telemetry** | Send test messages to verify connectivity with new certificate |

## Test Scenarios

Change the `scenario` field in `config.json`:

| Scenario | Steps Run | Description |
|----------|-----------|-------------|
| `success` | 1-6 | Full happy path (default) |
| `provision-only` | 1 | Just provision device with DPS |
| `renew-only` | 2-4 | Renew certificate (requires existing credentials) |
| `telemetry-only` | 2, 6 | Send messages (requires existing credentials) |

## Custom Renewal Payload

You can customize the certificate renewal request payload in `config.json`:

```json
"renewal": {
  "payload": {
    "id": "{id}",
    "csr": "{csr}"
  }
}
```

**Placeholders:**
- `{id}` - Replace with the device ID
- `{csr}` - Replace with the base64-encoded CSR

**Examples:**

```json
// Test with missing CSR (should fail)
"payload": {
  "id": "{id}"
}

// Test with wrong field names (should fail)
"payload": {
  "deviceId": "{id}",
  "certificate": "{csr}"
}
```

Remove the `payload` field to use the default: `{"id": device_id, "csr": csr_data}`

## Verbose Logging

For debugging, set `"verbose": true` in config.json, or use:

```bash
python cert_test.py --config config.json --verbose
```

## Troubleshooting

**"No existing credentials found"**
Run `success` or `provision-only` first to create credentials.

**Connection timeout**
Check your `id_scope` and `sas_key` are correct.

**To start fresh**
Delete the `certs/` folder and run again.
