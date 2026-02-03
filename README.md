# Azure IoT Scale Testing

Locust-based load testing framework for Azure IoT Hub and Device Provisioning Service (DPS). Simulates large-scale device fleets to test certificate-based provisioning, credential renewal, and telemetry workflows.

## Features

- **Certificate-based device provisioning** via Azure DPS with symmetric key enrollment
- **X.509 certificate generation** and CSR signing for device authentication
- **Credential renewal testing** through IoT Hub's credential management API
- **Distributed load testing** with Locust's master/worker architecture
- **State persistence** to Azure Blob Storage for device registration data
- **Distributed ID allocation** using ETag-based optimistic concurrency

## Prerequisites

- Python 3.12+
- [uv](https://docs.astral.sh/uv/) - Fast Python package manager
- Azure IoT Hub instance
- Azure Device Provisioning Service (DPS) instance
- Azure Storage Account (for state persistence)

## Quick Start

```bash
# Install dependencies
make install

# Configure environment
cp .env-example .env
# Edit .env with your Azure credentials

# Run a load test
make run-cert
```

## Development Setup

1. **Install uv** (if not already installed):
   ```bash
   curl -LsSf https://astral.sh/uv/install.sh | sh
   ```

2. **Set up the virtual environment**:
   ```bash
   make install
   ```

3. **Configure environment variables**:
   ```bash
   cp .env-example .env
   ```
   Edit `.env` with your Azure IoT Hub, DPS, and Storage Account credentials.

4. **Run tests**:
   ```bash
   make test
   ```

5. **Run linting and type checks**:
   ```bash
   make check
   ```

## Makefile Commands

| Command | Description |
|---------|-------------|
| `make install` | Set up virtual environment with uv |
| `make test` | Run pytest tests |
| `make check` | Run linting (ruff, black) and type checking (mypy) with auto-fix |
| `make check-no-fix` | Run checks without auto-fix (used in CI) |
| `make run-cert` | Run Locust load test with CertUser |
| `make run-adr` | Run Locust load test with AdrDevicePatchUser |
| `make run-hub-connect` | Run Locust load test with CertHubConnectUser |
| `make build` | Create requirements.txt in /dist for deployment |
| `make wheel` | Build wheel file using uv build |
| `make help` | Show all available commands |

## Project Structure

```
├── src/locust_pkg/      # Locust user classes and device simulation
│   ├── cert_user.py     # Main CertUser for certificate renewal testing
│   ├── hub_cert_device.py # IoT device class (DPS, MQTT, cert management)
│   └── storage.py       # Azure Blob Storage operations
├── deploy/              # Deployment scripts for Azure Load Testing
├── tests/               # Pytest test suite
└── wheels/              # Patched azure-iot-device wheel
```
