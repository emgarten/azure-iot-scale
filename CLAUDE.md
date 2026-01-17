# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Azure IoT scale testing tool using Locust. Tests certificate-based device provisioning and renewal against Azure IoT Hub and Device Provisioning Service (DPS).

## Common Commands

```bash
make install     # Set up virtual environment with uv
make test        # Run pytest tests
make check       # Run linting (ruff, black) and type checking (mypy) - auto-fixes issues
make check-no-fix # Same checks without auto-fix (used in CI)
make build       # Create requirements.txt in /dist for deployment
make run         # Run locust load test (requires .env file)
```

Run a single test:
```bash
uv run pytest tests/test_utils.py::test_function_name -v
```

## Code Quality Requirements

All code changes MUST pass `make check` before committing. This runs:
- `ruff check --fix` - linting with auto-fix
- `black` - code formatting (line-length 120)
- `mypy` - strict type checking

## Architecture

### Locust Users (src/locust_pkg/)

- **CertUser** (`cert_user.py`): Main load test user. Manages multiple IoT devices per user instance, performs certificate renewal requests in round-robin fashion. Configurable via environment variables (DEVICES_PER_USER, CERT_REQUEST_INTERVAL, etc.).

- **BasicHttpUser** (`http_user.py`): Simple HTTP user for basic endpoint testing.

### Core Components

- **HubCertDevice** (`hub_cert_device.py`): Self-contained IoT device class handling:
  - DPS provisioning with symmetric key authentication
  - X.509 certificate generation and CSR signing
  - IoT Hub MQTT connection with Paho
  - Certificate renewal via credential management API
  - State persistence to Azure Blob Storage
  - Locust metrics emission for all operations

- **Storage** (`storage.py`): Azure Blob Storage operations for:
  - Device registration data persistence (private keys, certificates)
  - Distributed device ID range allocation using ETag-based optimistic concurrency
  - Run isolation via LOAD_TEST_RUN_ID or RUN_ID

### Key Patterns

- **Lazy initialization**: Devices are created at user init, but provisioning and connection happen on first task execution
- **Observer pattern**: MQTT responses handled via callbacks (_credential_on_message)
- **Graceful degradation**: Storage failures are logged but don't crash the test
- **Distributed ID allocation**: Workers atomically allocate non-overlapping device ID ranges from blob storage

### Environment Variables

Required for running:
- `PROVISIONING_HOST`, `PROVISIONING_IDSCOPE`, `PROVISIONING_SAS_KEY` - DPS config
- `STORAGE_CONN_STR` or `STORAGE_ACCOUNT_URL` - Blob storage for state persistence
- `LOAD_TEST_RUN_ID` or `RUN_ID` - Test run isolation

### Dependencies

Uses a patched `azure-iot-device` wheel from `wheels/` directory (loaded at runtime via zipfile extraction in cert_user.py).
