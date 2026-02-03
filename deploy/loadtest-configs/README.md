# Load Test Configurations

This directory contains Azure Load Testing configuration files for the IoT scale testing tool.

## Configuration Pattern

This directory uses an example config pattern (similar to `.env.example`):

- **`.yaml.example` files** - Template configurations checked into git
- **`.yaml` files** - Real configurations with your settings (gitignored)

Real config files are gitignored to prevent accidentally committing environment-specific settings.

## Setup

Copy the example files to create your local config files:

```bash
cp deploy/loadtest-configs/cert-user.yaml.example deploy/loadtest-configs/cert-user.yaml
cp deploy/loadtest-configs/adr-device-patch-user.yaml.example deploy/loadtest-configs/adr-device-patch-user.yaml
cp deploy/loadtest-configs/adr-user.yaml.example deploy/loadtest-configs/adr-user.yaml
cp deploy/loadtest-configs/cert-hub-connect-user.yaml.example deploy/loadtest-configs/cert-hub-connect-user.yaml
```

Then edit the `.yaml` files with your specific settings (engine instances, environment variables, etc.).

## Config Files

| File | Description |
|------|-------------|
| `cert-user.yaml` | CertUser - Certificate renewal load test against Azure IoT Hub and DPS |
| `adr-device-patch-user.yaml` | AdrDevicePatchUser - ADR device patch operations load test |
| `adr-user.yaml` | AdrUser - ADR GET/PATCH operations with distributed device allocation |
| `cert-hub-connect-user.yaml` | CertHubConnectUser - Certificate-based IoT Hub connection load test |

## Notes

- The `loadtest.sh` script will fail with a helpful error if config files are missing
- Do not commit real `.yaml` config files - they may contain environment-specific settings
- Only `.yaml.example` template files should be tracked in git
