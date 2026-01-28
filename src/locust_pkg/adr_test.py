#!/usr/bin/env python3
"""Create Azure Device Registry namespace and devices via ARM API.

This script creates a resource group, namespace, and namespaced device for testing
Azure Device Registry functionality.
"""

import argparse
import secrets
import sys
import time
from datetime import datetime, timezone
from typing import Any

import requests
from azure.identity import AzureCliCredential

# Constants
API_VERSION_DEVICE_REGISTRY = "2025-11-01-preview"
API_VERSION_RESOURCE_GROUPS = "2021-04-01"
ARM_SCOPE = "https://management.azure.com/.default"
ARM_BASE_URL = "https://management.azure.com"
POLL_INTERVAL_SECONDS = 2
MAX_POLL_ATTEMPTS = 60


def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Create Azure Device Registry namespace and devices",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Example usage:
  python adr_test.py \\
    --subscription-id <sub-id> \\
    --resource-group mytestrg \\
    --rg-location eastus \\
    --namespace mynamespace \\
    --ns-location centraluseuap
        """,
    )
    parser.add_argument(
        "--subscription-id",
        required=True,
        help="Azure subscription ID",
    )
    parser.add_argument(
        "--resource-group",
        required=True,
        help="Resource group name",
    )
    parser.add_argument(
        "--rg-location",
        required=True,
        help="Resource group location (e.g., eastus)",
    )
    parser.add_argument(
        "--namespace",
        required=True,
        help="Device Registry namespace name",
    )
    parser.add_argument(
        "--ns-location",
        required=True,
        help="Namespace location (e.g., centraluseuap)",
    )
    return parser.parse_args()


def get_access_token() -> str:
    """Get access token using Azure CLI credential."""
    credential = AzureCliCredential()
    token = credential.get_token(ARM_SCOPE)
    return str(token.token)


def get_headers(token: str) -> dict[str, str]:
    """Build standard headers for ARM API requests."""
    return {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }


def poll_async_operation(url: str, token: str) -> dict[str, Any]:
    """Poll an Azure async operation until completion."""
    headers = get_headers(token)

    for attempt in range(MAX_POLL_ATTEMPTS):
        response = requests.get(url, headers=headers, timeout=30)
        response.raise_for_status()
        result: dict[str, Any] = response.json()

        status = result.get("status", "").lower()
        if status == "succeeded":
            return result
        elif status in ("failed", "canceled"):
            error = result.get("error", {})
            raise RuntimeError(f"Async operation {status}: {error.get('message', 'Unknown error')}")

        time.sleep(POLL_INTERVAL_SECONDS)

    raise TimeoutError(f"Async operation did not complete after {MAX_POLL_ATTEMPTS * POLL_INTERVAL_SECONDS} seconds")


def create_resource_group(subscription_id: str, resource_group: str, location: str, token: str) -> str:
    """Create a resource group if it doesn't exist. Returns status string."""
    url = f"{ARM_BASE_URL}/subscriptions/{subscription_id}/resourcegroups/{resource_group}"
    url += f"?api-version={API_VERSION_RESOURCE_GROUPS}"

    headers = get_headers(token)
    payload = {"location": location}

    response = requests.put(url, headers=headers, json=payload, timeout=30)
    response.raise_for_status()

    if response.status_code == 201:
        return "created"
    return "exists"


def create_namespace(subscription_id: str, resource_group: str, namespace: str, location: str, token: str) -> str:
    """Create a namespace if it doesn't exist. Returns status string."""
    url = (
        f"{ARM_BASE_URL}/subscriptions/{subscription_id}/resourceGroups/{resource_group}"
        f"/providers/Microsoft.DeviceRegistry/namespaces/{namespace}"
        f"?api-version={API_VERSION_DEVICE_REGISTRY}"
    )

    headers = get_headers(token)
    payload = {
        "location": location,
        "properties": {},
    }

    response = requests.put(url, headers=headers, json=payload, timeout=30)
    response.raise_for_status()

    # Handle long-running operation
    if response.status_code in (201, 202):
        async_url = response.headers.get("Azure-AsyncOperation") or response.headers.get("Location")
        if async_url:
            print("  Waiting for namespace creation to complete...")
            poll_async_operation(async_url, token)
        return "created"

    return "exists"


def raise_for_status_with_body(response: requests.Response) -> None:
    """Raise HTTPError with response body included in the message."""
    if response.status_code >= 400:
        try:
            error_body = response.json()
        except Exception:
            error_body = response.text
        raise requests.HTTPError(
            f"{response.status_code} {response.reason} for url: {response.url}\nResponse: {error_body}",
            response=response,
        )


def create_device(
    subscription_id: str,
    resource_group: str,
    namespace: str,
    device_name: str,
    location: str,
    external_device_id: str,
    token: str,
) -> dict[str, Any]:
    """Create a namespaced device. Returns the created device."""
    url = (
        f"{ARM_BASE_URL}/subscriptions/{subscription_id}/resourceGroups/{resource_group}"
        f"/providers/Microsoft.DeviceRegistry/namespaces/{namespace}/devices/{device_name}"
        f"?api-version={API_VERSION_DEVICE_REGISTRY}"
    )

    headers = get_headers(token)
    created_at = int(datetime.now(timezone.utc).timestamp())
    payload = {
        "location": location,
        "properties": {
            "enabled": True,
            "externalDeviceId": external_device_id,
            "operatingSystem": "Linux",
            "attributes": {
                "updateCount": 0,
                "createdAt": created_at,
            },
        },
    }

    response = requests.put(url, headers=headers, json=payload, timeout=30)
    raise_for_status_with_body(response)

    # Handle long-running operation
    if response.status_code in (201, 202):
        async_url = response.headers.get("Azure-AsyncOperation") or response.headers.get("Location")
        if async_url:
            print("  Waiting for device creation to complete...")
            poll_async_operation(async_url, token)

    result: dict[str, Any] = response.json()
    return result


def update_device(
    subscription_id: str,
    resource_group: str,
    namespace: str,
    device_name: str,
    token: str,
) -> tuple[dict[str, Any], str]:
    """Update a namespaced device with new OS version. Returns the updated device."""
    url = (
        f"{ARM_BASE_URL}/subscriptions/{subscription_id}/resourceGroups/{resource_group}"
        f"/providers/Microsoft.DeviceRegistry/namespaces/{namespace}/devices/{device_name}"
        f"?api-version={API_VERSION_DEVICE_REGISTRY}"
    )

    headers = get_headers(token)
    # Generate random version like "5.15.146"
    os_version = f"{secrets.randbelow(10)}.{secrets.randbelow(100)}.{secrets.randbelow(1000)}"
    payload = {
        "properties": {
            "operatingSystemVersion": os_version,
        },
    }

    response = requests.patch(url, headers=headers, json=payload, timeout=30)
    raise_for_status_with_body(response)

    # Handle long-running operation
    if response.status_code in (201, 202):
        async_url = response.headers.get("Azure-AsyncOperation") or response.headers.get("Location")
        if async_url:
            print("  Waiting for device update to complete...")
            poll_async_operation(async_url, token)

    result: dict[str, Any] = response.json()
    return result, os_version


def main() -> int:
    """Main entry point."""
    args = parse_args()

    print("=" * 70)
    print("Azure Device Registry - Namespace Device Creator")
    print("=" * 70)

    # Step 1: Authenticate
    print("\nAuthenticating with Azure CLI...")
    try:
        token = get_access_token()
        print("Authentication successful")
    except Exception as e:
        print(f"Error: Failed to authenticate with Azure CLI: {e}")
        return 1

    # Step 2: Create resource group
    print(f"\nCreating resource group '{args.resource_group}' in '{args.rg_location}'...")
    try:
        rg_status = create_resource_group(args.subscription_id, args.resource_group, args.rg_location, token)
        print(f"Resource group: {rg_status}")
    except requests.HTTPError as e:
        print(f"Error: Failed to create resource group: {e}")
        return 1

    # Step 3: Create namespace
    print(f"\nCreating namespace '{args.namespace}' in '{args.ns_location}'...")
    try:
        ns_status = create_namespace(args.subscription_id, args.resource_group, args.namespace, args.ns_location, token)
        print(f"Namespace: {ns_status}")
    except requests.HTTPError as e:
        print(f"Error: Failed to create namespace: {e}")
        return 1

    # Step 4: Create device
    suffix = secrets.token_hex(4)  # 8 hex characters
    device_name = f"device-{suffix}"
    external_device_id = f"ext-{suffix}"

    print(f"\nCreating device '{device_name}'...")
    try:
        device = create_device(
            subscription_id=args.subscription_id,
            resource_group=args.resource_group,
            namespace=args.namespace,
            device_name=device_name,
            location=args.ns_location,
            external_device_id=external_device_id,
            token=token,
        )
        print(f"Device created: {device_name}")
        print(f"  External ID: {external_device_id}")
        print(f"  Enabled: {device.get('properties', {}).get('enabled', 'N/A')}")
    except requests.HTTPError as e:
        print(f"Error: Failed to create device: {e}")
        return 1

    # Step 5: Update device with OS version
    print(f"\nUpdating device '{device_name}' with OS version...")
    try:
        updated_device, os_version = update_device(
            subscription_id=args.subscription_id,
            resource_group=args.resource_group,
            namespace=args.namespace,
            device_name=device_name,
            token=token,
        )
        print("Device updated successfully")
        print(f"  OS version: {os_version}")
    except requests.HTTPError as e:
        print(f"Error: Failed to update device: {e}")
        return 1

    print("\n" + "=" * 70)
    print("Summary")
    print("=" * 70)
    print(f"Resource Group: {args.resource_group} ({rg_status})")
    print(f"Namespace: {args.namespace} ({ns_status})")
    print(f"Device: {device_name} (created and updated)")
    print("=" * 70)

    return 0


if __name__ == "__main__":
    sys.exit(main())
