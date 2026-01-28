#!/usr/bin/env python3
"""Manage Azure Device Registry certificate policy validity days.

This script manages certificate issuance policy validity days via the Azure ARM REST API.
It increments the validityPeriodInDays by 1 on each run, rolling over from 90 to 30 days.
"""

import argparse
import sys
from typing import Any

import requests
from azure.identity import AzureCliCredential

# Constants
API_VERSION = "2025-11-01-preview"
MIN_VALIDITY_DAYS = 30
MAX_VALIDITY_DAYS = 90
DEFAULT_VALIDITY_DAYS = 30
ARM_SCOPE = "https://management.azure.com/.default"
ARM_BASE_URL = "https://management.azure.com"


def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Manage Azure Device Registry certificate policy validity days",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Example usage:
  python adr_test.py --subscription-id <sub-id> --resource-group <rg> --namespace <ns> --policy-name <policy>
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
        "--namespace",
        required=True,
        help="Device Registry namespace name",
    )
    parser.add_argument(
        "--policy-name",
        required=True,
        help="Certificate issuance policy name",
    )
    return parser.parse_args()


def get_policy_url(subscription_id: str, resource_group: str, namespace: str, policy_name: str) -> str:
    """Build the ARM API URL for the policy resource."""
    return (
        f"{ARM_BASE_URL}/subscriptions/{subscription_id}/resourceGroups/{resource_group}"
        f"/providers/Microsoft.DeviceRegistry/namespaces/{namespace}"
        f"/credentials/default/policies/{policy_name}?api-version={API_VERSION}"
    )


def get_access_token() -> str:
    """Get access token using Azure CLI credential."""
    credential = AzureCliCredential()
    token = credential.get_token(ARM_SCOPE)
    return str(token.token)


def get_policy(url: str, token: str) -> dict[str, Any] | None:
    """GET the policy. Returns None if 404."""
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }
    response = requests.get(url, headers=headers, timeout=30)

    if response.status_code == 404:
        return None

    response.raise_for_status()
    result: dict[str, Any] = response.json()
    return result


def patch_policy(url: str, token: str, validity_days: int) -> dict[str, Any] | None:
    """PATCH the policy with new validity days. Returns response body or None if no content."""
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }
    payload = {
        "properties": {
            "certificate": {
                "leafCertificateConfiguration": {
                    "validityPeriodInDays": validity_days,
                }
            }
        }
    }
    response = requests.patch(url, headers=headers, json=payload, timeout=30)
    response.raise_for_status()
    if response.status_code == 204 or not response.content:
        return None
    result: dict[str, Any] = response.json()
    return result


def create_policy(url: str, token: str, validity_days: int, location: str) -> dict[str, Any]:
    """PUT to create a new policy."""
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }
    payload = {
        "location": location,
        "properties": {
            "certificate": {
                "leafCertificateConfiguration": {
                    "validityPeriodInDays": validity_days,
                }
            }
        },
    }
    response = requests.put(url, headers=headers, json=payload, timeout=30)
    response.raise_for_status()
    result: dict[str, Any] = response.json()
    return result


def main() -> int:
    """Main entry point."""
    args = parse_args()

    print("=" * 70)
    print("Azure Device Registry Policy Validity Manager")
    print("=" * 70)

    # Step 1: Get Azure CLI access token
    print("\nAuthenticating with Azure CLI...")
    try:
        token = get_access_token()
        print("Authentication successful")
    except Exception as e:
        print(f"Error: Failed to authenticate with Azure CLI: {e}")
        return 1

    # Step 2: Build ARM API URL
    url = get_policy_url(
        subscription_id=args.subscription_id,
        resource_group=args.resource_group,
        namespace=args.namespace,
        policy_name=args.policy_name,
    )
    print(f"\nTarget policy: {args.policy_name}")
    print(f"Namespace: {args.namespace}")
    print(f"Resource group: {args.resource_group}")

    # Step 3: GET current policy
    print("\nFetching current policy...")
    try:
        policy = get_policy(url, token)
    except requests.HTTPError as e:
        print(f"Error: Failed to get policy: {e}")
        return 1

    # Step 4: Handle policy not found - create with default
    if policy is None:
        print(f"Policy not found, creating with default validity: {DEFAULT_VALIDITY_DAYS} days")
        try:
            # Use a default location - this should ideally match the namespace location
            # For now, we'll use centraluseuap as mentioned in the plan
            created_policy = create_policy(url, token, DEFAULT_VALIDITY_DAYS, "centraluseuap")
            new_validity = (
                created_policy.get("properties", {})
                .get("certificate", {})
                .get("leafCertificateConfiguration", {})
                .get("validityPeriodInDays", DEFAULT_VALIDITY_DAYS)
            )
            print("\nPolicy created successfully!")
            print(f"Validity period: {new_validity} days")
            return 0
        except requests.HTTPError as e:
            print(f"Error: Failed to create policy: {e}")
            return 1

    # Step 5: Extract current validity days
    current_validity = (
        policy.get("properties", {})
        .get("certificate", {})
        .get("leafCertificateConfiguration", {})
        .get("validityPeriodInDays")
    )

    if current_validity is None:
        print("Warning: Could not find validityPeriodInDays in policy, using default")
        current_validity = DEFAULT_VALIDITY_DAYS

    print(f"Current validity: {current_validity} days")

    # Step 6: Calculate new validity (increment by 1, rollover at 90)
    if current_validity >= MAX_VALIDITY_DAYS:
        new_validity = MIN_VALIDITY_DAYS
        print(f"Reached maximum ({MAX_VALIDITY_DAYS}), rolling over to {MIN_VALIDITY_DAYS}")
    else:
        new_validity = current_validity + 1

    # Step 7: PATCH policy with new value
    print(f"Updating validity: {current_validity} -> {new_validity} days")
    try:
        updated_policy = patch_policy(url, token, new_validity)
        if updated_policy is not None:
            final_validity = (
                updated_policy.get("properties", {})
                .get("certificate", {})
                .get("leafCertificateConfiguration", {})
                .get("validityPeriodInDays", new_validity)
            )
        else:
            final_validity = new_validity
        print("\nPolicy updated successfully!")
        print(f"New validity period: {final_validity} days")
    except requests.HTTPError as e:
        print(f"Error: Failed to update policy: {e}")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
