#!/bin/bash

set -e

# # Check for required parameters
# if [ $# -ne 2 ]; then
#     echo "Usage: $0 <subscription> <group> <id> <region> <hub_count> <hub_start_index>"
#     echo ""
#     echo "Parameters:"
#     echo "  subscription     - Azure subscription name or ID"
#     echo "  group            - Resource group name"
#     echo "  id               - Resource identifier (used for all resource names)"
#     echo "  region           - Azure region (e.g., westus2)"
#     echo "  hub_count        - Number of IoT hubs to create"
#     echo "  hub_start_index  - Starting index for hub naming (e.g., 1 for hub-1)"
#     exit 1
# fi

# Assign command-line parameters
SUBSCRIPTION="-"
RESOURCE_GROUP="ruath-gen2"
ID="ruath-can"
REGION="centraluseuap"
HUB_COUNT="$1"
HUB_START_INDEX="$2"

# Validate hub_count is a positive integer
if ! [[ "$HUB_COUNT" =~ ^[1-9][0-9]*$ ]]; then
    echo "Error: hub_count must be a positive integer"
    exit 1
fi

# Validate hub_start_index is a positive integer
if ! [[ "$HUB_START_INDEX" =~ ^[1-9][0-9]*$ ]]; then
    echo "Error: hub_start_index must be a positive integer"
    exit 1
fi

# Derived resource names
DPS_NAME="${ID}-dps"
NAMESPACE_NAME="${ID}-ns"
USER_IDENTITY="${ID}-identity"

HUB_END_INDEX=$((HUB_START_INDEX + HUB_COUNT - 1))

echo "=================================================="
echo "Azure IoT Hub Gen2 Multi-Hub Add Script"
echo "=================================================="
echo "Subscription:    $SUBSCRIPTION"
echo "Resource Group:  $RESOURCE_GROUP"
echo "ID Prefix:       $ID"
echo "Region:          $REGION"
echo "Hub Count:       $HUB_COUNT"
echo "=================================================="
echo "DPS Name:        $DPS_NAME"
echo "Namespace:       $NAMESPACE_NAME"
echo "User Identity:   $USER_IDENTITY"
echo "Hubs:            ruath-scale-$(printf '%03d' $HUB_START_INDEX) through ruath-scale-$(printf '%03d' $HUB_END_INDEX)"
echo "=================================================="
echo ""

set -x

# Set subscription
az account set --subscription "$SUBSCRIPTION"

# Get existing resources
UAMI_RESOURCE_ID=$(az identity show \
    --name "$USER_IDENTITY" \
    --resource-group "$RESOURCE_GROUP" \
    --query id -o tsv)

NAMESPACE_RESOURCE_ID=$(az iot adr ns show \
    --name "$NAMESPACE_NAME" \
    --resource-group "$RESOURCE_GROUP" \
    --query id -o tsv)

# Create multiple IoT Hubs
for i in $(seq "$HUB_START_INDEX" "$HUB_END_INDEX"); do
    HUB_NAME="ruath-scale-$(printf '%03d' $i)"
    echo ""
    echo "=================================================="
    echo "Creating IoT Hub: $HUB_NAME"
    echo "=================================================="

    # Create IoT Hub Gen2
    az iot hub create \
        --name "$HUB_NAME" \
        --resource-group "$RESOURCE_GROUP" \
        --location "$REGION" \
        --sku GEN2 \
        --mi-user-assigned "$UAMI_RESOURCE_ID" \
        --ns-resource-id "$NAMESPACE_RESOURCE_ID" \
        --ns-identity-id "$UAMI_RESOURCE_ID"

    # Link DPS to IoT Hub
    az iot dps linked-hub create \
        --dps-name "$DPS_NAME" \
        --resource-group "$RESOURCE_GROUP" \
        --hub-name "$HUB_NAME"
done

# Sync namespace credentials
echo ""
echo "=================================================="
echo "Syncing ADR namespace credentials"
echo "=================================================="
az iot adr ns credential sync \
    --namespace "$NAMESPACE_NAME" \
    --resource-group "$RESOURCE_GROUP"

set +x

echo ""
echo "=================================================="
echo "Provisioning Complete!"
echo "=================================================="
echo "Resource Group:  $RESOURCE_GROUP"
echo "DPS:             $DPS_NAME"
echo "Namespace:       $NAMESPACE_NAME"
echo "IoT Hubs Created:"
for i in $(seq "$HUB_START_INDEX" "$HUB_END_INDEX"); do
    echo "  - ruath-scale-$(printf '%03d' $i)"
done
echo "=================================================="
