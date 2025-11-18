#!/bin/bash

set -e

# Check for required parameters
if [ $# -ne 4 ]; then
    echo "Usage: $0 <subscription> <group> <id> <region>"
    echo ""
    echo "Parameters:"
    echo "  subscription - Azure subscription name or ID"
    echo "  group        - Resource group name"
    echo "  id           - Resource identifier (used for all resource names)"
    echo "  region       - Azure region (e.g., westus2)"
    exit 1
fi

# Assign command-line parameters
SUBSCRIPTION="$1"
RESOURCE_GROUP="$2"
ID="$3"
REGION="$4"

# Derived resource names
DPS_NAME="${ID}-dps"
NAMESPACE_NAME="${ID}-ns"
ENROLLMENT_ID="${ID}-enrollment"
HUB_NAME="${ID}-hub"
USER_IDENTITY="${ID}-identity"
POLICY_NAME="${ID}-policy"

echo "=================================================="
echo "Azure IoT Hub Gen2 Provisioning Script"
echo "=================================================="
echo "Subscription:    $SUBSCRIPTION"
echo "Resource Group:  $RESOURCE_GROUP"
echo "ID Prefix:       $ID"
echo "Region:          $REGION"
echo "=================================================="
echo "DPS Name:        $DPS_NAME"
echo "Namespace:       $NAMESPACE_NAME"
echo "Enrollment ID:   $ENROLLMENT_ID"
echo "Hub Name:        $HUB_NAME"
echo "User Identity:   $USER_IDENTITY"
echo "Policy Name:     $POLICY_NAME"
echo "=================================================="
echo ""

# Uncomment these if you need to install/update the Azure IoT extension
# az extension remove --name azure-iot
# az extension add --name azure-iot --allow-preview
# az extension add --upgrade --source https://github.com/Azure/azure-iot-cli-extension/releases/download/v0.30.0b1/azure_iot-0.30.0b1-py3-none-any.whl

set -x

# Set subscription
az account set --subscription "$SUBSCRIPTION"

# Create resource group
az group create --name "$RESOURCE_GROUP" --location "$REGION"

# Get subscription ID
SUBSCRIPTION_ID=$(az account show --query id -o tsv)

# Create role assignment for Azure IoT service
az role assignment create \
    --assignee "89d10474-74af-4874-99a7-c23c2f643083" \
    --role "Contributor" \
    --scope "/subscriptions/$SUBSCRIPTION_ID/resourceGroups/$RESOURCE_GROUP"

# Create user-assigned managed identity
az identity create \
    --name "$USER_IDENTITY" \
    --resource-group "$RESOURCE_GROUP" \
    --location "$REGION"

UAMI_RESOURCE_ID=$(az identity show \
    --name "$USER_IDENTITY" \
    --resource-group "$RESOURCE_GROUP" \
    --query id -o tsv)

# Create ADR namespace with credential policy
az iot adr ns create \
    --name "$NAMESPACE_NAME" \
    --resource-group "$RESOURCE_GROUP" \
    --location "$REGION" \
    --enable-credential-policy true \
    --policy-name "$POLICY_NAME"

# Get managed identity principal ID
UAMI_PRINCIPAL_ID=$(az identity show \
    --name "$USER_IDENTITY" \
    --resource-group "$RESOURCE_GROUP" \
    --query principalId -o tsv)

# Get namespace resource ID
NAMESPACE_RESOURCE_ID=$(az iot adr ns show \
    --name "$NAMESPACE_NAME" \
    --resource-group "$RESOURCE_GROUP" \
    --query id -o tsv)

# Assign role to managed identity for namespace
az role assignment create \
    --assignee "$UAMI_PRINCIPAL_ID" \
    --role "a5c3590a-3a1a-4cd4-9648-ea0a32b15137" \
    --scope "$NAMESPACE_RESOURCE_ID"

# Create IoT Hub Gen2
az iot hub create \
    --name "$HUB_NAME" \
    --resource-group "$RESOURCE_GROUP" \
    --location "$REGION" \
    --sku GEN2 \
    --mi-user-assigned "$UAMI_RESOURCE_ID" \
    --ns-resource-id "$NAMESPACE_RESOURCE_ID" \
    --ns-identity-id "$UAMI_RESOURCE_ID"

# Get ADR namespace principal ID
ADR_PRINCIPAL_ID=$(az iot adr ns show \
    --name "$NAMESPACE_NAME" \
    --resource-group "$RESOURCE_GROUP" \
    --query identity.principalId -o tsv)

# Get hub resource ID
HUB_RESOURCE_ID=$(az iot hub show \
    --name "$HUB_NAME" \
    --resource-group "$RESOURCE_GROUP" \
    --query id -o tsv)

# Assign roles to ADR namespace for hub access
az role assignment create \
    --assignee "$ADR_PRINCIPAL_ID" \
    --role "Contributor" \
    --scope "$HUB_RESOURCE_ID"

az role assignment create \
    --assignee "$ADR_PRINCIPAL_ID" \
    --role "IoT Hub Registry Contributor" \
    --scope "$HUB_RESOURCE_ID"

# Create Device Provisioning Service
az iot dps create \
    --name "$DPS_NAME" \
    --resource-group "$RESOURCE_GROUP" \
    --location "$REGION" \
    --mi-user-assigned "$UAMI_RESOURCE_ID" \
    --ns-resource-id "$NAMESPACE_RESOURCE_ID" \
    --ns-identity-id "$UAMI_RESOURCE_ID"

# Link DPS to IoT Hub
az iot dps linked-hub create \
    --dps-name "$DPS_NAME" \
    --resource-group "$RESOURCE_GROUP" \
    --hub-name "$HUB_NAME"

# List linked hubs
az iot dps linked-hub list \
    --dps-name "$DPS_NAME" \
    --resource-group "$RESOURCE_GROUP"

# Sync namespace credentials
az iot adr ns credential sync \
    --namespace "$NAMESPACE_NAME" \
    --resource-group "$RESOURCE_GROUP"

# Create enrollment group
az iot dps enrollment-group create \
    --dps-name "$DPS_NAME" \
    --resource-group "$RESOURCE_GROUP" \
    --enrollment-id "$ENROLLMENT_ID" \
    --credential-policy "$POLICY_NAME"

echo ""
echo "=================================================="
echo "Provisioning Complete!"
echo "=================================================="
echo "Resource Group:  $RESOURCE_GROUP"
echo "IoT Hub:         $HUB_NAME"
echo "DPS:             $DPS_NAME"
echo "Namespace:       $NAMESPACE_NAME"
echo "Enrollment ID:   $ENROLLMENT_ID"
echo "=================================================="
