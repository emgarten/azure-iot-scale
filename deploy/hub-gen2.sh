#!/bin/bash

set -xe

export SUBSCRIPTION="your subscription name or ID"
export RESOURCE_GROUP="your resource group name"
export RESOURCE_NAME="your resource name"
export REGION="westus2"


# az extension remove --name azure-iot
# az extension add --name azure-iot --allow-preview
# az extension add --upgrade --source https://github.com/Azure/azure-iot-cli-extension/releases/download/v0.30.0b1/azure_iot-0.30.0b1-py3-none-any.whl

az account set --subscription "<your subscription name or ID>"
az group create --name <RESOURCE_GROUP_NAME> --location <REGION>
az role assignment create --assignee "89d10474-74af-4874-99a7-c23c2f643083" --role "Contributor" --scope "/subscriptions/<SUBSCRIPTION_ID>/resourceGroups/<RESOURCE_GROUP_NAME>"
az identity create --name <USER_IDENTITY> --resource-group <RESOURCE_GROUP_NAME> --location <REGION>
UAMI_RESOURCE_ID=$(az identity show --name <USER_IDENTITY> --resource-group <RESOURCE_GROUP_NAME> --query id -o tsv)
az iot adr ns create --name <NAMESPACE_NAME> --resource-group <RESOURCE_GROUP_NAME> --location <REGION> --enable-credential-policy true --policy-name <POLICY_NAME>

UAMI_PRINCIPAL_ID=$(az identity show --name <USER_IDENTITY> --resource-group <RESOURCE_GROUP> --query principalId -o tsv)
NAMESPACE_RESOURCE_ID=$(az iot adr ns show --name <NAMESPACE_NAME> --resource-group <RESOURCE_GROUP> --query id -o tsv)
az role assignment create --assignee $UAMI_PRINCIPAL_ID --role "a5c3590a-3a1a-4cd4-9648-ea0a32b15137" --scope $NAMESPACE_RESOURCE_ID

az iot hub create --name <HUB_NAME> --resource-group <RESOURCE_GROUP> --location <HUB_LOCATION> --sku GEN2 --mi-user-assigned $UAMI_RESOURCE_ID --ns-resource-id $NAMESPACE_RESOURCE_ID --ns-identity-id $UAMI_RESOURCE_ID

ADR_PRINCIPAL_ID=$(az iot adr ns show --name <NAMESPACE_NAME> --resource-group <RESOURCE_GROUP> --query identity.principalId -o tsv)
HUB_RESOURCE_ID=$(az iot hub show --name <HUB_NAME> --resource-group <RESOURCE_GROUP> --query id -o tsv)
az role assignment create --assignee $ADR_PRINCIPAL_ID --role "Contributor" --scope $HUB_RESOURCE_ID

az role assignment create --assignee $ADR_PRINCIPAL_ID --role "Contributor" --scope $HUB_RESOURCE_ID
az role assignment create --assignee $ADR_PRINCIPAL_ID --role "IoT Hub Registry Contributor" --scope $HUB_RESOURCE_ID

az iot dps create --name <DPS_NAME> --resource-group <RESOURCE_GROUP> --location <LOCATION> --mi-user-assigned $UAMI_RESOURCE_ID --ns-resource-id $NAMESPACE_RESOURCE_ID --ns-identity-id $UAMI_RESOURCE_ID
az iot dps linked-hub create --dps-name <DPS_NAME> --resource-group <RESOURCE_GROUP> --hub-name <HUB_NAME>
az iot dps linked-hub list --dps-name <DPS_NAME> --resource-group <RESOURCE_GROUP>

az iot adr ns credential sync --namespace <NAMESPACE_NAME> --resource-group <RESOURCE_GROUP>
az iot dps enrollment-group create --dps-name <DPS_NAME> --resource-group <RESOURCE_GROUP> --enrollment-id <ENROLLMENT_ID> --credential-policy <POLICY_NAME>

