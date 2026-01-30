#!/bin/bash
#
# Azure Load Testing Deployment Script
#
# Before running, create config files from examples:
#   cp deploy/loadtest-configs/cert-user.yaml.example deploy/loadtest-configs/cert-user.yaml
#   cp deploy/loadtest-configs/adr-device-patch-user.yaml.example deploy/loadtest-configs/adr-device-patch-user.yaml
#   cp deploy/loadtest-configs/cert-hub-connect-user.yaml.example deploy/loadtest-configs/cert-hub-connect-user.yaml
#
# Then edit the config files with your specific settings.
#

set -e

# Function to check config file exists
check_config() {
    local config_file="$1"
    local example_file="${config_file}.example"

    if [ ! -f "$config_file" ]; then
        echo "Error: Config file not found: $config_file"
        if [ -f "$example_file" ]; then
            echo "Copy the example file to create your config:"
            echo "  cp $example_file $config_file"
        fi
        exit 1
    fi
}

# Check for required parameters
if [ $# -lt 4 ] || [ $# -gt 5 ]; then
    echo "Usage: $0 <subscription> <group> <id> <region> [test-type]"
    echo ""
    echo "Parameters:"
    echo "  subscription - Azure subscription name or ID"
    echo "  group        - Resource group name"
    echo "  id           - Resource identifier (used for all resource names)"
    echo "  region       - Azure region (e.g., westus2)"
    echo "  test-type    - Optional: cert|adr|hub-connect|all (default: all)"
    echo ""
    echo "Examples:"
    echo "  $0 my-subscription my-rg loadtest-001 westus2"
    echo "  $0 my-subscription my-rg loadtest-001 westus2 cert"
    echo "  $0 my-subscription my-rg loadtest-001 westus2 all"
    exit 1
fi

# Assign command-line parameters
SUBSCRIPTION="$1"
RESOURCE_GROUP="$2"
ID="$3"
REGION="$4"
TEST_TYPE="${5:-all}"

# Derived resource names
LOADTEST_NAME="${ID}"

# Script directory for relative paths
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Validate test type
case "$TEST_TYPE" in
    cert|adr|hub-connect|all)
        ;;
    *)
        echo "Error: Invalid test-type '$TEST_TYPE'"
        echo "Valid options: cert, adr, hub-connect, all"
        exit 1
        ;;
esac

# Check that dist directory exists with required files
if [ ! -f "$PROJECT_ROOT/dist/requirements.txt" ]; then
    echo "Error: dist/requirements.txt not found"
    echo "Run 'make build' first to generate the dist directory"
    exit 1
fi

if [ ! -f "$PROJECT_ROOT/dist/azure_iot_device-2.14.0-py3-none-any.whl" ]; then
    echo "Error: dist/azure_iot_device-2.14.0-py3-none-any.whl not found"
    echo "Run 'make build' first to generate the dist directory"
    exit 1
fi

echo "=================================================="
echo "Azure Load Testing Deployment Script"
echo "=================================================="
echo "Subscription:    $SUBSCRIPTION"
echo "Resource Group:  $RESOURCE_GROUP"
echo "ID Prefix:       $ID"
echo "Region:          $REGION"
echo "Test Type:       $TEST_TYPE"
echo "=================================================="
echo "Load Test:       $LOADTEST_NAME"
echo "=================================================="
echo ""

# Install Azure CLI load extension if needed
if ! az extension show --name load &>/dev/null; then
    echo "Installing Azure CLI 'load' extension..."
    az extension add --name load --yes
fi

# Set subscription
az account set --subscription "$SUBSCRIPTION"

# Function to deploy a single test
deploy_test() {
    local test_id="$1"
    local config_file="$2"

    echo ""
    echo "Deploying test: $test_id"
    echo "Config file: $config_file"

    # Extract test plan filename from config (to skip it in additional artifacts)
    local test_plan_file
    test_plan_file=$(grep -E '^testPlan:' "$config_file" | sed 's/testPlan: *//' | xargs basename)

    # Create or update test from YAML config
    if ! az load test create \
        --load-test-resource "$LOADTEST_NAME" \
        --resource-group "$RESOURCE_GROUP" \
        --test-id "$test_id" \
        --load-test-config-file "$config_file" 2>&1; then
        echo "Test already exists, updating..."
        az load test update \
            --load-test-resource "$LOADTEST_NAME" \
            --resource-group "$RESOURCE_GROUP" \
            --test-id "$test_id" \
            --load-test-config-file "$config_file"
    fi

    # Upload all Python files from locust_pkg (except the test plan file)
    for file in "$PROJECT_ROOT"/src/locust_pkg/*.py; do
        local filename
        filename=$(basename "$file")
        if [ "$filename" = "$test_plan_file" ]; then
            echo "Skipping $filename (already uploaded as test plan)"
            continue
        fi
        az load test file upload \
            --load-test-resource "$LOADTEST_NAME" \
            --resource-group "$RESOURCE_GROUP" \
            --test-id "$test_id" \
            --path "$file" \
            --file-type ADDITIONAL_ARTIFACTS
    done

    # Upload requirements.txt
    az load test file upload \
        --load-test-resource "$LOADTEST_NAME" \
        --resource-group "$RESOURCE_GROUP" \
        --test-id "$test_id" \
        --path "$PROJECT_ROOT/dist/requirements.txt" \
        --file-type ADDITIONAL_ARTIFACTS

    # Upload wheel file
    az load test file upload \
        --load-test-resource "$LOADTEST_NAME" \
        --resource-group "$RESOURCE_GROUP" \
        --test-id "$test_id" \
        --path "$PROJECT_ROOT/dist/azure_iot_device-2.14.0-py3-none-any.whl" \
        --file-type ADDITIONAL_ARTIFACTS

    echo "Test $test_id deployed successfully"
}

# Check config files exist before deploying
case "$TEST_TYPE" in
    cert)
        check_config "$SCRIPT_DIR/loadtest-configs/cert-user.yaml"
        ;;
    adr)
        check_config "$SCRIPT_DIR/loadtest-configs/adr-device-patch-user.yaml"
        ;;
    hub-connect)
        check_config "$SCRIPT_DIR/loadtest-configs/cert-hub-connect-user.yaml"
        ;;
    all)
        check_config "$SCRIPT_DIR/loadtest-configs/cert-user.yaml"
        check_config "$SCRIPT_DIR/loadtest-configs/adr-device-patch-user.yaml"
        check_config "$SCRIPT_DIR/loadtest-configs/cert-hub-connect-user.yaml"
        ;;
esac

# Deploy tests based on test type
case "$TEST_TYPE" in
    cert)
        deploy_test "cert-user-test" "$SCRIPT_DIR/loadtest-configs/cert-user.yaml"
        ;;
    adr)
        deploy_test "adr-device-patch-user-test" "$SCRIPT_DIR/loadtest-configs/adr-device-patch-user.yaml"
        ;;
    hub-connect)
        deploy_test "cert-hub-connect-user-test" "$SCRIPT_DIR/loadtest-configs/cert-hub-connect-user.yaml"
        ;;
    all)
        deploy_test "cert-user-test" "$SCRIPT_DIR/loadtest-configs/cert-user.yaml"
        deploy_test "adr-device-patch-user-test" "$SCRIPT_DIR/loadtest-configs/adr-device-patch-user.yaml"
        deploy_test "cert-hub-connect-user-test" "$SCRIPT_DIR/loadtest-configs/cert-hub-connect-user.yaml"
        ;;
esac

set +x

echo ""
echo "=================================================="
echo "Deployment Complete!"
echo "=================================================="
echo "Load Test Resource: $LOADTEST_NAME"
echo "Resource Group:     $RESOURCE_GROUP"
echo ""
echo "To run a test:"
echo "  az load test-run create \\"
echo "      --load-test-resource \"$LOADTEST_NAME\" \\"
echo "      --resource-group \"$RESOURCE_GROUP\" \\"
echo "      --test-id \"<test-id>\" \\"
echo "      --test-run-id \"run-\$(date +%Y%m%d-%H%M%S)\""
echo ""
echo "Available test IDs:"
case "$TEST_TYPE" in
    cert)
        echo "  - cert-user-test"
        ;;
    adr)
        echo "  - adr-device-patch-user-test"
        ;;
    hub-connect)
        echo "  - cert-hub-connect-user-test"
        ;;
    all)
        echo "  - cert-user-test"
        echo "  - adr-device-patch-user-test"
        echo "  - cert-hub-connect-user-test"
        ;;
esac
echo "=================================================="
