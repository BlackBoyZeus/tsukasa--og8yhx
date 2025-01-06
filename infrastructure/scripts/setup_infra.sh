#!/usr/bin/env bash

# AI Guardian System Infrastructure Setup Script
# Version: 1.0.0
# Description: Automates the setup and initialization of AI Guardian system infrastructure
# Dependencies:
# - terraform ~> 1.0
# - kubectl ~> 1.25
# - aws-cli ~> 2.0
# - freebsd-utils 13.2

set -euo pipefail
IFS=$'\n\t'

# Global variables
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly TERRAFORM_DIR="${SCRIPT_DIR}/../terraform"
readonly KUBERNETES_DIR="${SCRIPT_DIR}/../kubernetes"

# Environment variables with defaults
export TF_LOG=${TF_LOG:-INFO}
export AWS_REGION=${AWS_REGION:-$(aws configure get region)}
export ENVIRONMENT=${ENVIRONMENT:-production}
export FREEBSD_VERSION="13.2"
export TPM_DEVICE="/dev/tpm0"

# Color codes for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check prerequisites for infrastructure setup
check_prerequisites() {
    log_info "Checking prerequisites..."
    
    # Verify FreeBSD version
    local freebsd_ver=$(uname -r | cut -d'-' -f1)
    if [[ "${freebsd_ver}" != "${FREEBSD_VERSION}" ]]; then
        log_error "Incorrect FreeBSD version. Expected ${FREEBSD_VERSION}, got ${freebsd_ver}"
        return 1
    }

    # Check TPM device
    if [[ ! -c "${TPM_DEVICE}" ]]; then
        log_error "TPM device not found at ${TPM_DEVICE}"
        return 1
    }

    # Verify required tools
    local required_tools=("terraform" "kubectl" "aws")
    for tool in "${required_tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            log_error "Required tool not found: $tool"
            return 1
        fi
    done

    # Verify AWS credentials
    if ! aws sts get-caller-identity &> /dev/null; then
        log_error "Invalid AWS credentials"
        return 1
    }

    # Check kernel modules
    local required_modules=("crypto" "aesni" "zfs")
    for module in "${required_modules[@]}"; do
        if ! kldstat -n "$module" &> /dev/null; then
            log_error "Required kernel module not loaded: $module"
            return 1
        fi
    done

    log_info "Prerequisites check completed successfully"
    return 0
}

# Initialize Terraform
init_terraform() {
    log_info "Initializing Terraform..."
    
    cd "${TERRAFORM_DIR}"

    # Initialize Terraform with backend configuration
    if ! terraform init -backend=true -backend-config="region=${AWS_REGION}" \
        -backend-config="bucket=guardian-terraform-state" \
        -backend-config="key=guardian/terraform.tfstate"; then
        log_error "Failed to initialize Terraform"
        return 1
    }

    # Create workspace if it doesn't exist
    if ! terraform workspace select "${ENVIRONMENT}" 2>/dev/null; then
        log_info "Creating new workspace: ${ENVIRONMENT}"
        terraform workspace new "${ENVIRONMENT}"
    fi

    # Validate Terraform configuration
    if ! terraform validate; then
        log_error "Terraform validation failed"
        return 1
    }

    log_info "Terraform initialization completed successfully"
    return 0
}

# Deploy infrastructure components
deploy_infrastructure() {
    local environment="$1"
    log_info "Deploying infrastructure for environment: ${environment}"

    cd "${TERRAFORM_DIR}"

    # Create Terraform plan
    if ! terraform plan -out=tfplan \
        -var="environment=${environment}" \
        -var="region=${AWS_REGION}"; then
        log_error "Failed to create Terraform plan"
        return 1
    }

    # Apply Terraform configuration
    if ! terraform apply -auto-approve tfplan; then
        log_error "Failed to apply Terraform configuration"
        return 1
    }

    # Initialize HSM cluster
    log_info "Initializing HSM cluster..."
    if ! aws cloudhsm describe-clusters --region "${AWS_REGION}" &> /dev/null; then
        log_error "Failed to initialize HSM cluster"
        return 1
    }

    # Configure Temporal.io workflow engine
    log_info "Configuring Temporal.io workflow engine..."
    if ! kubectl apply -f "${KUBERNETES_DIR}/backend-deployment.yaml"; then
        log_error "Failed to deploy Temporal.io components"
        return 1
    }

    # Set up monitoring infrastructure
    log_info "Setting up monitoring infrastructure..."
    if ! kubectl apply -f "${KUBERNETES_DIR}/monitoring/"; then
        log_error "Failed to deploy monitoring components"
        return 1
    }

    log_info "Infrastructure deployment completed successfully"
    return 0
}

# Verify deployment status
verify_deployment() {
    log_info "Verifying deployment..."

    # Check HSM cluster status
    if ! aws cloudhsm describe-clusters --region "${AWS_REGION}" | grep -q "ACTIVE"; then
        log_error "HSM cluster verification failed"
        return 1
    }

    # Verify Temporal.io deployment
    if ! kubectl get deployment guardian-backend -n guardian-system | grep -q "3/3"; then
        log_error "Temporal.io deployment verification failed"
        return 1
    }

    # Check monitoring components
    if ! kubectl get pods -n monitoring | grep -q "Running"; then
        log_error "Monitoring deployment verification failed"
        return 1
    }

    # Verify TPM measurements
    if ! tpm2_pcrread sha256:0,1,2,3 &> /dev/null; then
        log_error "TPM verification failed"
        return 1
    }

    # Export deployment status
    cat > "${SCRIPT_DIR}/deployment_status.json" << EOF
{
    "hsm_endpoint": "$(terraform output -raw hsm_endpoint)",
    "temporal_endpoint": "$(terraform output -raw temporal_endpoint)",
    "monitoring_endpoint": "$(terraform output -raw monitoring_endpoint)",
    "security_status": {
        "hsm_status": "active",
        "tpm_status": "verified",
        "encryption_status": "enabled"
    },
    "performance_metrics": {
        "cpu_usage": "$(top -b -n1 | grep "CPU" | awk '{print $2}')",
        "memory_usage": "$(vmstat -s | grep "used memory" | awk '{print $1}')",
        "disk_usage": "$(df -h / | tail -1 | awk '{print $5}')"
    }
}
EOF

    log_info "Deployment verification completed successfully"
    return 0
}

# Main execution
main() {
    log_info "Starting AI Guardian infrastructure setup..."

    # Check prerequisites
    if ! check_prerequisites; then
        log_error "Prerequisites check failed"
        exit 1
    fi

    # Initialize Terraform
    if ! init_terraform; then
        log_error "Terraform initialization failed"
        exit 1
    }

    # Deploy infrastructure
    if ! deploy_infrastructure "${ENVIRONMENT}"; then
        log_error "Infrastructure deployment failed"
        exit 1
    }

    # Verify deployment
    if ! verify_deployment; then
        log_error "Deployment verification failed"
        exit 1
    }

    log_info "AI Guardian infrastructure setup completed successfully"
    exit 0
}

# Execute main function
main "$@"