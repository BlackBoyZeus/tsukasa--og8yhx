#!/usr/bin/env bash

# AI Guardian Backend Deployment Script
# Version: 1.0.0
# Description: Secure deployment script for building and deploying the AI Guardian backend system
# to FreeBSD-based gaming consoles with comprehensive security checks and zero-downtime deployment.

set -euo pipefail
IFS=$'\n\t'

# Source common setup functions
source "$(dirname "${BASH_SOURCE[0]}")/setup.sh"
source "$(dirname "${BASH_SOURCE[0]}")/test.sh"

# Script constants
readonly SCRIPT_DIR="$(dirname "${BASH_SOURCE[0]}")"
readonly PROJECT_ROOT="$(realpath "${SCRIPT_DIR}/../..")"
readonly DOCKER_REGISTRY="guardian.registry.local"
readonly IMAGE_TAG="$(git rev-parse --short HEAD)"
readonly TPM_PCR_VALUES="[0,1,2,3,4,7]"
readonly HEALTH_CHECK_TIMEOUT=300
readonly ROLLBACK_TIMEOUT=60
readonly MAX_DEPLOYMENT_TIME=600
readonly MIN_REPLICA_COUNT=3

# Color codes for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly NC='\033[0m'

# Logging functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
    return 1
}

# Verify security prerequisites including TPM state and HSM availability
verify_security_prerequisites() {
    log_info "Verifying security prerequisites..."

    # Verify TPM device availability
    if ! tpm2_getcap properties-fixed > /dev/null 2>&1; then
        log_error "TPM device not available or accessible"
        return 1
    }

    # Verify TPM PCR values
    if ! tpm2_pcrread sha256:${TPM_PCR_VALUES} > /dev/null 2>&1; then
        log_error "Failed to read TPM PCR values"
        return 1
    }

    # Verify HSM connectivity
    if ! pkcs11-tool --module /usr/local/lib/softhsm/libsofthsm2.so -L > /dev/null 2>&1; then
        log_error "HSM not accessible"
        return 1
    }

    # Verify secure boot state
    if ! efivar -l | grep -q "SecureBoot"; then
        log_warn "Secure Boot not enabled"
    fi

    # Verify RBAC permissions
    if ! kubectl auth can-i create deployments --namespace guardian; then
        log_error "Insufficient Kubernetes RBAC permissions"
        return 1
    }

    log_info "Security prerequisites verified successfully"
    return 0
}

# Build and sign the backend Docker image
build_secure_image() {
    local tag="$1"
    local build_args="$2"
    local signing_key="$3"

    log_info "Building secure container image..."

    # Validate base image security
    docker pull --quiet freebsd:latest
    if ! docker scan --accept-license freebsd:latest; then
        log_error "Base image security scan failed"
        return 1
    }

    # Build with security optimizations
    docker build \
        --no-cache \
        --build-arg BUILD_DATE="$(date -u +'%Y-%m-%dT%H:%M:%SZ')" \
        --build-arg VCS_REF="${IMAGE_TAG}" \
        --build-arg VERSION="${tag}" \
        ${build_args} \
        -t "${DOCKER_REGISTRY}/guardian-backend:${tag}" \
        -f infrastructure/docker/backend.Dockerfile \
        "${PROJECT_ROOT}"

    # Generate SBOM
    syft "${DOCKER_REGISTRY}/guardian-backend:${tag}" -o json > "sbom_${tag}.json"

    # Sign container image
    cosign sign \
        --key "${signing_key}" \
        --recursive \
        "${DOCKER_REGISTRY}/guardian-backend:${tag}"

    # Verify signature
    if ! cosign verify \
        --key "${signing_key}.pub" \
        "${DOCKER_REGISTRY}/guardian-backend:${tag}"; then
        log_error "Image signature verification failed"
        return 1
    }

    # Push to secure registry
    docker push "${DOCKER_REGISTRY}/guardian-backend:${tag}"

    log_info "Secure image build completed successfully"
    return 0
}

# Deploy with zero-downtime using blue-green strategy
deploy_with_zero_downtime() {
    local image_tag="$1"
    local namespace="$2"
    local deployment_config="$3"

    log_info "Starting zero-downtime deployment..."

    # Verify cluster security state
    if ! kubectl get validatingwebhookconfigurations guardian-policy > /dev/null 2>&1; then
        log_error "Security policy webhook not configured"
        return 1
    }

    # Apply security policies
    kubectl apply -f infrastructure/kubernetes/security-policies.yaml

    # Create new deployment
    kubectl apply -f <(cat "${deployment_config}" | \
        sed "s|IMAGE_TAG|${image_tag}|g" | \
        sed "s|NAMESPACE|${namespace}|g")

    # Wait for new pods
    if ! kubectl rollout status deployment/guardian-backend-${image_tag} \
        --namespace "${namespace}" \
        --timeout "${MAX_DEPLOYMENT_TIME}s"; then
        log_error "Deployment timeout exceeded"
        return 1
    }

    # Verify minimum replica count
    local ready_replicas
    ready_replicas=$(kubectl get deployment guardian-backend-${image_tag} \
        --namespace "${namespace}" \
        -o jsonpath='{.status.readyReplicas}')
    
    if [ "${ready_replicas}" -lt "${MIN_REPLICA_COUNT}" ]; then
        log_error "Insufficient ready replicas: ${ready_replicas}/${MIN_REPLICA_COUNT}"
        return 1
    }

    # Execute health checks
    local health_check_url="http://guardian-backend-${image_tag}:8080/health"
    local timeout_seconds=0
    
    while [ ${timeout_seconds} -lt ${HEALTH_CHECK_TIMEOUT} ]; do
        if curl -s "${health_check_url}" | grep -q '"status":"healthy"'; then
            break
        fi
        sleep 5
        timeout_seconds=$((timeout_seconds + 5))
    done

    if [ ${timeout_seconds} -ge ${HEALTH_CHECK_TIMEOUT} ]; then
        log_error "Health check timeout exceeded"
        return 1
    }

    # Update service to point to new deployment
    kubectl patch service guardian-backend \
        --namespace "${namespace}" \
        --patch "{\"spec\":{\"selector\":{\"version\":\"${image_tag}\"}}}"

    # Remove old deployment
    local old_deployments
    old_deployments=$(kubectl get deployments \
        --namespace "${namespace}" \
        --selector app=guardian-backend \
        --field-selector metadata.name!=guardian-backend-${image_tag} \
        -o name)

    for deployment in ${old_deployments}; do
        kubectl delete "${deployment}" --namespace "${namespace}"
    done

    log_info "Deployment completed successfully"
    return 0
}

# Handle deployment rollback with state verification
enhanced_rollback() {
    local deployment_name="$1"
    local previous_state="$2"

    log_warn "Initiating deployment rollback..."

    # Stop traffic to new version
    kubectl patch service guardian-backend --patch \
        "{\"spec\":{\"selector\":{\"version\":\"${previous_state}\"}}}"

    # Scale down new deployment
    kubectl scale deployment "${deployment_name}" --replicas 0

    # Verify old version health
    if ! kubectl rollout status deployment/guardian-backend-${previous_state} \
        --timeout "${ROLLBACK_TIMEOUT}s"; then
        log_error "Rollback failed: old version unhealthy"
        return 1
    fi

    # Clean up failed deployment
    kubectl delete deployment "${deployment_name}"

    log_info "Rollback completed successfully"
    return 0
}

# Main deployment function
main() {
    local start_time
    start_time=$(date +%s)

    # Verify security prerequisites
    if ! verify_security_prerequisites; then
        log_error "Security verification failed"
        exit 1
    fi

    # Run tests before deployment
    if ! run_tests; then
        log_error "Pre-deployment tests failed"
        exit 1
    }

    # Build and sign image
    if ! build_secure_image "${IMAGE_TAG}" \
        "--build-arg SECURITY_LEVEL=HIGH" \
        "/etc/guardian/keys/signing-key.pem"; then
        log_error "Image build failed"
        exit 1
    fi

    # Deploy with zero-downtime
    if ! deploy_with_zero_downtime \
        "${IMAGE_TAG}" \
        "guardian" \
        "infrastructure/kubernetes/backend-deployment.yaml"; then
        log_error "Deployment failed"
        enhanced_rollback "guardian-backend-${IMAGE_TAG}" "${previous_version}"
        exit 1
    fi

    local end_time
    end_time=$(date +%s)
    log_info "Deployment completed in $((end_time - start_time)) seconds"
}

# Execute main function
main "$@"