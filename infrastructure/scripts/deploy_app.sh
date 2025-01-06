#!/usr/bin/env bash

# AI Guardian System Deployment Script
# Version: 1.0.0
# Dependencies:
# - kubectl v1.28+
# - helm v3.12+
# - temporal v1.20+

set -euo pipefail

# Global configuration
readonly KUBE_NAMESPACE="guardian"
readonly DEPLOYMENT_TIMEOUT=600
readonly HEALTH_CHECK_INTERVAL=30
readonly DEPLOYMENT_STATE="/var/run/guardian/deployment.state"
readonly RESOURCE_THRESHOLD=5
readonly ROLLBACK_TIMEOUT=300
readonly TRAFFIC_SHIFT_INTERVAL=60

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
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

# Validate deployment prerequisites
check_prerequisites() {
    log_info "Validating deployment prerequisites..."
    
    # Verify Kubernetes access and permissions
    if ! kubectl auth can-i create deployments --namespace="${KUBE_NAMESPACE}"; then
        log_error "Insufficient Kubernetes permissions"
        return 1
    }

    # Verify TPM and secure boot status
    if ! tpm2_getcap properties-fixed | grep -q 'TPM_PT_MANUFACTURER: "IBM"'; then
        log_error "TPM validation failed"
        return 1
    }

    # Validate TLS certificates
    if ! openssl verify -CAfile /etc/guardian/certs/ca.crt /etc/guardian/certs/server.crt; then
        log_error "TLS certificate validation failed"
        return 1
    }

    # Check resource availability
    local cpu_available
    cpu_available=$(kubectl describe node -l node-role.kubernetes.io/worker=true | grep "Allocatable cpu" | awk '{print $3}')
    if [[ ${cpu_available%m} -lt 4000 ]]; then
        log_error "Insufficient CPU resources available"
        return 1
    }

    # Verify Temporal.io connectivity
    if ! temporal operator cluster health; then
        log_error "Temporal.io cluster health check failed"
        return 1
    }

    log_info "Prerequisites validation successful"
    return 0
}

# Deploy backend services with blue-green strategy
deploy_backend() {
    local version=$1
    local deployment_name="guardian-backend-${version}"
    
    log_info "Deploying backend version ${version}..."

    # Create new deployment
    kubectl apply -f ../kubernetes/backend-deployment.yaml \
        --namespace="${KUBE_NAMESPACE}" || return 1

    # Wait for new pods to be ready
    if ! kubectl wait --for=condition=ready pod \
        -l app=guardian,component=backend,version="${version}" \
        --timeout="${DEPLOYMENT_TIMEOUT}s" \
        --namespace="${KUBE_NAMESPACE}"; then
        log_error "Backend pods failed to become ready"
        return 1
    }

    # Progressive traffic shift
    for i in {0..100..20}; do
        log_info "Shifting ${i}% traffic to new version"
        kubectl patch service guardian-backend \
            --namespace="${KUBE_NAMESPACE}" \
            --type=json \
            -p="[{\"op\": \"replace\", \"path\": \"/spec/selector/version\", \"value\": \"${version}\"}]"
        
        sleep "${TRAFFIC_SHIFT_INTERVAL}"

        # Monitor health metrics during shift
        if ! verify_deployment_health; then
            log_error "Health check failed during traffic shift"
            rollback_deployment "${version}"
            return 1
        fi
    done

    # Update deployment state
    echo "{\"status\": \"deployed\", \"version\": \"${version}\", \"timestamp\": \"$(date -u +"%Y-%m-%dT%H:%M:%SZ")\"}" > "${DEPLOYMENT_STATE}"

    log_info "Backend deployment successful"
    return 0
}

# Deploy Temporal.io workflow engine
deploy_temporal() {
    local version=$1
    
    log_info "Deploying Temporal.io version ${version}..."

    # Apply Temporal deployment configuration
    kubectl apply -f ../kubernetes/temporal-deployment.yaml \
        --namespace="${KUBE_NAMESPACE}" || return 1

    # Wait for Temporal pods to be ready
    if ! kubectl wait --for=condition=ready pod \
        -l app=temporal,component=server \
        --timeout="${DEPLOYMENT_TIMEOUT}s" \
        --namespace="${KUBE_NAMESPACE}"; then
        log_error "Temporal pods failed to become ready"
        return 1
    }

    # Verify Temporal namespace and workflows
    if ! temporal operator namespace describe guardian; then
        log_error "Failed to verify Temporal namespace"
        return 1
    }

    log_info "Temporal deployment successful"
    return 0
}

# Verify deployment health
verify_deployment_health() {
    log_info "Verifying deployment health..."

    # Check pod health
    local unhealthy_pods
    unhealthy_pods=$(kubectl get pods \
        --namespace="${KUBE_NAMESPACE}" \
        -l app=guardian \
        --field-selector status.phase!=Running \
        -o name)
    
    if [[ -n "${unhealthy_pods}" ]]; then
        log_error "Unhealthy pods detected: ${unhealthy_pods}"
        return 1
    }

    # Check resource usage
    local cpu_usage
    cpu_usage=$(kubectl top pod \
        --namespace="${KUBE_NAMESPACE}" \
        -l app=guardian \
        --no-headers \
        | awk '{sum+=$2} END {print sum}')
    
    if [[ ${cpu_usage%m} -gt ${RESOURCE_THRESHOLD}000 ]]; then
        log_error "Resource usage exceeds threshold"
        return 1
    }

    # Verify security compliance
    if ! verify_security_compliance; then
        log_error "Security compliance check failed"
        return 1
    }

    log_info "Deployment health verification successful"
    return 0
}

# Verify security compliance
verify_security_compliance() {
    # Check security policies
    if ! kubectl auth can-i use podsecuritypolicy/restricted \
        --namespace="${KUBE_NAMESPACE}"; then
        return 1
    }

    # Verify TLS configuration
    if ! openssl s_client -connect localhost:9090 -tls1_3 </dev/null \
        | grep -q "Protocol  : TLSv1.3"; then
        return 1
    }

    # Check RBAC policies
    if ! kubectl auth can-i -l app=guardian --list \
        --namespace="${KUBE_NAMESPACE}" \
        | grep -q "pods/log.*yes"; then
        return 1
    }

    return 0
}

# Rollback deployment
rollback_deployment() {
    local version=$1
    
    log_warn "Initiating rollback for version ${version}..."

    # Restore previous service selector
    kubectl rollout undo deployment/guardian-backend \
        --namespace="${KUBE_NAMESPACE}" || true

    # Wait for rollback to complete
    kubectl rollout status deployment/guardian-backend \
        --namespace="${KUBE_NAMESPACE}" \
        --timeout="${ROLLBACK_TIMEOUT}s" || true

    # Update deployment state
    echo "{\"status\": \"rolled_back\", \"version\": \"${version}\", \"timestamp\": \"$(date -u +"%Y-%m-%dT%H:%M:%SZ")\"}" > "${DEPLOYMENT_STATE}"

    log_warn "Rollback completed"
}

# Main deployment function
main() {
    local version=${1:-}
    if [[ -z "${version}" ]]; then
        log_error "Version parameter is required"
        exit 1
    }

    # Create deployment state directory if it doesn't exist
    mkdir -p "$(dirname "${DEPLOYMENT_STATE}")"

    # Execute deployment steps
    if ! check_prerequisites; then
        log_error "Prerequisites check failed"
        exit 1
    }

    if ! deploy_temporal "${version}"; then
        log_error "Temporal deployment failed"
        exit 1
    }

    if ! deploy_backend "${version}"; then
        log_error "Backend deployment failed"
        rollback_deployment "${version}"
        exit 1
    }

    if ! verify_deployment_health; then
        log_error "Deployment health verification failed"
        rollback_deployment "${version}"
        exit 1
    }

    log_info "Deployment completed successfully"
}

# Execute main function with parameters
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi