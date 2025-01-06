#!/bin/bash

# AI Guardian System Rollback Script
# Version: 1.0.0
# Purpose: Automated rollback of system components with zero-downtime recovery
# Dependencies:
# - kubectl v1.28+
# - helm v3.12+
# - temporal v1.20+

set -euo pipefail

# Global configuration
ROLLBACK_TIMEOUT=${ROLLBACK_TIMEOUT:-300}  # 5 minutes timeout
HEALTH_CHECK_INTERVAL=${HEALTH_CHECK_INTERVAL:-15}  # 15 seconds between health checks
KUBE_NAMESPACE=${KUBE_NAMESPACE:-guardian}
ROLLBACK_STATE=${ROLLBACK_STATE:-/var/run/guardian/rollback.state}
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Source deployment state from deploy_app.sh
if [[ -f "${SCRIPT_DIR}/deploy_app.sh" ]]; then
    source "${SCRIPT_DIR}/deploy_app.sh"
fi

# Logging function
log() {
    local level=$1
    shift
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] [${level}] $*" >&2
}

# Check rollback prerequisites
check_rollback_prerequisites() {
    log "INFO" "Checking rollback prerequisites..."
    
    # Verify cluster access
    if ! kubectl auth can-i get deployments -n "${KUBE_NAMESPACE}" >/dev/null 2>&1; then
        log "ERROR" "Insufficient Kubernetes cluster access"
        return 1
    }

    # Check previous deployment state
    if [[ ! -f "${ROLLBACK_STATE}" ]]; then
        log "ERROR" "Previous deployment state not found"
        return 1
    }

    # Verify resource quotas
    local resource_check
    resource_check=$(kubectl describe quota -n "${KUBE_NAMESPACE}" 2>/dev/null)
    if [[ $? -ne 0 ]]; then
        log "ERROR" "Failed to verify resource quotas"
        return 1
    }

    # Validate security policies
    if ! kubectl auth can-i use podsecuritypolicy -n "${KUBE_NAMESPACE}" >/dev/null 2>&1; then
        log "WARNING" "Pod security policies not enforced"
    }

    return 0
}

# Rollback backend services
rollback_backend() {
    local target_version=$1
    local namespace=$2
    
    log "INFO" "Rolling back backend services to version ${target_version}"
    
    # Create rollback plan
    local rollback_manifest
    rollback_manifest=$(mktemp)
    cat "${SCRIPT_DIR}/../kubernetes/backend-deployment.yaml" | \
        sed "s/version: .*/version: ${target_version}/" > "${rollback_manifest}"

    # Execute rolling update
    if ! kubectl rollout undo deployment/guardian-backend -n "${namespace}" \
        --to-revision="${target_version}" --timeout="${ROLLBACK_TIMEOUT}s"; then
        log "ERROR" "Backend rollback failed"
        rm -f "${rollback_manifest}"
        return 1
    }

    # Monitor rollout status
    kubectl rollout status deployment/guardian-backend -n "${namespace}" \
        --timeout="${ROLLBACK_TIMEOUT}s"
    
    rm -f "${rollback_manifest}"
    return 0
}

# Rollback Temporal.io components
rollback_temporal() {
    local target_version=$1
    
    log "INFO" "Rolling back Temporal.io components to version ${target_version}"
    
    # Pause workflows gracefully
    temporal operator namespace update guardian --pause-processing=true
    
    # Backup workflow states
    local backup_dir="/tmp/temporal-backup-$(date +%Y%m%d-%H%M%S)"
    mkdir -p "${backup_dir}"
    
    # Execute Temporal rollback
    if ! helm rollback temporal "${target_version}" -n "${KUBE_NAMESPACE}"; then
        log "ERROR" "Temporal rollback failed"
        temporal operator namespace update guardian --pause-processing=false
        return 1
    }

    # Verify Temporal health
    local attempts=0
    while [[ $attempts -lt $((ROLLBACK_TIMEOUT/HEALTH_CHECK_INTERVAL)) ]]; do
        if temporal operator health && temporal operator namespace describe guardian | grep -q "ACTIVE"; then
            break
        fi
        ((attempts++))
        sleep "${HEALTH_CHECK_INTERVAL}"
    done

    # Resume workflows
    temporal operator namespace update guardian --pause-processing=false
    
    return 0
}

# Verify rollback success
verify_rollback() {
    log "INFO" "Verifying rollback status..."
    
    # Check pod status
    local unhealthy_pods
    unhealthy_pods=$(kubectl get pods -n "${KUBE_NAMESPACE}" \
        -l app=guardian -o jsonpath='{.items[?(@.status.phase!="Running")].metadata.name}')
    if [[ -n "${unhealthy_pods}" ]]; then
        log "ERROR" "Unhealthy pods detected: ${unhealthy_pods}"
        return 1
    }

    # Verify service endpoints
    if ! kubectl get endpoints -n "${KUBE_NAMESPACE}" guardian-backend \
        -o jsonpath='{.subsets[*].addresses[*]}' | grep -q .; then
        log "ERROR" "Backend service endpoints not healthy"
        return 1
    }

    # Check system metrics
    if ! curl -sf "http://localhost:8080/metrics" > /dev/null; then
        log "ERROR" "System metrics endpoint not responding"
        return 1
    }

    # Update rollback state
    echo "status=completed" > "${ROLLBACK_STATE}"
    echo "timestamp=$(date +%s)" >> "${ROLLBACK_STATE}"
    
    log "INFO" "Rollback verification completed successfully"
    return 0
}

# Main rollback procedure
main() {
    local target_version=$1
    
    log "INFO" "Starting system rollback to version ${target_version}"
    
    # Check prerequisites
    if ! check_rollback_prerequisites; then
        log "ERROR" "Prerequisite check failed"
        exit 1
    }
    
    # Create rollback state file
    echo "status=in_progress" > "${ROLLBACK_STATE}"
    echo "previous_version=${target_version}" >> "${ROLLBACK_STATE}"
    
    # Execute rollback operations
    if ! rollback_backend "${target_version}" "${KUBE_NAMESPACE}"; then
        log "ERROR" "Backend rollback failed"
        echo "status=failed" > "${ROLLBACK_STATE}"
        exit 1
    }
    
    if ! rollback_temporal "${target_version}"; then
        log "ERROR" "Temporal rollback failed"
        echo "status=failed" > "${ROLLBACK_STATE}"
        exit 1
    }
    
    # Verify rollback
    if ! verify_rollback; then
        log "ERROR" "Rollback verification failed"
        echo "status=failed" > "${ROLLBACK_STATE}"
        exit 1
    }
    
    log "INFO" "System rollback completed successfully"
    exit 0
}

# Script entry point
if [[ $# -ne 1 ]]; then
    echo "Usage: $0 <target_version>"
    exit 1
fi

main "$1"