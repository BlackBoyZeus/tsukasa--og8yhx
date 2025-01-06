#!/usr/bin/env bash

# AI Guardian System Update Script
# Version: 1.0.0
# Dependencies:
# - kubectl v1.28+
# - temporal v1.20+
# - tpm2-tools v5.2+

set -euo pipefail

# Source deployment functions
source "$(dirname "$0")/deploy_app.sh"

# Global configuration
readonly UPDATE_TIMEOUT=900
readonly HEALTH_CHECK_INTERVAL=30
readonly TPM_STATE_FILE="/var/run/guardian/tpm.state"
readonly ML_STATE_DIR="/var/lib/guardian/ml/state"
readonly TEMPORAL_BACKUP_DIR="/var/lib/guardian/temporal/backup"

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

# Check update prerequisites
check_update_prerequisites() {
    local target_version=$1
    local ml_model_version=$2

    log_info "Checking update prerequisites for version ${target_version}..."

    # Verify TPM state and secure boot chain
    if ! tpm2_pcrread sha256:0,1,2,3,4,5,6,7 > "${TPM_STATE_FILE}"; then
        log_error "Failed to verify TPM state"
        return 1
    fi

    # Validate SSL/TLS certificates
    if ! openssl verify -CAfile /etc/guardian/certs/ca.crt /etc/guardian/certs/guardian.crt; then
        log_error "SSL/TLS certificate validation failed"
        return 1
    }

    # Check ML model compatibility
    if ! yq eval ".model_versions[\"${ml_model_version}\"].compatible" ../config/ml-model-config.yaml; then
        log_error "ML model version ${ml_model_version} is not compatible"
        return 1
    }

    # Verify Temporal.io workflow compatibility
    if ! temporal operator cluster health; then
        log_error "Temporal.io cluster health check failed"
        return 1
    }

    # Verify system resource availability
    local available_memory
    available_memory=$(free -m | awk '/^Mem:/{print $7}')
    if [[ ${available_memory} -lt 4096 ]]; then
        log_error "Insufficient memory available for update"
        return 1
    }

    log_info "Prerequisites check completed successfully"
    return 0
}

# Backup system state
backup_system_state() {
    local backup_id="backup_$(date +%Y%m%d_%H%M%S)"
    local backup_dir="/var/lib/guardian/backups/${backup_id}"

    log_info "Creating system state backup..."

    # Create backup directory structure
    mkdir -p "${backup_dir}"/{ml,temporal,config,security}

    # Backup ML model states
    if ! cp -r "${ML_STATE_DIR}"/* "${backup_dir}/ml/"; then
        log_error "Failed to backup ML model states"
        return 1
    fi

    # Backup Temporal.io workflow states
    if ! temporal operator cluster backup start \
        --filename "${backup_dir}/temporal/workflows.backup"; then
        log_error "Failed to backup Temporal.io workflows"
        return 1
    fi

    # Backup security contexts and certificates
    if ! cp -r /etc/guardian/security/* "${backup_dir}/security/"; then
        log_error "Failed to backup security contexts"
        return 1
    }

    # Create backup manifest
    cat > "${backup_dir}/manifest.json" << EOF
{
    "backup_id": "${backup_id}",
    "timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
    "components": {
        "ml_models": "$(sha256sum "${backup_dir}/ml/*" 2>/dev/null | base64)",
        "temporal": "$(sha256sum "${backup_dir}/temporal/*" 2>/dev/null | base64)",
        "security": "$(sha256sum "${backup_dir}/security/*" 2>/dev/null | base64)"
    }
}
EOF

    # Sign backup manifest with TPM
    if ! tpm2_sign -c 0x81000000 -g sha256 -o "${backup_dir}/manifest.sig" \
        "${backup_dir}/manifest.json"; then
        log_error "Failed to sign backup manifest"
        return 1
    fi

    echo "${backup_id}"
    return 0
}

# Update ML components
update_ml_components() {
    local version=$1
    local model_path=$2

    log_info "Updating ML components to version ${version}..."

    # Verify model signature
    if ! openssl dgst -sha256 -verify /etc/guardian/certs/ml-public.pem \
        -signature "${model_path}.sig" "${model_path}"; then
        log_error "ML model signature verification failed"
        return 1
    fi

    # Stage new model version
    local staging_dir="${ML_STATE_DIR}/staging/${version}"
    mkdir -p "${staging_dir}"
    cp "${model_path}" "${staging_dir}/model.bin"

    # Perform gradual model transition
    for i in {0..100..20}; do
        log_info "Transitioning ${i}% traffic to new model..."
        
        # Update model router configuration
        cat > "${ML_STATE_DIR}/router.json" << EOF
{
    "models": {
        "current": "$(realpath "${ML_STATE_DIR}/current")",
        "new": "${staging_dir}",
        "traffic_split": ${i}
    }
}
EOF

        # Monitor inference performance
        sleep 30
        if ! verify_deployment_health; then
            log_error "Model transition health check failed"
            return 1
        fi
    done

    # Finalize model update
    rm -f "${ML_STATE_DIR}/current"
    ln -s "${staging_dir}" "${ML_STATE_DIR}/current"

    log_info "ML components update completed"
    return 0
}

# Update Temporal.io workflows
update_temporal_workflows() {
    local version=$1

    log_info "Updating Temporal.io workflows to version ${version}..."

    # Export current workflow states
    local workflow_backup="${TEMPORAL_BACKUP_DIR}/workflows_${version}.backup"
    if ! temporal operator cluster backup start --filename "${workflow_backup}"; then
        log_error "Failed to backup current workflows"
        return 1
    fi

    # Validate new workflow definitions
    if ! temporal workflow verify ../workflows/definitions/*.yaml; then
        log_error "Workflow definition validation failed"
        return 1
    }

    # Update workflow versions
    for workflow in ../workflows/definitions/*.yaml; do
        if ! temporal workflow deploy "${workflow}" --version "${version}"; then
            log_error "Failed to deploy workflow: $(basename "${workflow}")"
            return 1
        fi
    done

    # Update activity workers
    if ! kubectl rollout restart deployment/guardian-worker \
        --namespace="${KUBE_NAMESPACE}"; then
        log_error "Failed to restart workflow workers"
        return 1
    fi

    # Wait for workers to be ready
    if ! kubectl rollout status deployment/guardian-worker \
        --namespace="${KUBE_NAMESPACE}" --timeout="${UPDATE_TIMEOUT}s"; then
        log_error "Worker rollout failed"
        return 1
    fi

    log_info "Temporal.io workflow update completed"
    return 0
}

# Main update function
main() {
    local target_version=${1:-}
    local ml_model_version=${2:-}

    if [[ -z "${target_version}" || -z "${ml_model_version}" ]]; then
        log_error "Usage: $0 <target_version> <ml_model_version>"
        exit 1
    fi

    # Export update state
    export UPDATE_STATE='{
        "status": "starting",
        "target_version": "'"${target_version}"'",
        "ml_model_version": "'"${ml_model_version}"'",
        "timestamp": "'"$(date -u +"%Y-%m-%dT%H:%M:%SZ")"'"
    }'

    # Execute update steps
    if ! check_update_prerequisites "${target_version}" "${ml_model_version}"; then
        log_error "Prerequisites check failed"
        exit 1
    fi

    local backup_id
    if ! backup_id=$(backup_system_state); then
        log_error "System state backup failed"
        exit 1
    fi

    if ! update_ml_components "${target_version}" "/var/lib/guardian/ml/models/${ml_model_version}"; then
        log_error "ML components update failed"
        exit 1
    fi

    if ! update_temporal_workflows "${target_version}"; then
        log_error "Temporal.io workflow update failed"
        exit 1
    fi

    if ! deploy_backend "${target_version}"; then
        log_error "Backend deployment failed"
        rollback_deployment "${target_version}"
        exit 1
    fi

    # Update final state
    export UPDATE_STATE='{
        "status": "completed",
        "target_version": "'"${target_version}"'",
        "ml_model_version": "'"${ml_model_version}"'",
        "backup_id": "'"${backup_id}"'",
        "timestamp": "'"$(date -u +"%Y-%m-%dT%H:%M:%SZ")"'"
    }'

    log_info "System update completed successfully"
}

# Execute main function if script is run directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi