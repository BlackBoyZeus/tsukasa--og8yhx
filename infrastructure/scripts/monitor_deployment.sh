#!/usr/bin/env bash

# AI Guardian System Monitoring Script
# Version: 1.0.0
# Dependencies:
# - kubectl v1.28+
# - curl v7.88+
# - jq v1.6+
# - openssl v3.0+

set -euo pipefail

# Source deployment state and functions
source ./deploy_app.sh

# Global configuration
readonly MONITORING_INTERVAL=30
readonly HEALTH_CHECK_TIMEOUT=10
readonly MAX_RETRIES=5
readonly ALERT_THRESHOLD=90
readonly SECURITY_COMPLIANCE_LEVEL="HIGH"
readonly ML_PERFORMANCE_THRESHOLD=95
readonly CERT_EXPIRY_WARNING=30
readonly AUDIT_CHECK_INTERVAL=300

# Color codes for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly NC='\033[0m'

# Logging functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $(date -u +"%Y-%m-%dT%H:%M:%SZ") $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $(date -u +"%Y-%m-%dT%H:%M:%SZ") $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $(date -u +"%Y-%m-%dT%H:%M:%SZ") $1" >&2
}

# Check pod health with enhanced security context validation
check_pod_health() {
    local namespace=$1
    local deployment_name=$2
    local security_context=$3
    local status=0

    log_info "Checking pod health for ${deployment_name} in ${namespace}"

    # Verify pod security context
    local pod_security
    pod_security=$(kubectl get pods -n "${namespace}" -l "app=${deployment_name}" \
        -o jsonpath='{.items[*].spec.securityContext}')
    
    if ! echo "${pod_security}" | jq -e "${security_context}" >/dev/null; then
        log_error "Pod security context validation failed"
        status=1
    fi

    # Check resource quotas
    local resource_usage
    resource_usage=$(kubectl top pod -n "${namespace}" -l "app=${deployment_name}" \
        --no-headers | awk '{print $2}' | cut -d 'm' -f1)
    
    if [[ "${resource_usage:-0}" -gt "${ALERT_THRESHOLD}" ]]; then
        log_warn "High resource usage detected: ${resource_usage}%"
    fi

    # Validate Temporal.io worker health
    if ! temporal operator cluster health | grep -q "HEALTHY"; then
        log_error "Temporal.io worker health check failed"
        status=1
    fi

    return "${status}"
}

# Monitor system metrics with ML performance tracking
monitor_metrics() {
    local metrics_endpoint=$1
    local ml_model_config=$2
    local status=0

    log_info "Collecting system metrics from ${metrics_endpoint}"

    # Collect system metrics with certificate validation
    local metrics
    metrics=$(curl -sSL --cacert /etc/guardian/certs/ca.crt \
        --cert /etc/guardian/certs/client.crt \
        --key /etc/guardian/certs/client.key \
        "${metrics_endpoint}/metrics")

    # Track ML model performance
    local ml_performance
    ml_performance=$(echo "${metrics}" | jq -r '.ml_metrics.inference_latency')
    
    if [[ "${ml_performance:-0}" -gt "${ML_PERFORMANCE_THRESHOLD}" ]]; then
        log_warn "ML model performance degradation detected"
        status=1
    fi

    # Monitor ZFS storage health
    local zfs_health
    zfs_health=$(zpool status -x)
    if [[ "${zfs_health}" != "all pools are healthy" ]]; then
        log_error "ZFS storage health check failed: ${zfs_health}"
        status=1
    fi

    # Verify TPM status
    if ! tpm2_getcap properties-fixed | grep -q "TPM_PT_MANUFACTURER"; then
        log_error "TPM verification failed"
        status=1
    fi

    return "${status}"
}

# Check service health with security compliance
check_service_health() {
    local service_name=$1
    local port=$2
    local security_requirements=$3
    local status=0

    log_info "Checking health of service ${service_name} on port ${port}"

    # Validate TLS certificate chain
    local cert_expiry
    cert_expiry=$(openssl s_client -connect "localhost:${port}" 2>/dev/null \
        | openssl x509 -noout -enddate \
        | cut -d= -f2)
    
    local days_until_expiry
    days_until_expiry=$(( ($(date -d "${cert_expiry}" +%s) - $(date +%s) ) / 86400 ))
    
    if [[ "${days_until_expiry}" -lt "${CERT_EXPIRY_WARNING}" ]]; then
        log_warn "Certificate expiring in ${days_until_expiry} days"
    fi

    # Check service endpoint security
    local security_headers
    security_headers=$(curl -sSL -I "https://localhost:${port}/health" \
        --cacert /etc/guardian/certs/ca.crt)
    
    if ! echo "${security_headers}" | grep -q "Strict-Transport-Security"; then
        log_error "Missing security headers"
        status=1
    fi

    # Verify security compliance
    if ! verify_deployment_health; then
        log_error "Security compliance check failed"
        status=1
    fi

    return "${status}"
}

# Intelligent alert handling with correlation
alert_on_failure() {
    local alert_type=$1
    local alert_data=$2
    local correlation_context=$3

    log_info "Processing alert: ${alert_type}"

    # Classify alert severity
    local severity
    case "${alert_type}" in
        "security")
            severity="critical"
            ;;
        "performance")
            severity="warning"
            ;;
        *)
            severity="info"
            ;;
    esac

    # Generate alert payload
    local alert_payload
    alert_payload=$(jq -n \
        --arg type "${alert_type}" \
        --arg severity "${severity}" \
        --arg timestamp "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
        --argjson data "${alert_data}" \
        --argjson context "${correlation_context}" \
        '{type: $type, severity: $severity, timestamp: $timestamp, data: $data, context: $context}')

    # Send alert with security context
    curl -sSL -X POST \
        -H "Content-Type: application/json" \
        -H "X-Security-Context: ${SECURITY_COMPLIANCE_LEVEL}" \
        --cacert /etc/guardian/certs/ca.crt \
        --cert /etc/guardian/certs/client.crt \
        --key /etc/guardian/certs/client.key \
        -d "${alert_payload}" \
        "https://alerts.guardian.local/api/v1/alerts"
}

# Main monitoring loop
main() {
    log_info "Starting AI Guardian monitoring system"

    while true; do
        # Check deployment state
        if [[ -f "${DEPLOYMENT_STATE}" ]]; then
            local deployment_status
            deployment_status=$(jq -r '.status' "${DEPLOYMENT_STATE}")

            if [[ "${deployment_status}" == "deployed" ]]; then
                # Monitor pod health
                if ! check_pod_health "guardian" "guardian-backend" \
                    '{"runAsNonRoot": true, "readOnlyRootFilesystem": true}'; then
                    alert_on_failure "security" \
                        '{"component": "pods", "status": "unhealthy"}' \
                        '{"deployment": "guardian-backend"}'
                fi

                # Monitor system metrics
                if ! monitor_metrics "https://metrics.guardian.local" \
                    '{"model": "guardian-v1", "threshold": 95}'; then
                    alert_on_failure "performance" \
                        '{"component": "metrics", "status": "degraded"}' \
                        '{"service": "metrics"}'
                fi

                # Check service health
                if ! check_service_health "guardian-api" 8080 \
                    '{"tls": "required", "auth": "mTLS"}'; then
                    alert_on_failure "security" \
                        '{"component": "service", "status": "unhealthy"}' \
                        '{"service": "guardian-api"}'
                fi
            fi
        fi

        sleep "${MONITORING_INTERVAL}"
    done
}

# Export monitoring status
export MONITORING_STATUS

# Execute main function if script is run directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi