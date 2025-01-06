#!/bin/sh

# Guardian System - Security Check Script
# Version: 1.0.0
# FreeBSD Version: 13.0
#
# Performs comprehensive security checks and audits on the Guardian system's
# FreeBSD environment, validating security configurations, kernel hardening,
# and component isolation mechanisms.

set -e  # Exit on error
set -u  # Exit on undefined variables

# Import system configuration
. /etc/rc.subr
. /etc/guardian.conf 2>/dev/null || exit 1

# Global configuration
GUARDIAN_SECURITY_CHECKS="capsicum mac geli jail kernel audit resource"
GUARDIAN_MIN_SECURITY_LEVEL=2
GUARDIAN_REQUIRED_MODULES="guardian_module mac_guardian geli audit"
GUARDIAN_CHECK_TIMEOUT=300
GUARDIAN_MAX_RETRIES=3
GUARDIAN_RESOURCE_THRESHOLDS="cpu_max=75 mem_max=80 io_max=70"

# Logging configuration
LOG_FILE="/var/log/guardian/security_check.log"
AUDIT_FILE="/var/log/guardian/security_audit.log"

# Utility functions
log() {
    local level="$1"
    local message="$2"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "${timestamp} [${level}] ${message}" >> "${LOG_FILE}"
    [ "${level}" = "ERROR" ] && echo "${timestamp} [${level}] ${message}" >&2
}

audit_log() {
    local event="$1"
    local details="$2"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "${timestamp}|${event}|${details}" >> "${AUDIT_FILE}"
    auditd -t "${event}" "${details}" 2>/dev/null || true
}

check_prerequisites() {
    # Verify required utilities
    for util in sysctl kldstat procstat audit; do
        if ! which "${util}" >/dev/null 2>&1; then
            log "ERROR" "Required utility not found: ${util}"
            return 1
        fi
    done

    # Verify required kernel modules
    for module in ${GUARDIAN_REQUIRED_MODULES}; do
        if ! kldstat -n "${module}" >/dev/null 2>&1; then
            log "ERROR" "Required kernel module not loaded: ${module}"
            return 1
        fi
    done

    return 0
}

check_resource_usage() {
    local resource="$1"
    local threshold="$2"
    
    case "${resource}" in
        cpu)
            local usage=$(top -b -n 1 | grep "CPU:" | awk '{print $3}' | cut -d'.' -f1)
            ;;
        mem)
            local usage=$(top -b -n 1 | grep "Mem:" | awk '{print $3}' | cut -d'.' -f1)
            ;;
        io)
            local usage=$(iostat -c 1 | tail -n 1 | awk '{print $1}')
            ;;
        *)
            log "ERROR" "Unknown resource type: ${resource}"
            return 1
            ;;
    esac

    if [ "${usage}" -gt "${threshold}" ]; then
        log "WARNING" "${resource} usage (${usage}%) exceeds threshold (${threshold}%)"
        return 1
    fi

    return 0
}

check_capsicum_status() {
    local retry_count=0
    local status=1

    while [ ${retry_count} -lt ${GUARDIAN_MAX_RETRIES} ]; do
        # Check if Capsicum is enabled in kernel
        if ! sysctl security.capability_mode >/dev/null 2>&1; then
            log "ERROR" "Capsicum capability mode not available in kernel"
            return 1
        fi

        # Check resource usage before proceeding
        if ! check_resource_usage "cpu" "${cpu_max}"; then
            log "WARNING" "High CPU usage during Capsicum check"
            sleep 5
            retry_count=$((retry_count + 1))
            continue
        fi

        # Verify capability mode for Guardian processes
        for pid in $(pgrep -f "guardian_"); do
            if ! procstat -c ${pid} | grep -q "capability_mode"; then
                log "ERROR" "Process ${pid} not in capability mode"
                audit_log "CAPSICUM_CHECK" "FAIL: Process ${pid} not sandboxed"
                return 1
            fi
        done

        status=0
        break
    done

    [ ${status} -eq 0 ] && audit_log "CAPSICUM_CHECK" "SUCCESS: All processes verified"
    return ${status}
}

check_mac_policy() {
    local policy_baseline="$1"
    local timeout="$2"
    local start_time=$(date +%s)

    # Monitor system resources
    while true; do
        current_time=$(date +%s)
        [ $((current_time - start_time)) -gt ${timeout} ] && {
            log "ERROR" "MAC policy check timeout"
            return 1
        }

        # Check resource usage
        if ! check_resource_usage "cpu" "${cpu_max}" || \
           ! check_resource_usage "mem" "${mem_max}"; then
            sleep 5
            continue
        fi

        # Verify MAC module status
        if ! kldstat -n mac_guardian >/dev/null 2>&1; then
            log "ERROR" "Guardian MAC module not loaded"
            audit_log "MAC_CHECK" "FAIL: Module not loaded"
            return 1
        fi

        # Validate MAC policy rules
        if ! diff -q "${policy_baseline}" /etc/mac.conf >/dev/null 2>&1; then
            log "ERROR" "MAC policy configuration mismatch"
            audit_log "MAC_CHECK" "FAIL: Policy mismatch"
            return 1
        fi

        # Verify policy enforcement
        if [ $(sysctl -n security.mac.enforce) -ne 1 ]; then
            log "ERROR" "MAC policy enforcement disabled"
            audit_log "MAC_CHECK" "FAIL: Enforcement disabled"
            return 1
        fi

        audit_log "MAC_CHECK" "SUCCESS: Policy validated"
        return 0
    done
}

check_geli_encryption() {
    # Verify GELI providers
    local providers=$(geom eli list | grep "geli/" | wc -l)
    if [ ${providers} -eq 0 ]; then
        log "ERROR" "No active GELI providers found"
        audit_log "GELI_CHECK" "FAIL: No providers"
        return 1
    fi

    # Check each provider's status
    geom eli list | grep "geli/" | while read provider; do
        if ! geom eli status "${provider}" | grep -q "State: ACTIVE"; then
            log "ERROR" "GELI provider ${provider} not active"
            audit_log "GELI_CHECK" "FAIL: Provider ${provider} inactive"
            return 1
        fi
    done

    audit_log "GELI_CHECK" "SUCCESS: All providers verified"
    return 0
}

check_jail_isolation() {
    # Verify jail configurations
    if ! jls >/dev/null 2>&1; then
        log "ERROR" "Jail subsystem not available"
        return 1
    fi

    # Check each Guardian jail
    jls | grep "guardian_" | while read jail; do
        # Verify resource limits
        if ! rctl -h jail:${jail} >/dev/null 2>&1; then
            log "ERROR" "Resource limits not set for jail ${jail}"
            audit_log "JAIL_CHECK" "FAIL: No resource limits for ${jail}"
            return 1
        fi

        # Verify network isolation
        if ! jexec ${jail} netstat -an | grep -q "127.0.0.1"; then
            log "ERROR" "Network isolation issue in jail ${jail}"
            audit_log "JAIL_CHECK" "FAIL: Network isolation breach in ${jail}"
            return 1
        fi
    done

    audit_log "JAIL_CHECK" "SUCCESS: All jails verified"
    return 0
}

main() {
    local start_time=$(date +%s)
    local status=0

    # Initialize logging
    mkdir -p $(dirname "${LOG_FILE}") $(dirname "${AUDIT_FILE}")
    chmod 600 "${LOG_FILE}" "${AUDIT_FILE}"

    log "INFO" "Starting Guardian security check"
    audit_log "SECURITY_CHECK" "START"

    # Check prerequisites
    if ! check_prerequisites; then
        log "ERROR" "Prerequisites check failed"
        exit 1
    fi

    # Parse resource thresholds
    eval ${GUARDIAN_RESOURCE_THRESHOLDS}

    # Run security checks
    for check in ${GUARDIAN_SECURITY_CHECKS}; do
        log "INFO" "Running ${check} check"
        
        case "${check}" in
            capsicum)
                check_capsicum_status || status=1
                ;;
            mac)
                check_mac_policy "/etc/security/baseline.conf" ${GUARDIAN_CHECK_TIMEOUT} || status=1
                ;;
            geli)
                check_geli_encryption || status=1
                ;;
            jail)
                check_jail_isolation || status=1
                ;;
            *)
                log "WARNING" "Unknown security check: ${check}"
                ;;
        esac
    done

    # Log completion
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    if [ ${status} -eq 0 ]; then
        log "INFO" "Security check completed successfully (${duration}s)"
        audit_log "SECURITY_CHECK" "COMPLETE:SUCCESS:${duration}"
    else
        log "ERROR" "Security check failed (${duration}s)"
        audit_log "SECURITY_CHECK" "COMPLETE:FAIL:${duration}"
    fi

    return ${status}
}

main "$@"