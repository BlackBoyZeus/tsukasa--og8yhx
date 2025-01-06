#!/bin/sh
# AI Guardian Test Automation Script
# Version: 1.0.0
# Purpose: Enterprise-grade test automation for FreeBSD kernel modules
# Dependencies:
# - atf-sh (FreeBSD 13.0)
# - kyua (0.13)

set -e # Exit on error
set -u # Exit on undefined variables

# Global constants
readonly TEST_ROOT="/usr/local/tests/guardian"
readonly TEST_REPORT_DIR="/var/log/guardian/test_reports"
readonly EXIT_SUCCESS=0
readonly EXIT_FAILURE=1

# Test suite configuration from Makefile
. ../tests/Makefile

# Logging function with timestamp
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "${TEST_REPORT_DIR}/test_execution.log"
}

# Error handling function
handle_error() {
    local exit_code=$?
    local line_no=$1
    log "ERROR: Command failed at line ${line_no} with exit code ${exit_code}"
    cleanup
    exit "${EXIT_FAILURE}"
}

trap 'handle_error ${LINENO}' ERR

setup_test_environment() {
    log "Setting up test environment..."
    
    # Verify root privileges
    if [ "$(id -u)" -ne 0 ]; then
        log "ERROR: Root privileges required"
        exit "${EXIT_FAILURE}"
    }

    # Create test directories with secure permissions
    umask 077
    mkdir -p "${TEST_ROOT}" "${TEST_REPORT_DIR}"
    
    # Load required kernel modules with signature verification
    for module in guardian_module memory_protection capsicum; do
        if ! kldload -v "${module}" 2>/dev/null; then
            log "WARNING: Module ${module} already loaded or not found"
        fi
    done

    # Initialize test isolation jail
    jail -c name=guardian_test \
         path="${TEST_ROOT}/jail" \
         host.hostname=guardian_test \
         ip4.addr=127.0.1.1 \
         command=/bin/sh

    return "${EXIT_SUCCESS}"
}

run_kernel_tests() {
    log "Executing kernel test suite..."
    local retry_count=0
    local max_retries=3

    while [ ${retry_count} -lt ${max_retries} ]; do
        if kyua test --config=none \
            --build-root="${TEST_ROOT}/build" \
            --test-suite=guardian_kernel \
            --store="${TEST_REPORT_DIR}/kernel_results.db" \
            --timeout=300; then
            return "${EXIT_SUCCESS}"
        fi
        
        retry_count=$((retry_count + 1))
        log "Kernel tests failed, attempt ${retry_count}/${max_retries}"
        sleep 5
    done

    return "${EXIT_FAILURE}"
}

run_security_tests() {
    log "Executing security test suite..."
    
    # Run Capsicum capability tests
    kyua test --config=none \
        --build-root="${TEST_ROOT}/build" \
        --test-suite=guardian_security \
        --store="${TEST_REPORT_DIR}/security_results.db" \
        --timeout=300

    # Verify secure memory operations
    atf-sh ../tests/security/test_capsicum.c
    
    return "${EXIT_SUCCESS}"
}

run_hardware_tests() {
    log "Executing hardware integration tests..."
    
    # Test console driver functionality
    kyua test --config=none \
        --build-root="${TEST_ROOT}/build" \
        --test-suite=guardian_hardware \
        --store="${TEST_REPORT_DIR}/hardware_results.db" \
        --timeout=300

    return "${EXIT_SUCCESS}"
}

generate_report() {
    local report_type="$1"
    log "Generating ${report_type} test report..."

    case "${report_type}" in
        "html")
            kyua report-html \
                --store="${TEST_REPORT_DIR}/results.db" \
                --output="${TEST_REPORT_DIR}/html"
            ;;
        "junit")
            kyua report-junit \
                --store="${TEST_REPORT_DIR}/results.db" \
                --output="${TEST_REPORT_DIR}/junit.xml"
            ;;
        "json")
            kyua report-json \
                --store="${TEST_REPORT_DIR}/results.db" \
                --output="${TEST_REPORT_DIR}/results.json"
            ;;
        *)
            log "ERROR: Unknown report type: ${report_type}"
            return "${EXIT_FAILURE}"
            ;;
    esac

    return "${EXIT_SUCCESS}"
}

cleanup() {
    log "Performing secure cleanup..."

    # Securely remove temporary files
    find "${TEST_ROOT}" -type f -exec sh -c 'dd if=/dev/urandom of="${1}" bs=1k count=1 conv=notrunc >/dev/null 2>&1 && rm -f "${1}"' _ {} \;

    # Unload test kernel modules
    for module in guardian_module memory_protection capsicum; do
        if kldstat -n "${module}" >/dev/null 2>&1; then
            kldunload "${module}"
        fi
    done

    # Remove test jail
    jail -r guardian_test 2>/dev/null || true

    # Archive test results
    tar czf "${TEST_REPORT_DIR}/test_results_$(date +%Y%m%d_%H%M%S).tar.gz" \
        -C "${TEST_REPORT_DIR}" .

    log "Cleanup completed"
}

main() {
    local exit_status="${EXIT_SUCCESS}"

    log "Starting test execution..."

    if ! setup_test_environment; then
        log "ERROR: Failed to setup test environment"
        exit "${EXIT_FAILURE}"
    fi

    # Execute test suites
    if ! run_kernel_tests; then
        log "ERROR: Kernel tests failed"
        exit_status="${EXIT_FAILURE}"
    fi

    if ! run_security_tests; then
        log "ERROR: Security tests failed"
        exit_status="${EXIT_FAILURE}"
    fi

    if ! run_hardware_tests; then
        log "ERROR: Hardware tests failed"
        exit_status="${EXIT_FAILURE}"
    fi

    # Generate reports
    for report_type in html junit json; do
        if ! generate_report "${report_type}"; then
            log "ERROR: Failed to generate ${report_type} report"
            exit_status="${EXIT_FAILURE}"
        fi
    done

    cleanup

    log "Test execution completed with status: ${exit_status}"
    exit "${exit_status}"
}

main "$@"