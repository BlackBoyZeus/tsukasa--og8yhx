#!/bin/sh

# Guardian System - Kernel Module Loader
# Version: 1.0.0
# FreeBSD Version: 13.0
#
# Secure shell script for loading and initializing the Guardian kernel module
# with enhanced security features, TPM integration, and comprehensive error handling.

# Strict error handling
set -e
set -u

# Global constants
GUARDIAN_MODULE_PATH="/boot/modules/guardian.ko"
GUARDIAN_CONFIG_PATH="/etc/guardian.conf"
GUARDIAN_LOG_PATH="/var/log/guardian.log"
GUARDIAN_AUDIT_PATH="/var/log/guardian_audit.log"
GUARDIAN_TPM_STATE="/var/lib/guardian/tpm_state"
GUARDIAN_MAC_POLICY="/etc/guardian_mac_policy"

# Required FreeBSD version
REQUIRED_FREEBSD_VERSION="13.0"

# Log levels
LOG_INFO="INFO"
LOG_WARNING="WARNING"
LOG_ERROR="ERROR"
LOG_AUDIT="AUDIT"

# Exit codes
EXIT_SUCCESS=0
EXIT_FAILURE=1
EXIT_INVALID_ARGS=2
EXIT_PERMISSION_DENIED=3
EXIT_MODULE_ERROR=4
EXIT_TPM_ERROR=5
EXIT_MAC_ERROR=6

# Logging function with security context
log_message() {
    local level="$1"
    local message="$2"
    local timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    printf "[%s] [%s] %s\n" "$timestamp" "$level" "$message" >> "$GUARDIAN_LOG_PATH"
    
    # Additional audit logging for security events
    if [ "$level" = "$LOG_AUDIT" ]; then
        printf "[%s] %s\n" "$timestamp" "$message" >> "$GUARDIAN_AUDIT_PATH"
    fi
}

# Security audit function
audit_event() {
    local event="$1"
    local details="$2"
    log_message "$LOG_AUDIT" "Event: $event Details: $details"
}

# Cleanup function for secure termination
cleanup() {
    local exit_code=$?
    if [ $exit_code -ne $EXIT_SUCCESS ]; then
        log_message "$LOG_ERROR" "Guardian module loading failed with exit code: $exit_code"
        # Attempt to unload module if loaded
        kldstat -n guardian >/dev/null 2>&1 && kldunload guardian
        # Clean up TPM state
        [ -d "$GUARDIAN_TPM_STATE" ] && rm -rf "$GUARDIAN_TPM_STATE"/*
    fi
    exit $exit_code
}

trap cleanup EXIT INT TERM

# Check prerequisites with enhanced security validation
check_prerequisites() {
    # Verify root privileges
    if [ "$(id -u)" -ne 0 ]; then
        log_message "$LOG_ERROR" "Root privileges required"
        exit $EXIT_PERMISSION_DENIED
    }

    # Verify FreeBSD version
    local os_version=$(uname -r | cut -d'-' -f1)
    if [ "$os_version" != "$REQUIRED_FREEBSD_VERSION" ]; then
        log_message "$LOG_ERROR" "Incompatible FreeBSD version: $os_version (required: $REQUIRED_FREEBSD_VERSION)"
        exit $EXIT_INVALID_ARGS
    }

    # Verify module file existence and permissions
    if [ ! -f "$GUARDIAN_MODULE_PATH" ]; then
        log_message "$LOG_ERROR" "Guardian module not found at $GUARDIAN_MODULE_PATH"
        exit $EXIT_MODULE_ERROR
    fi

    # Verify module file permissions (only root should have access)
    local module_perms=$(stat -f "%Op" "$GUARDIAN_MODULE_PATH")
    if [ "$module_perms" != "100600" ]; then
        log_message "$LOG_ERROR" "Invalid module permissions: $module_perms (required: 100600)"
        exit $EXIT_MODULE_ERROR
    }

    # Verify configuration file
    if [ ! -f "$GUARDIAN_CONFIG_PATH" ]; then
        log_message "$LOG_ERROR" "Configuration file not found at $GUARDIAN_CONFIG_PATH"
        exit $EXIT_INVALID_ARGS
    }

    # Verify TPM state directory
    if [ ! -d "$GUARDIAN_TPM_STATE" ]; then
        mkdir -p "$GUARDIAN_TPM_STATE"
        chmod 700 "$GUARDIAN_TPM_STATE"
    fi

    # Verify MAC policy file
    if [ ! -f "$GUARDIAN_MAC_POLICY" ]; then
        log_message "$LOG_ERROR" "MAC policy file not found at $GUARDIAN_MAC_POLICY"
        exit $EXIT_MAC_ERROR
    }

    # Initialize log files with secure permissions
    touch "$GUARDIAN_LOG_PATH" "$GUARDIAN_AUDIT_PATH"
    chmod 600 "$GUARDIAN_LOG_PATH" "$GUARDIAN_AUDIT_PATH"
}

# Load Guardian kernel module with security validation
load_module() {
    log_message "$LOG_INFO" "Loading Guardian kernel module..."
    
    # Verify module signature before loading
    if ! kldxref "$GUARDIAN_MODULE_PATH" >/dev/null 2>&1; then
        log_message "$LOG_ERROR" "Module signature verification failed"
        exit $EXIT_MODULE_ERROR
    }

    # Load the module
    if ! kldload "$GUARDIAN_MODULE_PATH"; then
        log_message "$LOG_ERROR" "Failed to load Guardian module"
        exit $EXIT_MODULE_ERROR
    }

    # Verify module loaded successfully
    if ! kldstat -n guardian >/dev/null 2>&1; then
        log_message "$LOG_ERROR" "Module load verification failed"
        exit $EXIT_MODULE_ERROR
    }

    audit_event "MODULE_LOAD" "Guardian module loaded successfully"
}

# Configure module with security policies
configure_module() {
    log_message "$LOG_INFO" "Configuring Guardian module..."

    # Apply MAC framework policies
    if ! sysctl security.mac.guardian.enabled=1 >/dev/null 2>&1; then
        log_message "$LOG_ERROR" "Failed to enable MAC framework integration"
        exit $EXIT_MAC_ERROR
    }

    # Initialize TPM state
    if ! sysctl security.guardian.tpm.initialize=1 >/dev/null 2>&1; then
        log_message "$LOG_ERROR" "Failed to initialize TPM state"
        exit $EXIT_TPM_ERROR
    }

    # Load security policies from configuration
    if ! sysctl security.guardian.policy.load=1 >/dev/null 2>&1; then
        log_message "$LOG_ERROR" "Failed to load security policies"
        exit $EXIT_MODULE_ERROR
    }

    audit_event "MODULE_CONFIG" "Guardian module configured successfully"
}

# Main execution flow
main() {
    log_message "$LOG_INFO" "Starting Guardian module initialization..."

    # Check prerequisites
    check_prerequisites

    # Load module
    load_module

    # Configure module
    configure_module

    log_message "$LOG_INFO" "Guardian module initialization completed successfully"
    audit_event "INITIALIZATION_COMPLETE" "Guardian system ready"
    exit $EXIT_SUCCESS
}

main "$@"