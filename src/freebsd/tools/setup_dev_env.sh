#!/bin/sh

# Guardian System - Development Environment Setup Script
# Version: 1.0.0
# FreeBSD Version: 13.0
#
# Sets up the FreeBSD development environment for the Guardian gaming console system
# with enhanced security features, TPM integration, and comprehensive validation.

# Exit on error, undefined variables
set -e
set -u

# Source required scripts
. ./build_modules.sh
. ./security_check.sh

# Global configuration
DEV_ROOT="/usr/src/guardian"
REQUIRED_PACKAGES="rust llvm cmake ninja protobuf git tpm2-tools audit secadm"
KERNEL_SRC="/usr/src/sys"
DEBUG_MODE="true"
MAX_MEMORY="8192"
MIN_DISK_SPACE="20480"
LOG_FILE="/var/log/guardian/setup.log"
BACKUP_DIR="/var/backup/guardian"
SECURITY_POLICY_VERSION="1.2.0"

# Logging function with timestamps
log() {
    local level="$1"
    local message="$2"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "${timestamp} [${level}] ${message}" >> "${LOG_FILE}"
    [ "${level}" = "ERROR" ] && echo "${timestamp} [${level}] ${message}" >&2
}

# Verify root access and security context
check_root_access() {
    if [ "$(id -u)" -ne 0 ]; then
        log "ERROR" "This script must be run as root"
        return 1
    fi

    # Verify TPM availability
    if ! command -v tpm2_getcap >/dev/null 2>&1; then
        log "ERROR" "TPM support not available"
        return 2
    fi

    # Verify audit subsystem
    if ! service auditd status >/dev/null 2>&1; then
        log "ERROR" "Audit subsystem not running"
        return 2
    }

    return 0
}

# Install and validate required development tools
install_dependencies() {
    log "INFO" "Installing required packages..."

    # Update package repository with signature verification
    env SIGNATURE_TYPE=fingerprint \
        FINGERPRINT="$(/usr/local/etc/pkg/fingerprints/FreeBSD/trusted/pkg.freebsd.org.2013102301)" \
        pkg update -f

    # Install required packages
    for package in ${REQUIRED_PACKAGES}; do
        if ! pkg info -e "${package}"; then
            pkg install -y "${package}"
            
            # Verify package signature
            if ! pkg check -s "${package}"; then
                log "ERROR" "Package signature verification failed: ${package}"
                return 1
            fi
        fi
    done

    # Configure development tools with security policies
    if ! check_capsicum_status; then
        log "ERROR" "Capsicum security configuration failed"
        return 1
    fi

    return 0
}

# Setup kernel source with security hardening
setup_kernel_source() {
    log "INFO" "Setting up kernel source..."

    # Create development directories
    mkdir -p "${DEV_ROOT}"
    chmod 700 "${DEV_ROOT}"

    # Configure kernel build environment
    cat > "${DEV_ROOT}/kernel.conf" << EOF
# Guardian System Kernel Configuration
options     GUARDIAN_SECURITY
options     MAC
options     AUDIT
options     CAPABILITY_MODE
options     INVARIANTS
options     INVARIANT_SUPPORT
options     WITNESS
options     WITNESS_SKIPSPIN
EOF

    # Setup secure module signing
    if [ ! -f "${DEV_ROOT}/module.key" ]; then
        openssl genrsa -out "${DEV_ROOT}/module.key" 4096
        chmod 400 "${DEV_ROOT}/module.key"
    fi

    # Initialize TPM for module verification
    if ! tpm2_createprimary -C e -g sha256 -G rsa \
        -c "${DEV_ROOT}/tpm_primary.ctx"; then
        log "ERROR" "TPM initialization failed"
        return 1
    fi

    return 0
}

# Configure security development tools
configure_security_tools() {
    log "INFO" "Configuring security tools..."

    # Configure Capsicum development environment
    if ! sysctl security.capability_mode=1; then
        log "ERROR" "Failed to enable Capsicum capability mode"
        return 1
    fi

    # Setup MAC framework tools
    if ! kldload mac_guardian 2>/dev/null; then
        log "ERROR" "Failed to load Guardian MAC module"
        return 1
    fi

    # Configure audit development tools
    if ! service auditd onestatus >/dev/null 2>&1; then
        service auditd onestart
    fi

    # Initialize security baseline
    if ! check_mac_policy "/etc/security/baseline.conf" 300; then
        log "ERROR" "Security baseline configuration failed"
        return 1
    fi

    return 0
}

# Setup optimized build environment
setup_build_environment() {
    log "INFO" "Setting up build environment..."

    # Create build directories
    mkdir -p "${DEV_ROOT}/build"
    chmod 700 "${DEV_ROOT}/build"

    # Configure make environment
    cat > "${DEV_ROOT}/build/make.conf" << EOF
CFLAGS+=        -O2 -pipe -fstack-protector-strong -D_FORTIFY_SOURCE=2
CXXFLAGS+=      -O2 -pipe -fstack-protector-strong -D_FORTIFY_SOURCE=2
MAKE_JOBS_NUMBER?=      $(sysctl -n hw.ncpu)
WITH_DEBUG=     yes
WITH_MALLOC_PRODUCTION=yes
EOF

    # Setup build cache
    mkdir -p "${DEV_ROOT}/build/cache"
    chmod 700 "${DEV_ROOT}/build/cache"

    # Configure resource limits
    ulimit -v ${MAX_MEMORY}
    ulimit -n 4096

    return 0
}

# Main execution function
main() {
    local status=0

    # Initialize logging
    mkdir -p "$(dirname "${LOG_FILE}")"
    chmod 600 "${LOG_FILE}"

    log "INFO" "Starting Guardian development environment setup"

    # Check root access and security context
    if ! check_root_access; then
        log "ERROR" "Root access check failed"
        return 1
    fi

    # Create environment backup
    mkdir -p "${BACKUP_DIR}"
    chmod 700 "${BACKUP_DIR}"
    tar czf "${BACKUP_DIR}/env_backup_$(date +%Y%m%d_%H%M%S).tar.gz" \
        /etc/make.conf /etc/src.conf 2>/dev/null || true

    # Install dependencies
    if ! install_dependencies; then
        log "ERROR" "Failed to install dependencies"
        return 1
    fi

    # Setup kernel source
    if ! setup_kernel_source; then
        log "ERROR" "Failed to setup kernel source"
        return 1
    fi

    # Configure security tools
    if ! configure_security_tools; then
        log "ERROR" "Failed to configure security tools"
        return 1
    fi

    # Setup build environment
    if ! setup_build_environment; then
        log "ERROR" "Failed to setup build environment"
        return 1
    fi

    # Verify environment setup
    if ! check_requirements; then
        log "ERROR" "Environment verification failed"
        return 1
    fi

    log "INFO" "Guardian development environment setup completed successfully"
    return ${status}
}

# Execute main function with error handling
if ! main "$@"; then
    log "ERROR" "Setup failed"
    exit 1
fi

exit 0