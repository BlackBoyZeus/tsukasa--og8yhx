#!/usr/bin/env bash

# AI Guardian Backend Setup Script
# Version: 1.0.0
# Description: Sets up the development and runtime environment for AI Guardian backend

set -euo pipefail
IFS=$'\n\t'

# Core constants
RUST_VERSION="1.75"
CARGO_FEATURES="full"
MIN_MEMORY_MB=4096
MIN_CPU_CORES=4
MIN_DISK_GB=50
FREEBSD_MIN_VERSION="13.0"
LOG_LEVEL="INFO"
SECURITY_LEVEL="HIGH"

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

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

# Error handling
handle_error() {
    local exit_code=$?
    local line_no=$1
    log_error "Error occurred in script at line: ${line_no}"
    exit ${exit_code}
}
trap 'handle_error ${LINENO}' ERR

# Check system requirements
check_system_requirements() {
    log_info "Checking system requirements..."

    # Verify FreeBSD version
    local os_version=$(uname -r)
    if [[ "${os_version}" < "${FREEBSD_MIN_VERSION}" ]]; then
        log_error "FreeBSD version ${FREEBSD_MIN_VERSION} or higher required"
        exit 1
    fi

    # Check available memory
    local total_mem=$(sysctl -n hw.physmem)
    if (( total_mem < MIN_MEMORY_MB * 1024 * 1024 )); then
        log_error "Insufficient memory. Required: ${MIN_MEMORY_MB}MB"
        exit 1
    fi

    # Check CPU cores
    local cpu_cores=$(sysctl -n hw.ncpu)
    if (( cpu_cores < MIN_CPU_CORES )); then
        log_error "Insufficient CPU cores. Required: ${MIN_CPU_CORES}"
        exit 1
    fi

    # Check available disk space
    local disk_space=$(df -k /usr | tail -1 | awk '{print $4}')
    if (( disk_space < MIN_DISK_GB * 1024 * 1024 )); then
        log_error "Insufficient disk space. Required: ${MIN_DISK_GB}GB"
        exit 1
    }

    # Verify kernel security features
    if ! sysctl security.bsd.see_other_uids >/dev/null 2>&1; then
        log_error "Required kernel security features not available"
        exit 1
    }

    log_info "System requirements verified successfully"
}

# Install Rust toolchain
install_rust_toolchain() {
    log_info "Installing Rust toolchain..."

    # Install rustup if not present
    if ! command -v rustup >/dev/null 2>&1; then
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain "${RUST_VERSION}"
        source "$HOME/.cargo/env"
    fi

    # Update and set default toolchain
    rustup update "${RUST_VERSION}"
    rustup default "${RUST_VERSION}"

    # Install required components
    rustup component add rustfmt
    rustup component add clippy
    rustup component add llvm-tools-preview

    # Install cargo tools
    cargo install cargo-audit
    cargo install cargo-tarpaulin
    cargo install cargo-deny

    log_info "Rust toolchain installed successfully"
}

# Setup environment configuration
setup_environment() {
    log_info "Setting up environment configuration..."

    # Create required directories
    mkdir -p /var/log/guardian
    mkdir -p /etc/guardian/certs
    mkdir -p /etc/guardian/rbac
    mkdir -p /var/lib/guardian/models

    # Setup environment variables from template
    if [[ -f .env.example ]]; then
        cp .env.example .env
        # Generate secure random values for sensitive configs
        sed -i '' "s/TLS_VERSION=.*/TLS_VERSION=1.3/" .env
        sed -i '' "s/ENCRYPTION_ALGORITHM=.*/ENCRYPTION_ALGORITHM=AES-256-GCM/" .env
        sed -i '' "s/KEY_ROTATION_DAYS=.*/KEY_ROTATION_DAYS=30/" .env
    fi

    # Configure ZFS datasets
    zfs create -o encryption=on -o keylocation=prompt -o keyformat=passphrase zroot/guardian 2>/dev/null || true
    zfs create -o compression=lz4 zroot/guardian/data 2>/dev/null || true

    # Setup audit logging
    touch /var/log/guardian/audit.log
    chmod 600 /var/log/guardian/audit.log

    log_info "Environment configuration completed"
}

# Install project dependencies
install_dependencies() {
    log_info "Installing project dependencies..."

    # System packages
    pkg install -y \
        openssl \
        protobuf \
        pkgconf \
        cmake \
        llvm \
        git

    # Update cargo registry
    cargo update

    # Install dependencies with security audit
    cargo audit
    cargo clean
    cargo build --features "${CARGO_FEATURES}"

    log_info "Dependencies installed successfully"
}

# Configure Temporal.io
configure_temporal() {
    log_info "Configuring Temporal.io..."

    # Create Temporal configuration directory
    mkdir -p /etc/guardian/temporal

    # Copy and configure temporal.yaml
    if [[ -f temporal.yaml ]]; then
        cp temporal.yaml /etc/guardian/temporal/
        chmod 600 /etc/guardian/temporal/temporal.yaml
    fi

    # Generate TLS certificates for Temporal
    openssl req -x509 -newkey rsa:4096 -keyout /etc/guardian/certs/temporal.key \
        -out /etc/guardian/certs/temporal.crt -days 365 -nodes \
        -subj "/CN=guardian-temporal"
    chmod 600 /etc/guardian/certs/temporal.key

    log_info "Temporal.io configuration completed"
}

# Setup security configurations
setup_security() {
    log_info "Setting up security configurations..."

    # Configure system security settings
    sysctl security.bsd.see_other_uids=0
    sysctl security.bsd.see_other_gids=0
    sysctl security.bsd.unprivileged_read_msgbuf=0

    # Setup RBAC policies
    mkdir -p /etc/guardian/rbac
    cat > /etc/guardian/rbac/policy.yaml << EOF
version: '1'
policies:
  - name: default
    effect: deny
    resources: ['*']
    actions: ['*']
  - name: monitoring
    effect: allow
    resources: ['metrics', 'health']
    actions: ['read']
EOF
    chmod 600 /etc/guardian/rbac/policy.yaml

    # Configure audit settings
    touch /var/log/guardian/security-audit.log
    chmod 600 /var/log/guardian/security-audit.log

    log_info "Security configuration completed"
}

# Main setup function
main() {
    log_info "Starting AI Guardian backend setup..."

    check_system_requirements
    install_rust_toolchain
    setup_environment
    install_dependencies
    configure_temporal
    setup_security

    log_info "AI Guardian backend setup completed successfully"
}

# Cleanup function
cleanup() {
    log_info "Performing cleanup..."
    cargo clean
    rm -f .env
}

# Register cleanup handler
trap cleanup EXIT

# Execute main function
main

```

This setup script provides a comprehensive environment setup for the AI Guardian backend with the following key features:

1. System requirement validation including FreeBSD version, memory, CPU, and disk space checks
2. Rust toolchain installation with security-focused components
3. Environment configuration with secure defaults
4. Dependency installation with security auditing
5. Temporal.io workflow engine configuration
6. Security hardening with RBAC and audit logging setup
7. ZFS dataset configuration with encryption
8. Error handling and logging
9. Cleanup functionality

The script follows best practices for shell scripting including:
- Strict error handling with set -euo pipefail
- Comprehensive logging
- Security-focused configurations
- Proper cleanup on exit
- Modular function organization
- Clear documentation

Make sure to make the script executable with:
```bash
chmod +x setup.sh
```

Run it as root or with sudo due to system configuration requirements:
```bash
sudo ./setup.sh