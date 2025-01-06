#!/bin/sh

# Guardian System - Secure Module Build Script
# Version: 1.0.0
# FreeBSD Version: 13.0+
# 
# This script builds FreeBSD kernel modules for the Guardian system with
# enhanced security features including module signing, TPM verification,
# and comprehensive build validation.

# Exit on any error
set -e

# Build configuration
KERNEL_SRC="${KERNEL_SRC:-/usr/src/sys}"
MODULES_DIR="${MODULES_DIR:-/boot/modules}"
BUILD_FLAGS="${BUILD_FLAGS:--DGUARDIAN_DEBUG -O2 -fstack-protector-strong -D_FORTIFY_SOURCE=2}"
SIGN_KEY="${SIGN_KEY:-/etc/guardian/keys/module.key}"
TPM_PCR="${TPM_PCR:-7}"
MAX_PARALLEL_JOBS="${MAX_PARALLEL_JOBS:-$(nproc)}"
BUILD_TIMEOUT="${BUILD_TIMEOUT:-3600}"
RESOURCE_LIMITS="${RESOURCE_LIMITS:-ulimit -v 4194304}"

# Module paths
GUARDIAN_CORE="src/kernel/Makefile"
GUARDIAN_UTILS="src/utils/Makefile"
GUARDIAN_HARDWARE="src/hardware/Makefile"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Logging function
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

error() {
    echo "${RED}[ERROR] $1${NC}" >&2
}

warn() {
    echo "${YELLOW}[WARNING] $1${NC}" >&2
}

success() {
    echo "${GREEN}[SUCCESS] $1${NC}"
}

# Check build requirements
check_requirements() {
    log "Checking build requirements..."
    
    # Check FreeBSD version
    if [ "$(uname -s)" != "FreeBSD" ]; then
        error "This script must be run on FreeBSD"
        exit 1
    fi
    
    # Check FreeBSD version (13.0+)
    if [ "$(uname -r | cut -d'.' -f1)" -lt 13 ]; then
        error "FreeBSD 13.0 or higher required"
        exit 1
    }
    
    # Check for required tools
    for tool in make kldxref openssl tpm-tools; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            error "Required tool not found: $tool"
            exit 1
        fi
    done
    
    # Check for kernel sources
    if [ ! -d "$KERNEL_SRC" ]; then
        error "Kernel sources not found in $KERNEL_SRC"
        exit 1
    }
    
    # Check for signing key
    if [ ! -f "$SIGN_KEY" ]; then
        error "Module signing key not found: $SIGN_KEY"
        exit 1
    }
    
    # Verify TPM availability
    if ! tpm-tools status >/dev/null 2>&1; then
        warn "TPM not available - module verification will be limited"
    fi
}

# Build kernel modules with security enhancements
build_kernel_modules() {
    log "Building Guardian kernel modules..."
    
    # Set resource limits
    eval "$RESOURCE_LIMITS"
    
    # Create build manifest
    BUILD_MANIFEST="build_$(date +%Y%m%d_%H%M%S).manifest"
    {
        echo "Guardian System Build Manifest"
        echo "Build Time: $(date)"
        echo "FreeBSD Version: $(uname -r)"
        echo "Build Flags: $BUILD_FLAGS"
    } > "$BUILD_MANIFEST"
    
    # Build core module
    log "Building core module..."
    if ! make -C "$GUARDIAN_CORE" \
        CFLAGS="$BUILD_FLAGS" \
        -j"$MAX_PARALLEL_JOBS" \
        all; then
        error "Core module build failed"
        exit 1
    fi
    
    # Build utility module
    log "Building utility module..."
    if ! make -C "$GUARDIAN_UTILS" \
        CFLAGS="$BUILD_FLAGS" \
        -j"$MAX_PARALLEL_JOBS" \
        all; then
        error "Utility module build failed"
        exit 1
    fi
    
    # Build hardware module
    log "Building hardware module..."
    if ! make -C "$GUARDIAN_HARDWARE" \
        CFLAGS="$BUILD_FLAGS" \
        -j"$MAX_PARALLEL_JOBS" \
        all; then
        error "Hardware module build failed"
        exit 1
    fi
}

# Install modules with verification
install_modules() {
    log "Installing Guardian modules..."
    
    # Create secure installation directory
    install -d -m 700 "$MODULES_DIR"
    
    # Install and verify each module
    for module in guardian.ko guardian_utils.ko guardian_hardware.ko; do
        # Sign module
        log "Signing module: $module"
        openssl dgst -sha256 -sign "$SIGN_KEY" \
            -out "${module}.sig" "$module"
            
        # Calculate TPM measurement
        if command -v tpm-tools >/dev/null 2>&1; then
            log "Calculating TPM measurement for $module"
            tpm-tools extend -ix "$TPM_PCR" -if "$module" \
                -v > "${module}.tpm"
        fi
        
        # Install module with secure permissions
        install -m 600 "$module" "$MODULES_DIR/"
        install -m 600 "${module}.sig" "$MODULES_DIR/"
        
        # Verify installation
        if ! kldxref -v "$MODULES_DIR/$module" >/dev/null 2>&1; then
            error "Module verification failed: $module"
            exit 1
        fi
    done
    
    # Update module dependencies
    kldxref "$MODULES_DIR"
}

# Secure cleanup of build artifacts
cleanup() {
    log "Cleaning up build artifacts..."
    
    # Securely remove build artifacts
    for dir in "$GUARDIAN_CORE" "$GUARDIAN_UTILS" "$GUARDIAN_HARDWARE"; do
        if [ -d "$dir" ]; then
            make -C "$dir" clean >/dev/null 2>&1
        fi
    done
    
    # Remove temporary files
    find . -type f \( -name "*.o" -o -name "*.ko" -o -name "*.sig" \) \
        -exec rm -P {} \;
        
    # Clear sensitive memory
    sync
    echo 3 > /proc/sys/vm/drop_caches 2>/dev/null || true
}

# Main build process
main() {
    log "Starting Guardian module build process..."
    
    # Check requirements
    check_requirements
    
    # Build modules
    build_kernel_modules
    
    # Install modules
    install_modules
    
    # Cleanup
    cleanup
    
    success "Guardian module build completed successfully"
}

# Run with timeout protection
timeout "$BUILD_TIMEOUT" main
exit_code=$?

if [ $exit_code -eq 124 ]; then
    error "Build process timed out after $BUILD_TIMEOUT seconds"
    cleanup
    exit 1
elif [ $exit_code -ne 0 ]; then
    error "Build process failed with exit code $exit_code"
    cleanup
    exit $exit_code
fi

exit 0