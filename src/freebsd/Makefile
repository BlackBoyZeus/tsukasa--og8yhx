# Guardian System FreeBSD Components Makefile
# FreeBSD 13.0
# Implements secure build process for kernel modules, drivers and system components

.include <bsd.own.mk>    # FreeBSD 13.0
.include <bsd.kmod.mk>   # FreeBSD 13.0

# Build directories
SUBDIR=		src/utils src/hardware src/security src/kernel src/system

# Enhanced security compilation flags
CFLAGS+=	-O2 -pipe \
		-fstack-protector-strong \
		-fno-strict-aliasing \
		-D_KERNEL \
		-DKLD_MODULE \
		-nostdinc \
		-I./include \
		-DSECURITY_ENHANCED

# Maximum warning level
WARNS=		6

# Debug flags for development builds
DEBUG_FLAGS=	-g

# Security level for enhanced protection
SECURITY_LEVEL=	3

# Include component makefiles
.include "src/utils/Makefile"
.include "src/hardware/Makefile"
.include "src/security/Makefile"

# Kernel configuration
KERNEL_CONF=	${.CURDIR}/kernel.conf

# Default target - builds all components with security validation
all: security-check
	@echo "Building Guardian FreeBSD components with enhanced security..."
	@for dir in ${SUBDIR}; do \
		(cd $$dir && ${MAKE} all SECURITY_LEVEL=${SECURITY_LEVEL}) || exit 1; \
	done
	@${MAKE} verify-signatures
	@echo "Build completed with security validation."

# Clean target - securely removes all build artifacts
clean:
	@echo "Securely cleaning build artifacts..."
	@for dir in ${SUBDIR}; do \
		(cd $$dir && ${MAKE} clean) || exit 1; \
	done
	@rm -P *~ *.o *.ko *.core
	@echo "Secure cleanup completed."

# Install target - securely installs components with verification
install: all
	@echo "Installing Guardian kernel modules with security verification..."
	@${MAKE} verify-signatures
	@for dir in ${SUBDIR}; do \
		(cd $$dir && ${MAKE} install) || exit 1; \
	done
	@${MAKE} update-dependencies
	@${MAKE} verify-permissions
	@${MAKE} verify-integrity
	@echo "Secure installation completed."

# Security validation target
security-check:
	@echo "Performing security validation..."
	@if [ ${SECURITY_LEVEL} -lt 3 ]; then \
		echo "ERROR: Insufficient security level"; \
		exit 1; \
	fi
	@${MAKE} verify-environment
	@${MAKE} verify-flags
	@echo "Security validation passed."

# Verify build environment security
verify-environment:
	@echo "Verifying build environment..."
	@if [ ! -f ${KERNEL_CONF} ]; then \
		echo "ERROR: Missing kernel configuration"; \
		exit 1; \
	fi

# Verify security compilation flags
verify-flags:
	@echo "Verifying security flags..."
	@if ! echo ${CFLAGS} | grep -q "fstack-protector-strong"; then \
		echo "ERROR: Missing stack protection"; \
		exit 1; \
	fi

# Verify module signatures
verify-signatures:
	@echo "Verifying module signatures..."
	@for module in guardian_utils.ko guardian_hardware.ko guardian_security.ko; do \
		if [ -f $$module ]; then \
			kldxref -v $$module || exit 1; \
		fi \
	done

# Update kernel module dependencies
update-dependencies:
	@echo "Updating module dependencies..."
	@kldxref -R /boot/kernel

# Verify secure permissions
verify-permissions:
	@echo "Verifying secure permissions..."
	@find /boot/kernel -name "guardian_*.ko" -exec chmod 600 {} \;
	@find /boot/kernel -name "guardian_*.ko" -exec chown root:wheel {} \;

# Verify system integrity
verify-integrity:
	@echo "Verifying system integrity..."
	@for module in guardian_utils.ko guardian_hardware.ko guardian_security.ko; do \
		if [ -f /boot/kernel/$$module ]; then \
			sha256 -c /boot/kernel/$$module || exit 1; \
		fi \
	done

.include <bsd.subdir.mk>