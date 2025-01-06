# Guardian System Kernel Module Makefile
# FreeBSD 13.0 Kernel Module Build System
# Version: 1.0.0
# Security Level: High

.include <bsd.kmod.mk>

# Module name and source files
KMOD=		guardian
SRCS=		guardian_module.c \
		memory_protection.c \
		secure_boot.c \
		tpm_driver.c \
		hsm_driver.c

# Compiler security flags
CFLAGS+=	-O2 \
		-fstack-protector-strong \
		-D_FORTIFY_SOURCE=2 \
		-fPIE \
		-fstack-clash-protection \
		-fcf-protection=full \
		-DGUARDIAN_DEBUG \
		-DGUARDIAN_SECURE_BOOT \
		-DKLD_MODULE_VERSIONING \
		-I${.CURDIR}/../include

# Warning and error flags
WARNS=		2
NO_WERROR=	

# Debug flags for comprehensive debugging
DEBUG_FLAGS=	-g3 -gdwarf-4

# Module signing configuration
SIGN_KEY=	/secure/keys/guardian-kmod.key
SIGN_METHOD=	sha512

# Secure build targets
.PHONY: all clean install sign verify

# Primary build target with security validations
all: verify_env
	@echo "Building Guardian kernel module with security controls..."
	@${MAKE} clean
	@${MAKE} guardian.ko
	@${MAKE} sign
	@${MAKE} verify

# Environment security verification
verify_env:
	@echo "Verifying build environment security..."
	@test -f ${SIGN_KEY} || (echo "ERROR: Signing key not found"; exit 1)
	@test `stat -f "%Lp" ${.CURDIR}` -eq 700 || \
		(echo "ERROR: Insecure directory permissions"; exit 1)

# Secure cleanup
clean:
	@echo "Securely cleaning build artifacts..."
	@rm -P *.o *.ko *.ko.debug .depend* *.sig 2>/dev/null || true
	@rm -Prf .deps
	@sync

# Secure installation with proper permissions
install: verify sign
	@echo "Installing Guardian kernel module..."
	@test -d /boot/modules || mkdir -m 755 /boot/modules
	@install -m 600 -o root -g wheel guardian.ko /boot/modules/
	@install -m 600 -o root -g wheel guardian.ko.sig /boot/modules/
	@if [ -f guardian.ko.debug ]; then \
		install -m 600 -o root -g wheel guardian.ko.debug \
			/usr/lib/debug/boot/modules/; \
	fi
	@kldxref /boot/modules
	@echo "Updating TPM measurements..."
	@sh -c 'tpm2_extend -ix 4 -ih `sha256 -q guardian.ko`'

# Module signing using HSM
sign: guardian.ko
	@echo "Signing kernel module using HSM..."
	@if [ -x /usr/local/bin/hsm-sign ]; then \
		/usr/local/bin/hsm-sign -k ${SIGN_KEY} \
			-m ${SIGN_METHOD} guardian.ko; \
	else \
		echo "ERROR: HSM signing tool not found"; \
		exit 1; \
	fi

# Signature verification
verify: guardian.ko guardian.ko.sig
	@echo "Verifying module signature..."
	@if [ -x /usr/local/bin/hsm-verify ]; then \
		/usr/local/bin/hsm-verify -k ${SIGN_KEY}.pub \
			-m ${SIGN_METHOD} guardian.ko; \
	else \
		echo "ERROR: HSM verification tool not found"; \
		exit 1; \
	fi

# Build-time security checks
.for src in ${SRCS}
${src}: verify_source_${src}

verify_source_${src}:
	@echo "Verifying source file integrity: ${src}"
	@test -f ${.CURDIR}/${src} || \
		(echo "ERROR: Source file ${src} not found"; exit 1)
	@test `stat -f "%Lp" ${.CURDIR}/${src}` -eq 600 || \
		(echo "ERROR: Insecure source file permissions: ${src}"; exit 1)
.endfor

# Dependency generation with security validation
.depend: ${SRCS}
	@echo "Generating secure dependencies..."
	@rm -f .depend
	@mkdep -a ${CFLAGS} ${SRCS}

# Load/unload targets for testing (restricted to secure environments)
load: verify
	@if [ `sysctl -n security.guardian.secure_mode` = "1" ]; then \
		kldload /boot/modules/guardian.ko; \
	else \
		echo "ERROR: System not in secure mode"; \
		exit 1; \
	fi

unload:
	@kldunload guardian || true