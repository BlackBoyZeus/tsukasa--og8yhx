# Guardian System Kernel Module Makefile
# Version: 1.0.0
# Security-hardened build configuration for FreeBSD kernel module

.include <bsd.own.mk>

# Module name
KMOD=		guardian_system

# Source files
SRCS=		sysctl_handlers.c \
		resource_monitor.c \
		process_control.c \
		kenv_manager.c

# Include paths
CFLAGS+=	-I${.CURDIR}/../../include \
		-I${.CURDIR}/../utils

# Compiler optimization flags
CFLAGS+=	-O2 -g

# Warning flags - maximum warnings enabled
WARNS=		6
CFLAGS+=	-Wall -Wextra -Werror

# Security hardening flags
CFLAGS+=	-fstack-protector-strong \
		-D_FORTIFY_SOURCE=2 \
		-fPIE

# Linker security flags
LDFLAGS+=	-z now \
		-z relro \
		-pie

# Kernel module metadata
MAINTAINER=	guardian-security@example.com
VERSION=	1.0.0

# Build-time security checks
beforebuild: .PHONY
	@echo "Verifying build environment security..."
	@if [ ! -w ${.CURDIR} ]; then \
		echo "Error: Insecure build directory permissions"; \
		exit 1; \
	fi

# Custom clean target with secure file removal
clean: .PHONY
	@echo "Securely removing build artifacts..."
	rm -P ${PROG} ${OBJS} ${CLEANFILES} *.o *.ko *.d
	@echo "Clearing build cache..."
	rm -rf .depend

# Secure installation target
install: beforeinstall .PHONY
	@echo "Performing secure module installation..."
	@if [ -f ${DESTDIR}${KMODDIR}/${KMOD}.ko ]; then \
		mv ${DESTDIR}${KMODDIR}/${KMOD}.ko \
		   ${DESTDIR}${KMODDIR}/${KMOD}.ko.bak; \
	fi
	${INSTALL} -o root -g wheel -m 0600 ${KMOD}.ko ${DESTDIR}${KMODDIR}/
	@echo "Generating installation manifest..."
	@sha256 ${DESTDIR}${KMODDIR}/${KMOD}.ko > \
		${DESTDIR}${KMODDIR}/${KMOD}.ko.sha256

beforeinstall: .PHONY
	@echo "Verifying installation prerequisites..."
	@if [ ! -d ${DESTDIR}${KMODDIR} ]; then \
		mkdir -p ${DESTDIR}${KMODDIR}; \
	fi
	@if [ ! -w ${DESTDIR}${KMODDIR} ]; then \
		echo "Error: Cannot write to module directory"; \
		exit 1; \
	fi

# Module verification target
verify: .PHONY
	@echo "Verifying module integrity..."
	@if [ -f ${DESTDIR}${KMODDIR}/${KMOD}.ko ]; then \
		sha256 -c ${DESTDIR}${KMODDIR}/${KMOD}.ko.sha256; \
	fi

.include <bsd.kmod.mk>