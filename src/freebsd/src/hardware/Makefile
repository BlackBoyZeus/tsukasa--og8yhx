# Guardian System - Hardware Components Makefile
# FreeBSD 13.0 Kernel Module Build Configuration
# Copyright (c) 2024. All rights reserved.

# Compiler and tools
CC=		clang		# FreeBSD 13.0
MAKE=		make		# FreeBSD 13.0

# Kernel module name
KMOD=		guardian_hardware

# Source files
SRCS=		console_driver.c \
		memory_manager.c \
		gpu_access.c

# Include paths
INCLUDEDIR=	${.CURDIR}/../include
CFLAGS+=	-I${INCLUDEDIR}

# Security-enhanced compilation flags
CFLAGS+=	-O2 \
		-pipe \
		-fno-strict-aliasing \
		-D_KERNEL \
		-DKLD_MODULE \
		-nostdinc \
		-fstack-protector-strong \
		-D_FORTIFY_SOURCE=2 \
		-fPIE \
		-fvisibility=hidden \
		-Wall \
		-Wextra \
		-Werror \
		-Wformat \
		-Wformat-security \
		-Wstack-protector \
		-Wstrict-overflow=5 \
		-Wno-unused-parameter

# Hardware-specific optimization flags
CFLAGS+=	-march=native \
		-mtune=native

# Debug build flags
.if defined(DEBUG)
CFLAGS+=	-g \
		-DDEBUG \
		-DGUARDIAN_DEBUG_ENABLED=1 \
		-fno-omit-frame-pointer
.endif

# Production build flags
.if defined(RELEASE)
CFLAGS+=	-DNDEBUG \
		-fomit-frame-pointer
.endif

# Linker flags for enhanced security
LDFLAGS+=	-z noexecstack \
		-z relro \
		-z now \
		-pie

# FreeBSD kernel module specific flags
SRCS+=		device_if.h \
		bus_if.h \
		vnode_if.h

# Kernel module dependencies
DEPS=		guardian_types.h \
		guardian_errors.h

# Clean targets
CLEANFILES+=	${KMOD}.ko \
		${KMOD}.ko.debug \
		machine \
		${DEPS:M*.h}

# Build targets
beforebuild: ${DEPS}
	@echo "Building ${KMOD} with security features enabled..."

# Install targets
beforeinstall:
	@echo "Verifying secure installation environment..."
	@if [ ! -d ${DESTDIR}${KMODDIR} ]; then \
		mkdir -p ${DESTDIR}${KMODDIR}; \
	fi

afterinstall:
	@echo "Setting secure permissions..."
	@chmod 0600 ${DESTDIR}${KMODDIR}/${KMOD}.ko
	@echo "Updating kernel module dependencies..."
	@/sbin/kldxref ${DESTDIR}${KMODDIR}

# Debug target
debug: .PHONY
	@${MAKE} DEBUG=1

# Release target
release: .PHONY
	@${MAKE} RELEASE=1

# Test target with security validation
test: .PHONY
	@echo "Running security validation tests..."
	@${MAKE} DEBUG=1
	@if [ -f ${KMOD}.ko ]; then \
		/usr/bin/ktrace -i -f ${KMOD}.ko; \
	fi

# Security audit target
security-audit: .PHONY
	@echo "Performing security audit..."
	@scan-build ${MAKE}
	@if command -v cppcheck > /dev/null; then \
		cppcheck --enable=all --suppress=missingIncludeSystem ${SRCS}; \
	fi

.include <bsd.kmod.mk>