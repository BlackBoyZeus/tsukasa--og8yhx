# Guardian System FreeBSD Kernel Module Utilities Makefile
# Version: 1.0.0
# Security Level: High - Production Build Configuration

# Source files
SRCS=	error_handlers.c \
	debug_helpers.c \
	kernel_utils.c

# Kernel module name
KMOD=	guardian_utils

# Warning level (maximum)
WARNS=	6

# Include paths
INCS=	-I../../include \
	-I/usr/src/sys \
	-I/usr/src/sys/modules

# Security and optimization flags
CFLAGS+=	-O2 \
		-Wall \
		-Wextra \
		-Werror \
		-fstack-protector-strong \
		-D_FORTIFY_SOURCE=2 \
		-fPIE \
		-DGUARDIAN_DEBUG_ENABLED

# Debug flags (enabled when DEBUG is defined)
.if defined(DEBUG)
CFLAGS+=	-g -DDEBUG
.endif

# Ensure proper module signing if enabled
.if defined(SIGNING_KEY)
SIGNING_FLAGS=	-s ${SIGNING_KEY}
.endif

# Default target
all: ${KMOD}.ko

# Clean target with secure deletion
clean:
	rm -P *.o
	rm -P *.ko
	rm -P .depend*
	rm -P machine
	rm -P x86
.if defined(DEBUG)
	rm -P *.debug
.endif

# Install target with proper permissions
install:
.if defined(SIGNING_KEY)
	@echo "Verifying module signature..."
	kldxref ${SIGNING_FLAGS} ${KMOD}.ko
.endif
	install -o root -g wheel -m 555 ${KMOD}.ko ${DESTDIR}/boot/modules/
	kldxref ${DESTDIR}/boot/modules

# Include kernel module build rules
.include <bsd.kmod.mk>