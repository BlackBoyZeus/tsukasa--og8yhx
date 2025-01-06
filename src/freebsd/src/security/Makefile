# Guardian System - Security Components Makefile
# Version: 1.0.0
# FreeBSD Version: 13.0

# Compiler and flags
CC?=		clang
CFLAGS+=	-O2 -pipe -fno-strict-aliasing \
		-I../../include \
		-fstack-protector-strong \
		-D_FORTIFY_SOURCE=2 \
		-ftpm-support \
		-Wall -Wextra -Werror \
		-DGUARDIAN_VERSION=\"1.0.0\"

# Maximum warning level for security-critical code
WARNS=		6

# Debug flags when building debug version
DEBUG_FLAGS=	-g -fsanitize=address,undefined

# Security hardening flags
SECURITY_FLAGS=	-fPIE -fPIC -Wl,-z,relro,-z,now

# Source files
SRCS=	capsicum_wrapper.c \
	mac_policy.c \
	audit_hooks.c \
	jail_config.c \
	geli_manager.c

# Object files
OBJS=	${SRCS:.c=.o}

# Include paths
INCS=	-I../../include \
	-I../utils \
	-I/usr/src/sys

# FreeBSD kernel module flags
KMOD=	guardian_security
SRCS+=	${KMOD}.c

# Default target
all: ${KMOD}.ko

# Build kernel module
${KMOD}.ko: ${OBJS}
	${CC} ${CFLAGS} ${SECURITY_FLAGS} -shared -o ${.TARGET} ${OBJS}

# Pattern rule for object files
.c.o:
	${CC} ${CFLAGS} ${SECURITY_FLAGS} ${INCS} -c ${.IMPSRC} -o ${.TARGET}

# Clean build artifacts
clean:
	rm -f ${OBJS} ${KMOD}.ko *.o *.d

# Install the module
install:
	@mkdir -p ${DESTDIR}/boot/modules
	${INSTALL} -o root -g wheel -m 0600 ${KMOD}.ko ${DESTDIR}/boot/modules/
	kldxref ${DESTDIR}/boot/modules

# Dependency files
DEPFILES= ${SRCS:T:R:S/$/.d/}
.for depfile in ${DEPFILES}
.if exists(${depfile})
.include "${depfile}"
.endif
.endfor

# Additional targets
lint:
	${LINT} ${LINTKERNFLAGS} ${CFLAGS:M-[DIU]*} ${.ALLSRC}

tags: ${SRCS}
	ctags -f /dev/stdout ${.ALLSRC} | \
	    sed "s;${.CURDIR}/;;" > ${.TARGET}

# Build with debug flags
debug: CFLAGS+=${DEBUG_FLAGS}
debug: all

# Build with additional security checks
secure: CFLAGS+=${SECURITY_FLAGS} -DGUARDIAN_SECURE_BUILD
secure: all

.include <bsd.kmod.mk>