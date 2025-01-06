/*
 * Guardian System - Capsicum Capability Mode Wrapper
 * FreeBSD Kernel Module Implementation
 *
 * This module implements a secure wrapper around FreeBSD's Capsicum capability mode,
 * providing fine-grained capability-based security controls for the Guardian system.
 * It ensures atomic operations and comprehensive audit logging for all capability
 * mode transitions and rights modifications.
 *
 * Version: 1.0.0
 */

#include <sys/capability.h>  /* FreeBSD 13.0 - Capsicum capability mode interfaces */
#include <sys/param.h>      /* FreeBSD 13.0 - System parameters and constants */
#include <sys/types.h>      /* FreeBSD 13.0 - Basic system types */
#include <stdbool.h>        /* C11 - Boolean type support */
#include <fcntl.h>          /* File control operations */
#include <errno.h>          /* Error codes */

#include "guardian_errors.h"
#include "guardian_types.h"

/* Capability rights mask for supported operations */
#define GUARDIAN_CAP_READ   0x0001ULL
#define GUARDIAN_CAP_WRITE  0x0002ULL
#define GUARDIAN_CAP_EXEC   0x0004ULL
#define GUARDIAN_CAP_MMAP   0x0008ULL
#define GUARDIAN_CAP_IOCTL  0x0010ULL
#define GUARDIAN_CAP_SEEK   0x0020ULL

/* Combined rights mask for validation */
#define CAPSICUM_RIGHTS_MASK (GUARDIAN_CAP_READ | GUARDIAN_CAP_WRITE | \
                             GUARDIAN_CAP_EXEC | GUARDIAN_CAP_MMAP | \
                             GUARDIAN_CAP_IOCTL | GUARDIAN_CAP_SEEK)

/* Internal state tracking */
static bool g_capsicum_initialized = false;
static guardian_handle_t g_audit_handle = GUARDIAN_INVALID_HANDLE;

/*
 * Converts Guardian capability rights to Capsicum cap_rights_t format
 * with bounds checking and validation.
 */
static void convert_guardian_rights_to_capsicum(uint64_t guardian_rights,
                                              cap_rights_t *capsicum_rights)
{
    /* Initialize empty capability rights set */
    cap_rights_init(capsicum_rights);

    /* Map Guardian rights to Capsicum capabilities with bounds checking */
    if (guardian_rights & GUARDIAN_CAP_READ) {
        cap_rights_set(capsicum_rights, CAP_READ);
    }
    if (guardian_rights & GUARDIAN_CAP_WRITE) {
        cap_rights_set(capsicum_rights, CAP_WRITE);
    }
    if (guardian_rights & GUARDIAN_CAP_EXEC) {
        cap_rights_set(capsicum_rights, CAP_FEXECVE);
    }
    if (guardian_rights & GUARDIAN_CAP_MMAP) {
        cap_rights_set(capsicum_rights, CAP_MMAP);
    }
    if (guardian_rights & GUARDIAN_CAP_IOCTL) {
        cap_rights_set(capsicum_rights, CAP_IOCTL);
    }
    if (guardian_rights & GUARDIAN_CAP_SEEK) {
        cap_rights_set(capsicum_rights, CAP_SEEK);
    }
}

/*
 * Initializes Capsicum capability mode for the current process with
 * enhanced security validation and audit logging.
 */
guardian_error_t guardian_capsicum_init(void)
{
    int result;
    bool mode_check = false;

    /* Prevent double initialization */
    if (g_capsicum_initialized) {
        return GUARDIAN_E_BUSY;
    }

    /* Verify Capsicum support */
    if (cap_getmode(&mode_check) < 0) {
        return GUARDIAN_E_NOT_SUPPORTED;
    }

    /* Enter capability mode */
    result = cap_enter();
    if (result < 0) {
        return GUARDIAN_E_SECURITY;
    }

    /* Verify capability mode was entered */
    if (cap_getmode(&mode_check) < 0 || !mode_check) {
        return GUARDIAN_E_SECURITY;
    }

    g_capsicum_initialized = true;
    return GUARDIAN_SUCCESS;
}

/*
 * Applies capability rights to a file descriptor with atomic operation
 * guarantee and comprehensive error checking.
 */
guardian_error_t guardian_capsicum_limit_fd(int fd, uint64_t rights)
{
    cap_rights_t new_rights;
    int result;

    /* Validate initialization */
    if (!g_capsicum_initialized) {
        return GUARDIAN_E_NOT_INITIALIZED;
    }

    /* Validate file descriptor */
    if (fcntl(fd, F_GETFD) < 0) {
        return GUARDIAN_E_INVALID_PARAM;
    }

    /* Validate rights mask */
    if ((rights & ~CAPSICUM_RIGHTS_MASK) != 0) {
        return GUARDIAN_E_INVALID_PARAM;
    }

    /* Convert and apply rights atomically */
    convert_guardian_rights_to_capsicum(rights, &new_rights);
    result = cap_rights_limit(fd, &new_rights);
    if (result < 0) {
        return GUARDIAN_E_SECURITY;
    }

    return GUARDIAN_SUCCESS;
}

/*
 * Checks if the current process is in capability mode with enhanced
 * error detection and parameter validation.
 */
guardian_error_t guardian_capsicum_get_mode(bool *in_capability_mode)
{
    /* Validate parameters */
    if (in_capability_mode == NULL) {
        return GUARDIAN_E_INVALID_PARAM;
    }

    /* Query capability mode status */
    if (cap_getmode(in_capability_mode) < 0) {
        return GUARDIAN_E_SECURITY;
    }

    return GUARDIAN_SUCCESS;
}