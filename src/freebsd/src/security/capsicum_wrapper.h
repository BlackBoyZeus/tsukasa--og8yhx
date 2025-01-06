/*
 * Capsicum Wrapper Interface for Guardian Security System
 * FreeBSD 13.0 Kernel Module Implementation
 *
 * This header provides a secure wrapper interface for FreeBSD's Capsicum
 * capability mode functionality, enabling fine-grained capability-based
 * security controls for the Guardian system. It implements thread-safe
 * operations with comprehensive error handling and security validation.
 *
 * Copyright (c) 2024. All rights reserved.
 */

#ifndef _GUARDIAN_CAPSICUM_WRAPPER_H_
#define _GUARDIAN_CAPSICUM_WRAPPER_H_

#include <sys/capability.h>  /* FreeBSD 13.0 - Capsicum capability interfaces */
#include <sys/param.h>      /* FreeBSD 13.0 - System parameters */
#include "guardian_errors.h" /* Error handling types */
#include "guardian_types.h"  /* Core type definitions */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Capability rights flags for fine-grained access control
 * These map to FreeBSD's cap_rights_t but provide a Guardian-specific interface
 */
#define GUARDIAN_CAP_READ   (1ULL << 0)  /* Read access capability */
#define GUARDIAN_CAP_WRITE  (1ULL << 1)  /* Write access capability */
#define GUARDIAN_CAP_EXEC   (1ULL << 2)  /* Execute access capability */
#define GUARDIAN_CAP_MMAP   (1ULL << 3)  /* Memory mapping capability */
#define GUARDIAN_CAP_IOCTL  (1ULL << 4)  /* IOCTL operation capability */
#define GUARDIAN_CAP_SEEK   (1ULL << 5)  /* Seek operation capability */

/*
 * Initializes Capsicum capability mode for the current process.
 * Must be called before any other capability operations.
 *
 * @return guardian_error_t:
 *   GUARDIAN_SUCCESS - Initialization successful
 *   GUARDIAN_E_NOT_SUPPORTED - Capsicum not supported by kernel
 *   GUARDIAN_E_INIT_FAILED - Initialization failed
 *   GUARDIAN_E_SECURITY - Security violation detected
 */
guardian_error_t guardian_capsicum_init(void);

/*
 * Applies capability rights to a file descriptor with security validation.
 * Thread-safe implementation with comprehensive error checking.
 *
 * @param fd: File descriptor to apply capabilities to
 * @param rights: Bitmap of GUARDIAN_CAP_* rights to apply
 *
 * @return guardian_error_t:
 *   GUARDIAN_SUCCESS - Rights successfully applied
 *   GUARDIAN_E_INVALID_PARAM - Invalid file descriptor
 *   GUARDIAN_E_PERMISSION - Insufficient permissions
 *   GUARDIAN_E_NOT_INITIALIZED - Capsicum not initialized
 *   GUARDIAN_E_SECURITY - Security violation detected
 */
guardian_error_t guardian_capsicum_limit_fd(int fd, uint64_t rights);

/*
 * Thread-safely checks if the current process is in capability mode.
 * Provides atomic operation with proper memory barriers.
 *
 * @param in_capability_mode: Pointer to store the capability mode status
 *
 * @return guardian_error_t:
 *   GUARDIAN_SUCCESS - Check completed successfully
 *   GUARDIAN_E_INVALID_PARAM - Invalid pointer parameter
 *   GUARDIAN_E_NOT_INITIALIZED - Capsicum not initialized
 */
guardian_error_t guardian_capsicum_get_mode(bool *in_capability_mode);

#ifdef __cplusplus
}
#endif

#endif /* _GUARDIAN_CAPSICUM_WRAPPER_H_ */