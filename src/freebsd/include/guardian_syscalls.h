/*
 * Guardian System - System Call Interface Definitions
 * FreeBSD Kernel Module Implementation
 *
 * This header defines the core system call interfaces for the Guardian security
 * system's FreeBSD kernel module. It provides secure, type-safe syscall interfaces
 * with comprehensive parameter validation, memory protection, and audit logging.
 *
 * Copyright (c) 2024. All rights reserved.
 */

#ifndef _GUARDIAN_SYSCALLS_H_
#define _GUARDIAN_SYSCALLS_H_

#include <sys/types.h>      /* FreeBSD 13.0 - Basic system types */
#include <sys/syscall.h>    /* FreeBSD 13.0 - System call definitions */
#include <sys/sysent.h>     /* FreeBSD 13.0 - System entry table definitions */

#include "guardian_types.h"  /* Core type definitions */
#include "guardian_errors.h" /* Error handling framework */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * System call base number and limits
 */
#define GUARDIAN_SYSCALL_BASE      210  /* Base syscall number */
#define GUARDIAN_MAX_SYSCALLS      32   /* Maximum number of syscalls */
#define GUARDIAN_SYSCALL_AUDIT_ENABLED 1 /* Enable syscall auditing */

/*
 * System call identifier type
 */
typedef uint32_t guardian_syscall_t;

/*
 * Function decorators for syscall implementation
 */
#define __syscall   __attribute__((visibility("default")))
#define __audit_event __attribute__((annotate("audit")))
#define __validate_params __attribute__((annotate("validate")))

/*
 * Initialize the Guardian system with security validation
 *
 * @param flags: Initialization flags controlling system behavior
 * @return: Success or detailed error code
 *
 * Security: Requires root privileges, validates caller context
 * Audit: Logs initialization attempt and result
 */
__syscall __audit_event
guardian_error_t guardian_sys_init(guardian_init_flags_t flags);

/*
 * Get current system state with security validation
 *
 * @param state: Pointer to state structure to be filled
 * @param size: Size of the state structure for validation
 * @return: Success or detailed error code
 *
 * Security: Validates user buffer and access permissions
 * Audit: Logs state access attempts
 */
__syscall __validate_params
guardian_error_t guardian_sys_get_state(
    guardian_system_state_t *state,
    size_t size
);

/*
 * Set security policy with comprehensive validation
 *
 * @param policy: Pointer to security policy configuration
 * @param policy_size: Size of policy structure for validation
 * @return: Success or detailed error code
 *
 * Security: Requires elevated privileges, validates policy integrity
 * Audit: Logs policy changes with before/after state
 */
__syscall __audit_event __validate_params
guardian_error_t guardian_sys_set_policy(
    guardian_security_policy_t *policy,
    size_t policy_size
);

/*
 * Map memory region with security checks
 *
 * @param region: Memory region descriptor
 * @param handle: Output handle for mapped region
 * @param flags: Protection and mapping flags
 * @return: Success or detailed error code
 *
 * Security: Validates memory bounds and permissions
 * Audit: Logs memory mapping operations
 */
__syscall __validate_params __audit_event
guardian_error_t guardian_sys_map_region(
    guardian_memory_region_t *region,
    guardian_handle_t *handle,
    guardian_protection_flags_t flags
);

/*
 * System call table initialization structure
 */
struct guardian_syscall_table {
    guardian_syscall_t number;
    sy_call_t *handler;
    int argument_count;
    const char *name;
};

#ifdef __cplusplus
}
#endif

#endif /* _GUARDIAN_SYSCALLS_H_ */