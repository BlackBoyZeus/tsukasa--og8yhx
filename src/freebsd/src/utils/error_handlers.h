/*
 * Guardian System - Error Handler Framework
 * 
 * Header file defining error handling utilities, types, and function declarations
 * for the Guardian system's FreeBSD kernel module. Provides comprehensive error
 * handling with security context awareness and audit logging capabilities.
 *
 * Version: 1.0.0
 * FreeBSD Version: 13.0
 */

#ifndef _GUARDIAN_ERROR_HANDLERS_H_
#define _GUARDIAN_ERROR_HANDLERS_H_

#include <sys/types.h>  /* FreeBSD 13.0 - System type definitions */
#include <sys/param.h>  /* FreeBSD 13.0 - System parameters and constants */
#include <sys/kernel.h> /* FreeBSD 13.0 - Kernel functions and utilities */
#include <sys/lock.h>   /* FreeBSD 13.0 - Kernel locking primitives */
#include <sys/mutex.h>  /* FreeBSD 13.0 - Mutex synchronization */
#include "../include/guardian_errors.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Constants for error handler configuration
 */
#define GUARDIAN_MAX_ERROR_HANDLERS      8    /* Maximum number of error handlers */
#define GUARDIAN_ERROR_CHAIN_SIZE        16   /* Size of error chain buffer */
#define GUARDIAN_ERROR_SECURITY_LEVELS   4    /* Number of security levels */
#define GUARDIAN_ERROR_AUDIT_BUFFER_SIZE 1024 /* Size of audit buffer */

/*
 * Error handler function type definition with security context
 */
typedef guardian_status_t (*guardian_error_handler_t)(
    const guardian_error_info_t* error_info,
    const guardian_security_context_t* sec_ctx,
    void* user_data
);

/*
 * Error handler configuration structure
 */
typedef struct guardian_handler_config {
    guardian_security_level_t min_security_level;
    uint32_t flags;
    void* user_data;
    size_t audit_buffer_size;
} guardian_handler_config_t;

/*
 * Error chain structure with security context
 */
typedef struct guardian_error_chain {
    guardian_error_info_t errors[GUARDIAN_ERROR_CHAIN_SIZE];
    size_t count;
    guardian_security_level_t security_level;
    struct mtx chain_lock;  /* Mutex for thread safety */
} guardian_error_chain_t;

/*
 * Function declarations
 */

/*
 * Initialize error handling subsystem
 * Must be called during system initialization with appropriate security context
 */
GUARDIAN_KERNEL_INIT guardian_status_t guardian_error_init(
    guardian_security_context_t* sec_ctx
);

/*
 * Log error with security context and audit information
 * Thread-safe and atomic operation
 */
GUARDIAN_ATOMIC void guardian_error_log(
    const guardian_error_info_t* error_info,
    guardian_security_level_t sec_level,
    const guardian_audit_context_t* audit_ctx
);

/*
 * Register new error handler with security validation
 * Requires privileged security context
 */
GUARDIAN_PRIVILEGED guardian_status_t guardian_error_register_handler(
    guardian_error_handler_t handler,
    guardian_security_level_t required_level,
    const guardian_handler_config_t* config
);

/*
 * Unregister error handler
 * Requires matching security context
 */
GUARDIAN_PRIVILEGED guardian_status_t guardian_error_unregister_handler(
    guardian_error_handler_t handler
);

/*
 * Get current error chain with security validation
 */
const guardian_error_chain_t* guardian_error_get_chain(
    guardian_security_level_t required_level
);

/*
 * Clear error chain with security validation
 */
guardian_status_t guardian_error_clear_chain(
    guardian_security_level_t required_level
);

/*
 * Get error handler statistics
 */
guardian_status_t guardian_error_get_stats(
    guardian_error_stats_t* stats,
    guardian_security_level_t required_level
);

/*
 * Error handling macros
 */

/* Log error with security context */
#define GUARDIAN_ERROR_LOG_SEC(error_info, sec_level) \
    guardian_error_log((error_info), (sec_level), NULL)

/* Log error with audit trail */
#define GUARDIAN_ERROR_LOG_AUDIT(error_info, sec_level, audit_data) \
    do { \
        guardian_audit_context_t audit_ctx = { \
            .data = (audit_data), \
            .size = strlen(audit_data) \
        }; \
        guardian_error_log((error_info), (sec_level), &audit_ctx); \
    } while (0)

/* Check error condition with security context */
#define GUARDIAN_CHECK_ERROR_SEC(cond, error_code, sec_level) \
    do { \
        if (!(cond)) { \
            guardian_error_info_t error = GUARDIAN_ERROR_INFO(error_code); \
            GUARDIAN_ERROR_LOG_SEC(&error, sec_level); \
            return (error_code); \
        } \
    } while (0)

#ifdef __cplusplus
}
#endif

#endif /* _GUARDIAN_ERROR_HANDLERS_H_ */