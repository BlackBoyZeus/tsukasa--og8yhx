/*
 * Guardian System - Kernel Environment Manager
 * 
 * Secure kernel environment variable management interface with comprehensive
 * security validation, audit logging, and thread-safe operations.
 *
 * Version: 1.0.0
 * FreeBSD Version: 13.0
 */

#ifndef _GUARDIAN_KENV_MANAGER_H_
#define _GUARDIAN_KENV_MANAGER_H_

#include <sys/types.h>      /* FreeBSD 13.0 - System type definitions */
#include <sys/kernel.h>     /* FreeBSD 13.0 - Kernel interface definitions */
#include <sys/sysctl.h>     /* FreeBSD 13.0 - Sysctl interface definitions */
#include <sys/lock.h>       /* FreeBSD 13.0 - Kernel locking primitives */
#include "guardian_types.h"
#include "guardian_errors.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Kernel environment configuration constants
 */
#define GUARDIAN_MAX_KENV_VALUE    1024    /* Maximum value length */
#define GUARDIAN_MAX_KENV_VARS     256     /* Maximum number of variables */

/*
 * Kernel environment variable flags
 */
#define GUARDIAN_KENV_FLAG_SECURE    0x0001  /* Secure variable with enhanced protection */
#define GUARDIAN_KENV_FLAG_READONLY  0x0002  /* Read-only variable */
#define GUARDIAN_KENV_FLAG_AUDIT     0x0004  /* Enable audit logging for access */

/*
 * Kernel environment variable entry structure
 * Enhanced with security context and audit information
 */
typedef struct guardian_kenv_entry {
    char name[GUARDIAN_MAX_NAME];                /* Variable name */
    char value[GUARDIAN_MAX_KENV_VALUE];         /* Variable value */
    uint32_t flags;                             /* Security and access flags */
    guardian_security_context_t security_context; /* Security context */
    time_t last_modified;                       /* Last modification timestamp */
} guardian_kenv_entry_t;

/*
 * Function declarations
 */

/**
 * Securely retrieve a kernel environment variable value
 *
 * @param ctx    Security context for access validation
 * @param name   Name of the environment variable
 * @param value  Buffer to store the variable value
 * @param size   Size of the value buffer
 * @param error  Detailed error information structure
 *
 * @return GUARDIAN_STATUS_SUCCESS on success, error code otherwise
 */
_Thread_safe guardian_status_t guardian_kenv_get(
    const guardian_security_context_t* ctx,
    const char* name,
    char* value,
    size_t size,
    guardian_error_info_t* error
);

/**
 * Securely set or update a kernel environment variable
 *
 * @param ctx    Security context for privilege validation
 * @param name   Name of the environment variable
 * @param value  Value to set
 * @param flags  Security and access control flags
 * @param error  Detailed error information structure
 *
 * @return GUARDIAN_STATUS_SUCCESS on success, error code otherwise
 */
_Thread_safe guardian_status_t guardian_kenv_set(
    const guardian_security_context_t* ctx,
    const char* name,
    const char* value,
    uint32_t flags,
    guardian_error_info_t* error
);

/*
 * Internal validation macros
 */
#define GUARDIAN_KENV_CHECK_NAME(name) \
    GUARDIAN_CHECK_ERROR((name != NULL && strlen(name) < GUARDIAN_MAX_NAME), \
        GUARDIAN_ERROR_INVALID_PARAM, "Invalid kenv name parameter")

#define GUARDIAN_KENV_CHECK_VALUE(value, size) \
    GUARDIAN_CHECK_ERROR((value != NULL && size <= GUARDIAN_MAX_KENV_VALUE), \
        GUARDIAN_ERROR_INVALID_PARAM, "Invalid kenv value parameter")

#define GUARDIAN_KENV_CHECK_CONTEXT(ctx) \
    GUARDIAN_CHECK_ERROR((ctx != NULL), \
        GUARDIAN_ERROR_SECURITY, "Invalid security context")

#define GUARDIAN_KENV_CHECK_FLAGS(flags) \
    GUARDIAN_CHECK_ERROR(((flags & ~(GUARDIAN_KENV_FLAG_SECURE | \
                                   GUARDIAN_KENV_FLAG_READONLY | \
                                   GUARDIAN_KENV_FLAG_AUDIT)) == 0), \
        GUARDIAN_ERROR_INVALID_PARAM, "Invalid kenv flags")

/*
 * Audit logging macros
 */
#define GUARDIAN_KENV_AUDIT_ACCESS(ctx, name, op) \
    do { \
        char audit_msg[GUARDIAN_ERROR_AUDIT_BUFFER]; \
        snprintf(audit_msg, sizeof(audit_msg), \
                "kenv %s access: name=%s, uid=%u, gid=%u", \
                op, name, ctx->uid, ctx->gid); \
        GUARDIAN_AUDIT_ERROR(GUARDIAN_SUCCESS, "Kenv access", audit_msg); \
    } while (0)

#ifdef __cplusplus
}
#endif

#endif /* _GUARDIAN_KENV_MANAGER_H_ */