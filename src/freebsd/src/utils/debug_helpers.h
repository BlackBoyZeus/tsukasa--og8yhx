/*
 * Guardian System - Debug Helper Functions
 * 
 * This header provides secure debugging utilities and helper functions for the 
 * Guardian system's FreeBSD kernel module with comprehensive security controls
 * and audit trail support.
 *
 * Version: 1.0.0
 * FreeBSD Version: 13.0
 */

#ifndef _GUARDIAN_DEBUG_HELPERS_H_
#define _GUARDIAN_DEBUG_HELPERS_H_

#include <sys/types.h>  /* FreeBSD 13.0 - System type definitions */
#include <sys/param.h>  /* FreeBSD 13.0 - System parameters */
#include <sys/kernel.h> /* FreeBSD 13.0 - Kernel debugging facilities */

#include "guardian_errors.h"
#include "guardian_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Debug configuration constants
 */
#define GUARDIAN_DEBUG_BUFFER_SIZE    4096  /* Size of debug message buffer */
#define GUARDIAN_MAX_BACKTRACE        64    /* Maximum backtrace depth */
#define GUARDIAN_DEBUG_ENABLED        1     /* Debug functionality enabled */
#define GUARDIAN_SECURE_DEBUG         1     /* Security controls enabled */
#define GUARDIAN_MAX_DEBUG_THREADS    256   /* Maximum concurrent debug threads */
#define GUARDIAN_SECURITY_BOUNDARY_CHECK 1  /* Memory boundary validation */

/*
 * Debug information structure with security context and audit support
 */
typedef struct guardian_debug_info {
    const char* file;                          /* Source file */
    int line;                                  /* Line number */
    const char* function;                      /* Function name */
    guardian_security_context_t security_context; /* Security context */
    uint64_t audit_trail_id;                   /* Audit trail identifier */
    char message[GUARDIAN_DEBUG_BUFFER_SIZE];  /* Debug message buffer */
} guardian_debug_info_t;

/*
 * Security-aware assertion macro with context validation
 */
#define GUARDIAN_ASSERT(sec_ctx, condition) \
    do { \
        if (GUARDIAN_DEBUG_ENABLED && !(condition)) { \
            guardian_debug_log(sec_ctx, \
                "Assertion failed: %s\nFile: %s\nLine: %d\nFunction: %s", \
                #condition, __FILE__, __LINE__, __func__); \
            guardian_backtrace(sec_ctx, 1); \
            panic("GUARDIAN_ASSERT"); \
        } \
    } while (0)

/*
 * Secure debug breakpoint macro with security validation
 */
#define GUARDIAN_DEBUG_BREAK(sec_ctx) \
    do { \
        if (GUARDIAN_DEBUG_ENABLED && \
            guardian_validate_security_context(sec_ctx) == GUARDIAN_STATUS_SUCCESS) { \
            breakpoint(); \
        } \
    } while (0)

/*
 * Function declarations
 */

/*
 * Securely logs a debug message with security context and audit trail
 */
guardian_status_t guardian_debug_log(
    guardian_security_context_t* sec_ctx,
    const char* format,
    ...) __attribute__((format(printf, 2, 3)));

/*
 * Securely captures and logs backtrace with security boundary validation
 */
guardian_status_t guardian_backtrace(
    guardian_security_context_t* sec_ctx,
    uint32_t skip_frames);

/*
 * Securely dumps memory contents with boundary protection
 */
guardian_status_t guardian_memory_dump(
    guardian_security_context_t* sec_ctx,
    const void* addr,
    size_t len);

/*
 * Internal helper functions
 */

/*
 * Validates security context for debug operations
 */
static inline guardian_status_t guardian_validate_security_context(
    guardian_security_context_t* sec_ctx) {
    if (!sec_ctx) {
        return GUARDIAN_STATUS_ERROR;
    }
    /* Validate security context permissions */
    if (!(sec_ctx->capabilities & GUARDIAN_CAP_DEBUG)) {
        return GUARDIAN_STATUS_ERROR;
    }
    return GUARDIAN_STATUS_SUCCESS;
}

/*
 * Validates memory boundaries for secure access
 */
static inline guardian_status_t guardian_validate_memory_bounds(
    const void* addr,
    size_t len) {
    if (!addr || len == 0 || len > GUARDIAN_DEBUG_BUFFER_SIZE) {
        return GUARDIAN_STATUS_ERROR;
    }
    /* Add additional boundary checks based on security policy */
    if (GUARDIAN_SECURITY_BOUNDARY_CHECK) {
        /* Validate address range against kernel memory boundaries */
        if ((uintptr_t)addr < VM_MIN_KERNEL_ADDRESS ||
            (uintptr_t)addr + len > VM_MAX_KERNEL_ADDRESS) {
            return GUARDIAN_STATUS_ERROR;
        }
    }
    return GUARDIAN_STATUS_SUCCESS;
}

#ifdef __cplusplus
}
#endif

#endif /* _GUARDIAN_DEBUG_HELPERS_H_ */