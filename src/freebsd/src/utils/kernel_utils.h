/*
 * Guardian System - Kernel Utility Functions
 * 
 * This header provides secure utility functions and macros for kernel-level operations
 * in the Guardian system, implementing memory-safe operations, process control,
 * device access, and security context utilities.
 *
 * Version: 1.0.0
 * FreeBSD Version: 13.0
 */

#ifndef _GUARDIAN_KERNEL_UTILS_H_
#define _GUARDIAN_KERNEL_UTILS_H_

#include <sys/types.h>      /* FreeBSD 13.0 - System type definitions */
#include <sys/param.h>      /* FreeBSD 13.0 - System parameters */
#include <sys/kernel.h>     /* FreeBSD 13.0 - Kernel interfaces */
#include <sys/malloc.h>     /* FreeBSD 13.0 - Kernel memory allocation */
#include "guardian_types.h"
#include "guardian_errors.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Memory allocation flags
 */
#define GUARDIAN_KMALLOC_WAIT    M_WAITOK    /* Can sleep */
#define GUARDIAN_KMALLOC_NOWAIT  M_NOWAIT    /* Cannot sleep */

/*
 * System constants
 */
#define GUARDIAN_PAGE_SIZE       PAGE_SIZE
#define GUARDIAN_MEMORY_ALIGNMENT CACHE_LINE_SIZE
#define GUARDIAN_MAX_ALLOC_SIZE  MAXPHYS
#define GUARDIAN_SECURITY_MAGIC  0x47554152   /* "GUAR" in hex */

/*
 * Secure memory allocation with alignment and validation
 */
__attribute__((malloc))
__attribute__((aligned(GUARDIAN_MEMORY_ALIGNMENT)))
void* guardian_kmalloc(size_t size, int flags, guardian_security_context_t* sec_ctx);

/*
 * Secure memory deallocation with validation
 */
void guardian_kfree(void* ptr, guardian_security_context_t* sec_ctx);

/*
 * Memory statistics retrieval with security validation
 */
__attribute__((warn_unused_result))
guardian_status_t guardian_get_memory_stats(
    guardian_memory_stats_t* stats,
    guardian_security_context_t* sec_ctx
);

/*
 * Security validation macros
 */
#define GUARDIAN_VALIDATE_SECURITY_CONTEXT(ctx) \
    do { \
        if ((ctx) == NULL || \
            ((ctx)->security_flags & GUARDIAN_SECURITY_MAGIC) != GUARDIAN_SECURITY_MAGIC) { \
            GUARDIAN_ERROR_PUSH(GUARDIAN_ERROR_SECURITY, "Invalid security context"); \
            return NULL; \
        } \
    } while (0)

#define GUARDIAN_VALIDATE_POINTER(ptr) \
    do { \
        if ((ptr) == NULL || \
            (((uintptr_t)(ptr) & (GUARDIAN_MEMORY_ALIGNMENT - 1)) != 0)) { \
            GUARDIAN_ERROR_PUSH(GUARDIAN_ERROR_INVALID_PARAM, "Invalid pointer alignment"); \
            return; \
        } \
    } while (0)

#define GUARDIAN_VALIDATE_SIZE(size) \
    do { \
        if ((size) == 0 || (size) > GUARDIAN_MAX_ALLOC_SIZE) { \
            GUARDIAN_ERROR_PUSH(GUARDIAN_ERROR_INVALID_PARAM, "Invalid allocation size"); \
            return NULL; \
        } \
    } while (0)

/*
 * Memory operation audit macros
 */
#define GUARDIAN_AUDIT_ALLOC(size, ptr, ctx) \
    do { \
        guardian_error_info_t audit = GUARDIAN_ERROR_INFO(GUARDIAN_SUCCESS, "Memory allocated"); \
        snprintf(audit.audit_data, GUARDIAN_ERROR_AUDIT_BUFFER, \
                "size=%zu, ptr=%p, uid=%u", (size), (ptr), (ctx)->uid); \
        guardian_error_chain_push(&audit); \
    } while (0)

#define GUARDIAN_AUDIT_FREE(ptr, ctx) \
    do { \
        guardian_error_info_t audit = GUARDIAN_ERROR_INFO(GUARDIAN_SUCCESS, "Memory freed"); \
        snprintf(audit.audit_data, GUARDIAN_ERROR_AUDIT_BUFFER, \
                "ptr=%p, uid=%u", (ptr), (ctx)->uid); \
        guardian_error_chain_push(&audit); \
    } while (0)

/*
 * Function implementations
 */

void* guardian_kmalloc(size_t size, int flags, guardian_security_context_t* sec_ctx) {
    void* ptr;
    
    /* Validate parameters */
    GUARDIAN_VALIDATE_SECURITY_CONTEXT(sec_ctx);
    GUARDIAN_VALIDATE_SIZE(size);
    
    /* Allocate aligned memory */
    ptr = malloc(size + GUARDIAN_MEMORY_ALIGNMENT, M_GUARDIAN, flags);
    if (ptr == NULL) {
        GUARDIAN_ERROR_PUSH(GUARDIAN_ERROR_MEMORY, "Memory allocation failed");
        return NULL;
    }
    
    /* Align pointer and zero memory */
    ptr = (void*)(((uintptr_t)ptr + GUARDIAN_MEMORY_ALIGNMENT - 1) & 
                  ~(GUARDIAN_MEMORY_ALIGNMENT - 1));
    memset(ptr, 0, size);
    
    /* Audit allocation */
    GUARDIAN_AUDIT_ALLOC(size, ptr, sec_ctx);
    
    return ptr;
}

void guardian_kfree(void* ptr, guardian_security_context_t* sec_ctx) {
    /* Validate parameters */
    GUARDIAN_VALIDATE_SECURITY_CONTEXT(sec_ctx);
    GUARDIAN_VALIDATE_POINTER(ptr);
    
    /* Zero memory before freeing */
    memset(ptr, 0, malloc_usable_size(ptr));
    
    /* Free memory */
    free(ptr, M_GUARDIAN);
    
    /* Audit deallocation */
    GUARDIAN_AUDIT_FREE(ptr, sec_ctx);
}

guardian_status_t guardian_get_memory_stats(
    guardian_memory_stats_t* stats,
    guardian_security_context_t* sec_ctx
) {
    /* Validate parameters */
    if (stats == NULL) {
        GUARDIAN_ERROR_PUSH(GUARDIAN_ERROR_INVALID_PARAM, "Invalid stats pointer");
        return GUARDIAN_STATUS_ERROR;
    }
    GUARDIAN_VALIDATE_SECURITY_CONTEXT(sec_ctx);
    
    /* Collect system memory statistics */
    stats->total = vm_cnt.v_page_count * PAGE_SIZE;
    stats->free = vm_cnt.v_free_count * PAGE_SIZE;
    stats->used = stats->total - stats->free;
    stats->shared = vm_cnt.v_active_count * PAGE_SIZE;
    stats->cached = vm_cnt.v_cache_count * PAGE_SIZE;
    stats->locked = vm_cnt.v_wire_count * PAGE_SIZE;
    
    /* Validate collected statistics */
    if (stats->used > stats->total || 
        stats->free > stats->total ||
        stats->shared > stats->total ||
        stats->cached > stats->total ||
        stats->locked > stats->total) {
        GUARDIAN_ERROR_PUSH(GUARDIAN_ERROR_CORRUPTION, "Invalid memory statistics");
        return GUARDIAN_STATUS_ERROR;
    }
    
    return GUARDIAN_STATUS_SUCCESS;
}

#ifdef __cplusplus
}
#endif

#endif /* _GUARDIAN_KERNEL_UTILS_H_ */