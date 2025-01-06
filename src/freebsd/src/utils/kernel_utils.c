/*
 * Guardian System - Kernel Utility Functions
 * 
 * Core utility functions for FreeBSD kernel module operations with enhanced
 * security features, memory management, and error handling capabilities.
 *
 * Version: 1.0.0
 * FreeBSD Version: 13.0
 */

#include <sys/types.h>      /* FreeBSD 13.0 */
#include <sys/param.h>      /* FreeBSD 13.0 */
#include <sys/kernel.h>     /* FreeBSD 13.0 */
#include <sys/malloc.h>     /* FreeBSD 13.0 */
#include <sys/proc.h>       /* FreeBSD 13.0 */
#include "guardian_errors.h"
#include "guardian_types.h"
#include "guardian_ioctl.h"

/* Memory allocation tag for tracking */
static MALLOC_DEFINE(M_GUARDIAN, GUARDIAN_MALLOC_TAG, "Guardian System Memory");

/* Thread-local error context */
static GUARDIAN_ERROR_THREAD_LOCAL guardian_error_chain_t error_chain;

/* Memory statistics tracking */
static struct mtx memory_stats_mtx;
static guardian_memory_stats_t global_memory_stats;

/* Initialization */
static void guardian_init_memory_tracking(void) {
    mtx_init(&memory_stats_mtx, "guardian_memory_stats", NULL, MTX_DEF);
    bzero(&global_memory_stats, sizeof(guardian_memory_stats_t));
}

/* Memory statistics update with locking */
static void update_memory_stats(ssize_t delta) {
    mtx_lock(&memory_stats_mtx);
    global_memory_stats.used += delta;
    if (delta > 0) {
        global_memory_stats.total += delta;
    }
    mtx_unlock(&memory_stats_mtx);
}

/*
 * Enhanced kernel memory allocation with retry mechanism and error tracking
 */
void* guardian_kmalloc(size_t size) {
    void* ptr = NULL;
    int retries = 0;
    guardian_error_info_t error_info;

    /* Validate size parameter */
    if (size == 0 || size > GUARDIAN_MAX_IOCTL_SIZE) {
        GUARDIAN_ERROR_PUSH(GUARDIAN_ERROR_INVALID_PARAM, "Invalid allocation size");
        return NULL;
    }

    /* Attempt allocation with exponential backoff */
    while (retries < GUARDIAN_MAX_RETRIES && ptr == NULL) {
        ptr = malloc(size, M_GUARDIAN, M_WAITOK | M_ZERO);
        if (ptr == NULL) {
            if (retries < GUARDIAN_MAX_RETRIES - 1) {
                /* Exponential backoff delay */
                pause("guardian_alloc", (1 << retries) * hz/4);
                retries++;
            } else {
                /* Final retry failed, log error */
                bzero(&error_info, sizeof(error_info));
                error_info.code = GUARDIAN_ERROR_MEMORY;
                error_info.severity = GUARDIAN_SEVERITY_ERROR;
                snprintf(error_info.message, GUARDIAN_ERROR_BUFFER_SIZE,
                        "Memory allocation failed after %d retries", retries);
                guardian_error_chain_push(&error_info);
                return NULL;
            }
        }
    }

    /* Update memory statistics */
    if (ptr != NULL) {
        update_memory_stats(size);
    }

    return ptr;
}

/*
 * Secure kernel memory deallocation with validation
 */
void guardian_kfree(void* ptr) {
    if (ptr == NULL) {
        return;
    }

    /* Zero memory before freeing */
    size_t size = malloc_usable_size(ptr);
    explicit_bzero(ptr, size);
    
    /* Update statistics and free memory */
    update_memory_stats(-size);
    free(ptr, M_GUARDIAN);
}

/*
 * Process information retrieval with enhanced security validation
 */
guardian_status_t guardian_get_process_info(pid_t pid, guardian_process_info_t* info) {
    struct proc* p;
    guardian_error_info_t error_info;
    guardian_status_t status = GUARDIAN_STATUS_SUCCESS;

    /* Validate parameters */
    if (info == NULL || pid < 0) {
        GUARDIAN_ERROR_PUSH(GUARDIAN_ERROR_INVALID_PARAM, "Invalid process info parameters");
        return GUARDIAN_STATUS_ERROR;
    }

    /* Find process with security validation */
    p = pfind(pid);
    if (p == NULL) {
        GUARDIAN_ERROR_PUSH(GUARDIAN_ERROR_NOT_FOUND, "Process not found");
        return GUARDIAN_STATUS_ERROR;
    }

    /* Lock process for safe access */
    PROC_LOCK(p);

    /* Verify security context */
    if (!(p->p_flag & P_SYSTEM)) {
        /* Copy process information with bounds checking */
        bzero(info, sizeof(guardian_process_info_t));
        info->pid = p->p_pid;
        strlcpy(info->name, p->p_comm, GUARDIAN_MAX_NAME);
        info->state = p->p_state;
        
        /* Set security context */
        info->security_context.uid = p->p_ucred->cr_uid;
        info->security_context.gid = p->p_ucred->cr_gid;
        
        /* Get memory statistics */
        info->memory_stats.total = p->p_vmspace->vm_tsize + 
                                 p->p_vmspace->vm_dsize +
                                 p->p_vmspace->vm_ssize;
    } else {
        status = GUARDIAN_STATUS_ERROR;
        GUARDIAN_ERROR_PUSH(GUARDIAN_ERROR_PERMISSION, "Access denied to system process");
    }

    PROC_UNLOCK(p);
    return status;
}

/*
 * Memory statistics retrieval with thread safety and caching
 */
guardian_status_t guardian_get_memory_stats(guardian_memory_stats_t* stats) {
    guardian_error_info_t error_info;

    if (stats == NULL) {
        GUARDIAN_ERROR_PUSH(GUARDIAN_ERROR_INVALID_PARAM, "Invalid stats pointer");
        return GUARDIAN_STATUS_ERROR;
    }

    /* Copy statistics with locking */
    mtx_lock(&memory_stats_mtx);
    memcpy(stats, &global_memory_stats, sizeof(guardian_memory_stats_t));
    mtx_unlock(&memory_stats_mtx);

    return GUARDIAN_STATUS_SUCCESS;
}

/* Module initialization and cleanup */
static void guardian_kernel_utils_init(void) {
    guardian_init_memory_tracking();
}

static void guardian_kernel_utils_cleanup(void) {
    mtx_destroy(&memory_stats_mtx);
}

/* Module load/unload handlers */
SYSINIT(guardian_utils_init, SI_SUB_LOCK, SI_ORDER_FIRST, 
        guardian_kernel_utils_init, NULL);
SYSUNINIT(guardian_utils_cleanup, SI_SUB_LOCK, SI_ORDER_FIRST,
          guardian_kernel_utils_cleanup, NULL);