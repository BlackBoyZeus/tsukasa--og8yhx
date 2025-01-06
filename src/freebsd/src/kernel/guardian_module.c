/*
 * Guardian System - FreeBSD Kernel Module Implementation
 * 
 * This module provides kernel-level integration, system monitoring,
 * memory protection, and security policy enforcement for the gaming
 * console platform with enhanced atomic operations and memory barriers
 * for thread safety.
 *
 * Copyright (c) 2024. All rights reserved.
 */

#include <sys/param.h>      /* FreeBSD 13.0 */
#include <sys/module.h>     /* FreeBSD 13.0 */
#include <sys/kernel.h>     /* FreeBSD 13.0 */
#include <sys/systm.h>      /* FreeBSD 13.0 */
#include <machine/atomic.h> /* FreeBSD 13.0 */

#include "../include/guardian_errors.h"
#include "../include/guardian_types.h"
#include "memory_protection.h"

/* Module information */
static struct moduledata_t guardian_mod = {
    "guardian",    /* module name */
    NULL,         /* event handler */
    NULL          /* extra data */
};

DECLARE_MODULE(guardian, guardian_mod, SI_SUB_DRIVERS, SI_ORDER_FIRST);
MODULE_VERSION(guardian, 1);

/* Global state with atomic operations */
static _Atomic guardian_system_state_t guardian_module_state;
static _Atomic int guardian_initialized = 0;
static struct mtx guardian_lock;

/* Internal function prototypes */
static guardian_error_t guardian_init_atomic(void);
static guardian_error_t guardian_cleanup_atomic(void);
static void guardian_eventhandler_atomic(void *arg, int event_type);

/*
 * Initialize the Guardian kernel module with atomic operations
 */
static guardian_error_t guardian_init_atomic(void) {
    guardian_error_t status = GUARDIAN_SUCCESS;
    
    mtx_lock(&guardian_lock);
    
    /* Check if already initialized using atomic operation */
    if (atomic_load(&guardian_initialized)) {
        mtx_unlock(&guardian_lock);
        return GUARDIAN_E_BUSY;
    }
    
    /* Initialize system state with memory barriers */
    guardian_system_state_t initial_state = {
        .status = GUARDIAN_STATUS_INITIALIZED,
        .uptime = 0,
        .memory_usage = 0,
        .active_policies = 0
    };
    
    GUARDIAN_MEMORY_BARRIER();
    atomic_store(&guardian_module_state, initial_state);
    GUARDIAN_MEMORY_BARRIER();
    
    /* Setup memory protection with atomic operations */
    guardian_memory_region_t kernel_region = {
        .base_address = (void *)kernel_base,
        .size = kernel_size,
        .flags = GUARDIAN_MEM_SECURE | GUARDIAN_MEM_LOCKED,
        .protection = GUARDIAN_PROT_READ | GUARDIAN_PROT_EXEC
    };
    
    status = guardian_protect_region_atomic(GUARDIAN_INVALID_HANDLE, &kernel_region);
    if (status != GUARDIAN_SUCCESS) {
        goto cleanup;
    }
    
    /* Mark as initialized using atomic operation */
    GUARDIAN_MEMORY_BARRIER();
    atomic_store(&guardian_initialized, 1);
    
cleanup:
    mtx_unlock(&guardian_lock);
    return status;
}

/*
 * Cleanup and unload the Guardian kernel module with atomic operations
 */
static guardian_error_t guardian_cleanup_atomic(void) {
    guardian_error_t status = GUARDIAN_SUCCESS;
    
    mtx_lock(&guardian_lock);
    
    /* Check if initialized using atomic operation */
    if (!atomic_load(&guardian_initialized)) {
        mtx_unlock(&guardian_lock);
        return GUARDIAN_E_NOT_INITIALIZED;
    }
    
    /* Cleanup memory protection with atomic operations */
    guardian_memory_region_t kernel_region = {
        .base_address = (void *)kernel_base,
        .size = kernel_size,
        .flags = GUARDIAN_MEM_SECURE | GUARDIAN_MEM_LOCKED,
        .protection = GUARDIAN_PROT_NONE
    };
    
    status = guardian_verify_protection_atomic(GUARDIAN_INVALID_HANDLE, &kernel_region);
    if (status != GUARDIAN_SUCCESS) {
        goto cleanup;
    }
    
    /* Reset system state with memory barriers */
    guardian_system_state_t reset_state = {0};
    GUARDIAN_MEMORY_BARRIER();
    atomic_store(&guardian_module_state, reset_state);
    GUARDIAN_MEMORY_BARRIER();
    
    /* Mark as uninitialized using atomic operation */
    atomic_store(&guardian_initialized, 0);
    
cleanup:
    mtx_unlock(&guardian_lock);
    return status;
}

/*
 * Thread-safe event handler for system events and security violations
 */
static void guardian_eventhandler_atomic(void *arg, int event_type) {
    mtx_lock(&guardian_lock);
    
    /* Validate event type with thread safety */
    if (!atomic_load(&guardian_initialized)) {
        goto cleanup;
    }
    
    /* Process security event using atomic operations */
    guardian_system_state_t current_state = atomic_load(&guardian_module_state);
    
    switch (event_type) {
        case GUARDIAN_EVENT_SECURITY_VIOLATION:
            current_state.status |= GUARDIAN_STATUS_ERROR;
            break;
        case GUARDIAN_EVENT_POLICY_UPDATE:
            current_state.active_policies++;
            break;
        default:
            break;
    }
    
    /* Update system state with memory barriers */
    GUARDIAN_MEMORY_BARRIER();
    atomic_store(&guardian_module_state, current_state);
    GUARDIAN_MEMORY_BARRIER();
    
cleanup:
    mtx_unlock(&guardian_lock);
}

/*
 * Module load entry point
 */
static int guardian_mod_load(struct module *module, int cmd, void *arg) {
    guardian_error_t status;
    
    switch (cmd) {
        case MOD_LOAD:
            mtx_init(&guardian_lock, "guardian_lock", NULL, MTX_DEF);
            status = guardian_init_atomic();
            return (status == GUARDIAN_SUCCESS) ? 0 : EINVAL;
            
        case MOD_UNLOAD:
            status = guardian_cleanup_atomic();
            if (status == GUARDIAN_SUCCESS) {
                mtx_destroy(&guardian_lock);
                return 0;
            }
            return EINVAL;
            
        default:
            return EOPNOTSUPP;
    }
}

/*
 * Module event handler registration
 */
static moduledata_t guardian_mod = {
    "guardian",
    guardian_mod_load,
    NULL
};

DECLARE_MODULE(guardian, guardian_mod, SI_SUB_DRIVERS, SI_ORDER_FIRST);
MODULE_VERSION(guardian, 1);
MODULE_DEPEND(guardian, kernel, 1, 1, 1);