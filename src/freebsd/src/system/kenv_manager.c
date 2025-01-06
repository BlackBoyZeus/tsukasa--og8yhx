/*
 * Guardian System - Kernel Environment Manager Implementation
 * 
 * Secure kernel environment variable management with comprehensive security
 * validation, audit logging, and thread-safe operations.
 *
 * Version: 1.0.0
 * FreeBSD Version: 13.0
 */

#include <sys/types.h>      /* FreeBSD 13.0 - System type definitions */
#include <sys/kernel.h>     /* FreeBSD 13.0 - Kernel interface definitions */
#include <sys/sysctl.h>     /* FreeBSD 13.0 - Sysctl interface definitions */
#include <sys/kenv.h>       /* FreeBSD 13.0 - Kernel environment interface */
#include "guardian_types.h"
#include "guardian_errors.h"
#include "kenv_manager.h"

/* Global state with security protections */
static struct mtx kenv_lock;
static guardian_kenv_entry_t kenv_entries[GUARDIAN_MAX_KENV_VARS];
static volatile int kenv_count = 0;
static guardian_kenv_security_ctx_t kenv_security_ctx;

/* Initialize kernel environment management system */
guardian_status_t guardian_kenv_init(guardian_kenv_security_ctx_t* security_ctx) {
    guardian_error_info_t error;

    /* Validate security context */
    GUARDIAN_KENV_CHECK_CONTEXT(security_ctx);

    /* Initialize mutex with security attributes */
    mtx_init(&kenv_lock, "guardian_kenv_lock", NULL, MTX_DEF | MTX_SAFE);

    /* Initialize kenv entries with secure defaults */
    memset(kenv_entries, 0, sizeof(kenv_entries));
    kenv_count = 0;

    /* Copy security context with validation */
    memcpy(&kenv_security_ctx, security_ctx, sizeof(guardian_kenv_security_ctx_t));

    /* Log initialization event */
    GUARDIAN_KENV_AUDIT_ACCESS(security_ctx, "system", "init");

    return GUARDIAN_STATUS_SUCCESS;
}

/* Cleanup kernel environment management system */
void guardian_kenv_cleanup(void) {
    mtx_lock(&kenv_lock);
    
    /* Securely clear all entries */
    memset(kenv_entries, 0, sizeof(kenv_entries));
    kenv_count = 0;

    /* Log cleanup event */
    GUARDIAN_KENV_AUDIT_ACCESS(&kenv_security_ctx, "system", "cleanup");

    mtx_unlock(&kenv_lock);
    mtx_destroy(&kenv_lock);
}

/* Get kernel environment variable with security validation */
guardian_status_t guardian_kenv_get(
    const char* name,
    char* value,
    size_t size,
    guardian_kenv_security_ctx_t* security_ctx
) {
    guardian_error_info_t error;
    guardian_status_t status = GUARDIAN_STATUS_ERROR;
    int i;

    /* Validate input parameters */
    GUARDIAN_KENV_CHECK_NAME(name);
    GUARDIAN_KENV_CHECK_VALUE(value, size);
    GUARDIAN_KENV_CHECK_CONTEXT(security_ctx);

    /* Acquire lock with timeout */
    if (mtx_trylock(&kenv_lock) != 0) {
        GUARDIAN_ERROR_PUSH(GUARDIAN_ERROR_BUSY, "Kenv lock acquisition failed");
        return GUARDIAN_STATUS_BUSY;
    }

    /* Search for variable with bounds checking */
    for (i = 0; i < kenv_count && i < GUARDIAN_MAX_KENV_VARS; i++) {
        if (strcmp(kenv_entries[i].name, name) == 0) {
            /* Verify security context and permissions */
            if (!(security_ctx->uid == kenv_entries[i].security_context.uid ||
                  security_ctx->capabilities & GUARDIAN_CAP_KENV_READ)) {
                GUARDIAN_ERROR_PUSH(GUARDIAN_ERROR_PERMISSION, "Insufficient permissions");
                status = GUARDIAN_STATUS_ERROR;
                goto cleanup;
            }

            /* Copy value with bounds checking */
            size_t value_len = strlcpy(value, kenv_entries[i].value, size);
            if (value_len >= size) {
                GUARDIAN_ERROR_PUSH(GUARDIAN_ERROR_OVERFLOW, "Value buffer too small");
                status = GUARDIAN_STATUS_ERROR;
                goto cleanup;
            }

            /* Log successful access */
            GUARDIAN_KENV_AUDIT_ACCESS(security_ctx, name, "read");
            status = GUARDIAN_STATUS_SUCCESS;
            break;
        }
    }

    if (status != GUARDIAN_STATUS_SUCCESS) {
        GUARDIAN_ERROR_PUSH(GUARDIAN_ERROR_NOT_FOUND, "Kenv variable not found");
    }

cleanup:
    mtx_unlock(&kenv_lock);
    return status;
}

/* Set kernel environment variable with security validation */
guardian_status_t guardian_kenv_set(
    const char* name,
    const char* value,
    guardian_kenv_security_ctx_t* security_ctx,
    uint32_t flags
) {
    guardian_error_info_t error;
    guardian_status_t status = GUARDIAN_STATUS_ERROR;
    int i;

    /* Validate input parameters */
    GUARDIAN_KENV_CHECK_NAME(name);
    GUARDIAN_KENV_CHECK_VALUE(value, GUARDIAN_MAX_KENV_VALUE);
    GUARDIAN_KENV_CHECK_CONTEXT(security_ctx);
    GUARDIAN_KENV_CHECK_FLAGS(flags);

    /* Verify write permissions */
    if (!(security_ctx->capabilities & GUARDIAN_CAP_KENV_WRITE)) {
        GUARDIAN_ERROR_PUSH(GUARDIAN_ERROR_PERMISSION, "Insufficient permissions");
        return GUARDIAN_STATUS_ERROR;
    }

    /* Acquire lock with timeout */
    if (mtx_trylock(&kenv_lock) != 0) {
        GUARDIAN_ERROR_PUSH(GUARDIAN_ERROR_BUSY, "Kenv lock acquisition failed");
        return GUARDIAN_STATUS_BUSY;
    }

    /* Check for existing entry */
    for (i = 0; i < kenv_count && i < GUARDIAN_MAX_KENV_VARS; i++) {
        if (strcmp(kenv_entries[i].name, name) == 0) {
            /* Check if variable is read-only */
            if (kenv_entries[i].flags & GUARDIAN_KENV_FLAG_READONLY) {
                GUARDIAN_ERROR_PUSH(GUARDIAN_ERROR_PERMISSION, "Variable is read-only");
                status = GUARDIAN_STATUS_ERROR;
                goto cleanup;
            }

            /* Update existing entry */
            strlcpy(kenv_entries[i].value, value, GUARDIAN_MAX_KENV_VALUE);
            kenv_entries[i].flags = flags;
            kenv_entries[i].last_modified = time_second;
            memcpy(&kenv_entries[i].security_context, security_ctx, 
                   sizeof(guardian_security_context_t));

            GUARDIAN_KENV_AUDIT_ACCESS(security_ctx, name, "update");
            status = GUARDIAN_STATUS_SUCCESS;
            goto cleanup;
        }
    }

    /* Add new entry if space available */
    if (kenv_count < GUARDIAN_MAX_KENV_VARS) {
        strlcpy(kenv_entries[kenv_count].name, name, GUARDIAN_MAX_NAME);
        strlcpy(kenv_entries[kenv_count].value, value, GUARDIAN_MAX_KENV_VALUE);
        kenv_entries[kenv_count].flags = flags;
        kenv_entries[kenv_count].last_modified = time_second;
        memcpy(&kenv_entries[kenv_count].security_context, security_ctx,
               sizeof(guardian_security_context_t));

        kenv_count++;
        GUARDIAN_KENV_AUDIT_ACCESS(security_ctx, name, "create");
        status = GUARDIAN_STATUS_SUCCESS;
    } else {
        GUARDIAN_ERROR_PUSH(GUARDIAN_ERROR_QUOTA, "Maximum kenv variables reached");
        status = GUARDIAN_STATUS_ERROR;
    }

cleanup:
    mtx_unlock(&kenv_lock);
    return status;
}

/* Remove kernel environment variable with security validation */
guardian_status_t guardian_kenv_unset(
    const char* name,
    guardian_kenv_security_ctx_t* security_ctx
) {
    guardian_error_info_t error;
    guardian_status_t status = GUARDIAN_STATUS_ERROR;
    int i, j;

    /* Validate input parameters */
    GUARDIAN_KENV_CHECK_NAME(name);
    GUARDIAN_KENV_CHECK_CONTEXT(security_ctx);

    /* Verify delete permissions */
    if (!(security_ctx->capabilities & GUARDIAN_CAP_KENV_WRITE)) {
        GUARDIAN_ERROR_PUSH(GUARDIAN_ERROR_PERMISSION, "Insufficient permissions");
        return GUARDIAN_STATUS_ERROR;
    }

    /* Acquire lock with timeout */
    if (mtx_trylock(&kenv_lock) != 0) {
        GUARDIAN_ERROR_PUSH(GUARDIAN_ERROR_BUSY, "Kenv lock acquisition failed");
        return GUARDIAN_STATUS_BUSY;
    }

    /* Find and remove entry */
    for (i = 0; i < kenv_count && i < GUARDIAN_MAX_KENV_VARS; i++) {
        if (strcmp(kenv_entries[i].name, name) == 0) {
            /* Check if variable is read-only */
            if (kenv_entries[i].flags & GUARDIAN_KENV_FLAG_READONLY) {
                GUARDIAN_ERROR_PUSH(GUARDIAN_ERROR_PERMISSION, "Variable is read-only");
                status = GUARDIAN_STATUS_ERROR;
                goto cleanup;
            }

            /* Shift remaining entries */
            for (j = i; j < kenv_count - 1; j++) {
                memcpy(&kenv_entries[j], &kenv_entries[j + 1], 
                       sizeof(guardian_kenv_entry_t));
            }

            /* Clear last entry and decrement count */
            memset(&kenv_entries[kenv_count - 1], 0, sizeof(guardian_kenv_entry_t));
            kenv_count--;

            GUARDIAN_KENV_AUDIT_ACCESS(security_ctx, name, "delete");
            status = GUARDIAN_STATUS_SUCCESS;
            break;
        }
    }

    if (status != GUARDIAN_STATUS_SUCCESS) {
        GUARDIAN_ERROR_PUSH(GUARDIAN_ERROR_NOT_FOUND, "Kenv variable not found");
    }

cleanup:
    mtx_unlock(&kenv_lock);
    return status;
}