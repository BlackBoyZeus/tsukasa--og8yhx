/*
 * Guardian System - Error Handler Implementation
 * 
 * Implementation of error handling utilities for the Guardian system's FreeBSD
 * kernel module with comprehensive security features and audit trail support.
 *
 * Version: 1.0.0
 * FreeBSD Version: 13.0
 */

#include <sys/types.h>    /* FreeBSD 13.0 */
#include <sys/param.h>    /* FreeBSD 13.0 */
#include <sys/kernel.h>   /* FreeBSD 13.0 */
#include <sys/systm.h>    /* FreeBSD 13.0 */
#include <sys/malloc.h>   /* FreeBSD 13.0 */
#include <sys/mutex.h>    /* FreeBSD 13.0 */

#include "../include/guardian_errors.h"
#include "error_handlers.h"
#include "debug_helpers.h"

/* Global error handling state */
static guardian_error_handler_t g_error_handlers[GUARDIAN_MAX_ERROR_HANDLERS];
static size_t g_handler_count = 0;
static guardian_error_chain_t g_error_chain;
static struct mtx g_error_mutex;
static guardian_security_context_t g_security_context;

/* Memory allocation tag */
MALLOC_DECLARE(M_GUARDIAN_ERROR);
MALLOC_DEFINE(M_GUARDIAN_ERROR, "guardian_error", "Guardian Error Handling");

/* Initialize error handling subsystem */
guardian_status_t
guardian_error_init(void)
{
    /* Initialize error mutex */
    mtx_init(&g_error_mutex, "guardian_error_mutex", NULL, MTX_DEF);
    
    /* Initialize error chain */
    bzero(&g_error_chain, sizeof(guardian_error_chain_t));
    mtx_init(&g_error_chain.chain_lock, "guardian_error_chain_lock", NULL, MTX_DEF);
    
    /* Initialize handler registry */
    bzero(g_error_handlers, sizeof(g_error_handlers));
    g_handler_count = 0;
    
    /* Initialize security context */
    bzero(&g_security_context, sizeof(guardian_security_context_t));
    g_security_context.security_flags = GUARDIAN_SECURITY_ENABLED;
    
    return GUARDIAN_SUCCESS;
}

/* Log error with security context validation */
void
guardian_error_log(const guardian_error_info_t *error_info,
                  const guardian_security_context_t *sec_context)
{
    guardian_status_t status;
    char audit_buffer[GUARDIAN_ERROR_AUDIT_BUFFER];
    
    /* Validate parameters */
    if (!error_info || !sec_context) {
        guardian_debug_log(&g_security_context, 
            "Invalid parameters in guardian_error_log");
        return;
    }
    
    /* Acquire error mutex */
    mtx_lock(&g_error_mutex);
    
    /* Validate security context */
    if (!(sec_context->capabilities & GUARDIAN_CAP_ERROR_LOG)) {
        mtx_unlock(&g_error_mutex);
        guardian_debug_log(&g_security_context,
            "Insufficient privileges for error logging");
        return;
    }
    
    /* Add error to chain if space available */
    if (g_error_chain.count < GUARDIAN_MAX_ERROR_CHAIN) {
        guardian_error_info_t *chain_error = 
            &g_error_chain.errors[g_error_chain.count++];
        
        /* Copy error info with security context */
        bcopy(error_info, chain_error, sizeof(guardian_error_info_t));
        chain_error->security_context = *sec_context;
        chain_error->timestamp = time_second;
        
        /* Generate audit trail */
        snprintf(audit_buffer, sizeof(audit_buffer),
            "Error logged: code=%d, severity=%d, context=0x%llx",
            error_info->code, error_info->severity,
            (unsigned long long)sec_context->security_flags);
        
        guardian_audit_log(&g_security_context, audit_buffer);
        
        /* Invoke registered handlers */
        for (size_t i = 0; i < g_handler_count; i++) {
            if (g_error_handlers[i]) {
                status = g_error_handlers[i](error_info, sec_context, NULL);
                if (status != GUARDIAN_SUCCESS) {
                    guardian_debug_log(&g_security_context,
                        "Handler %zu failed with status %d", i, status);
                }
            }
        }
    }
    
    mtx_unlock(&g_error_mutex);
}

/* Register error handler with security validation */
guardian_status_t
guardian_error_register_handler(guardian_error_handler_t handler,
                              guardian_security_level_t security_level)
{
    guardian_status_t status = GUARDIAN_SUCCESS;
    
    /* Validate parameters */
    if (!handler) {
        return GUARDIAN_ERROR_INVALID_PARAM;
    }
    
    /* Acquire error mutex */
    mtx_lock(&g_error_mutex);
    
    /* Check for available slots */
    if (g_handler_count >= GUARDIAN_MAX_ERROR_HANDLERS) {
        status = GUARDIAN_ERROR_QUOTA;
        goto cleanup;
    }
    
    /* Validate security level */
    if (security_level > GUARDIAN_SECURITY_LEVEL_MAX) {
        status = GUARDIAN_ERROR_SECURITY;
        goto cleanup;
    }
    
    /* Register handler */
    g_error_handlers[g_handler_count++] = handler;
    
    /* Log registration */
    guardian_audit_log(&g_security_context,
        "Error handler registered at index %zu with security level %d",
        g_handler_count - 1, security_level);
    
cleanup:
    mtx_unlock(&g_error_mutex);
    return status;
}

/* Clear error chain with security validation */
guardian_status_t
guardian_error_clear_chain(guardian_security_context_t *sec_context)
{
    guardian_status_t status = GUARDIAN_SUCCESS;
    
    /* Validate security context */
    if (!sec_context) {
        return GUARDIAN_ERROR_INVALID_PARAM;
    }
    
    /* Acquire error mutex */
    mtx_lock(&g_error_mutex);
    
    /* Check security privileges */
    if (!(sec_context->capabilities & GUARDIAN_CAP_ERROR_CLEAR)) {
        status = GUARDIAN_ERROR_PERMISSION;
        goto cleanup;
    }
    
    /* Clear error chain */
    explicit_bzero(&g_error_chain.errors,
                  sizeof(guardian_error_info_t) * GUARDIAN_MAX_ERROR_CHAIN);
    g_error_chain.count = 0;
    
    /* Log clear operation */
    guardian_audit_log(&g_security_context,
        "Error chain cleared by security context 0x%llx",
        (unsigned long long)sec_context->security_flags);
    
cleanup:
    mtx_unlock(&g_error_mutex);
    return status;
}

/* Module cleanup */
void
guardian_error_cleanup(void)
{
    /* Acquire error mutex */
    mtx_lock(&g_error_mutex);
    
    /* Clear handlers and chain */
    bzero(g_error_handlers, sizeof(g_error_handlers));
    g_handler_count = 0;
    explicit_bzero(&g_error_chain, sizeof(g_error_chain_t));
    
    /* Destroy mutexes */
    mtx_unlock(&g_error_mutex);
    mtx_destroy(&g_error_mutex);
    mtx_destroy(&g_error_chain.chain_lock);
}