/*
 * Guardian System - Debug Helper Functions Implementation
 * 
 * Secure debugging utilities and helper functions for the Guardian system's 
 * FreeBSD kernel module with comprehensive security controls and audit support.
 *
 * Version: 1.0.0
 * FreeBSD Version: 13.0
 */

#include <sys/types.h>    /* FreeBSD 13.0 */
#include <sys/param.h>    /* FreeBSD 13.0 */
#include <sys/kernel.h>   /* FreeBSD 13.0 */
#include <sys/systm.h>    /* FreeBSD 13.0 */
#include <sys/stack.h>    /* FreeBSD 13.0 */
#include <sys/proc.h>     /* FreeBSD 13.0 */

#include "debug_helpers.h"
#include "guardian_errors.h"
#include "guardian_types.h"

/* Global debug state */
static volatile int g_debug_enabled = GUARDIAN_DEBUG_ENABLED;

/* Thread-local debug buffer */
static __thread char g_debug_buffer[GUARDIAN_DEBUG_BUFFER_SIZE];

/* Global security context */
static guardian_security_context_t* g_security_context = NULL;

/*
 * Securely logs a debug message with source location information and audit trail
 */
guardian_status_t
guardian_debug_log(guardian_security_context_t* sec_ctx, const char* format, ...) {
    va_list args;
    size_t len = 0;
    guardian_error_info_t error_info;

    /* Validate security context */
    if (guardian_validate_security_context(sec_ctx) != GUARDIAN_STATUS_SUCCESS) {
        return GUARDIAN_STATUS_ERROR;
    }

    /* Check debug enabled state */
    if (!g_debug_enabled) {
        return GUARDIAN_STATUS_SUCCESS;
    }

    /* Initialize thread-local buffer */
    memset(g_debug_buffer, 0, GUARDIAN_DEBUG_BUFFER_SIZE);

    /* Add source location prefix */
    len = snprintf(g_debug_buffer, GUARDIAN_DEBUG_BUFFER_SIZE,
        "[%s:%d %s] ", __FILE__, __LINE__, __func__);

    if (len >= GUARDIAN_DEBUG_BUFFER_SIZE) {
        return GUARDIAN_STATUS_ERROR;
    }

    /* Format message with variable arguments */
    va_start(args, format);
    vsnprintf(g_debug_buffer + len, 
        GUARDIAN_DEBUG_BUFFER_SIZE - len, 
        format, 
        args);
    va_end(args);

    /* Filter sensitive data */
    if (guardian_filter_sensitive_data(g_debug_buffer) != GUARDIAN_STATUS_SUCCESS) {
        return GUARDIAN_STATUS_ERROR;
    }

    /* Log message to kernel debug buffer */
    log(LOG_DEBUG, "%s\n", g_debug_buffer);

    /* Record audit trail */
    error_info.code = GUARDIAN_SUCCESS;
    error_info.severity = GUARDIAN_SEVERITY_INFO;
    strlcpy(error_info.message, g_debug_buffer, GUARDIAN_ERROR_BUFFER_SIZE);
    error_info.security_context = *sec_ctx;
    
    guardian_audit_log(&error_info);

    return GUARDIAN_STATUS_SUCCESS;
}

/*
 * Securely captures and prints the current call stack with security validation
 */
guardian_status_t
guardian_backtrace(guardian_security_context_t* sec_ctx, uint32_t skip_frames) {
    struct stack st;
    int i;
    guardian_error_info_t error_info;

    /* Validate security context */
    if (guardian_validate_security_context(sec_ctx) != GUARDIAN_STATUS_SUCCESS) {
        return GUARDIAN_STATUS_ERROR;
    }

    /* Initialize stack trace buffer */
    stack_zero(&st);

    /* Capture stack trace */
    stack_save(&st);

    /* Skip requested frames */
    for (i = 0; i < skip_frames && !stack_empty(&st); i++) {
        stack_pop(&st);
    }

    /* Print remaining stack frames */
    while (!stack_empty(&st)) {
        vm_offset_t pc;
        
        pc = stack_pop(&st);

        /* Validate memory access */
        if (guardian_validate_memory_bounds((void*)pc, sizeof(vm_offset_t)) 
            != GUARDIAN_STATUS_SUCCESS) {
            continue;
        }

        /* Format and log stack frame */
        snprintf(g_debug_buffer, GUARDIAN_DEBUG_BUFFER_SIZE,
            "  %p", (void*)pc);
        
        log(LOG_DEBUG, "%s\n", g_debug_buffer);
    }

    /* Record audit trail */
    error_info.code = GUARDIAN_SUCCESS;
    error_info.severity = GUARDIAN_SEVERITY_INFO;
    strlcpy(error_info.message, "Stack trace captured", GUARDIAN_ERROR_BUFFER_SIZE);
    error_info.security_context = *sec_ctx;
    
    guardian_audit_log(&error_info);

    return GUARDIAN_STATUS_SUCCESS;
}

/*
 * Securely dumps memory contents with boundary protection and access validation
 */
guardian_status_t
guardian_memory_dump(guardian_security_context_t* sec_ctx, const void* addr, size_t len) {
    size_t i;
    const unsigned char* p = addr;
    guardian_error_info_t error_info;

    /* Validate security context */
    if (guardian_validate_security_context(sec_ctx) != GUARDIAN_STATUS_SUCCESS) {
        return GUARDIAN_STATUS_ERROR;
    }

    /* Validate memory bounds */
    if (guardian_validate_memory_bounds(addr, len) != GUARDIAN_STATUS_SUCCESS) {
        return GUARDIAN_STATUS_ERROR;
    }

    /* Initialize output buffer */
    memset(g_debug_buffer, 0, GUARDIAN_DEBUG_BUFFER_SIZE);

    /* Format memory dump header */
    snprintf(g_debug_buffer, GUARDIAN_DEBUG_BUFFER_SIZE,
        "Memory dump at %p (length: %zu):\n", addr, len);
    log(LOG_DEBUG, "%s", g_debug_buffer);

    /* Dump memory contents in hex + ASCII format */
    for (i = 0; i < len; i += 16) {
        size_t j, line_len;
        
        /* Format address */
        line_len = snprintf(g_debug_buffer, GUARDIAN_DEBUG_BUFFER_SIZE,
            "%p: ", (void*)(p + i));

        /* Format hex values */
        for (j = 0; j < 16 && (i + j) < len; j++) {
            line_len += snprintf(g_debug_buffer + line_len,
                GUARDIAN_DEBUG_BUFFER_SIZE - line_len,
                "%02x ", p[i + j]);
        }

        /* Pad with spaces */
        while (j++ < 16) {
            line_len += snprintf(g_debug_buffer + line_len,
                GUARDIAN_DEBUG_BUFFER_SIZE - line_len, "   ");
        }

        /* Add ASCII representation */
        line_len += snprintf(g_debug_buffer + line_len,
            GUARDIAN_DEBUG_BUFFER_SIZE - line_len, " |");

        for (j = 0; j < 16 && (i + j) < len; j++) {
            unsigned char c = p[i + j];
            line_len += snprintf(g_debug_buffer + line_len,
                GUARDIAN_DEBUG_BUFFER_SIZE - line_len,
                "%c", isprint(c) ? c : '.');
        }

        line_len += snprintf(g_debug_buffer + line_len,
            GUARDIAN_DEBUG_BUFFER_SIZE - line_len, "|\n");

        /* Log the formatted line */
        log(LOG_DEBUG, "%s", g_debug_buffer);
    }

    /* Record audit trail */
    error_info.code = GUARDIAN_SUCCESS;
    error_info.severity = GUARDIAN_SEVERITY_INFO;
    snprintf(error_info.message, GUARDIAN_ERROR_BUFFER_SIZE,
        "Memory dump performed at %p (length: %zu)", addr, len);
    error_info.security_context = *sec_ctx;
    
    guardian_audit_log(&error_info);

    return GUARDIAN_STATUS_SUCCESS;
}

/* Internal helper function to filter sensitive data from debug messages */
static guardian_status_t
guardian_filter_sensitive_data(char* buffer) {
    /* Add implementation-specific sensitive data filtering */
    /* This is a placeholder for the actual implementation */
    return GUARDIAN_STATUS_SUCCESS;
}