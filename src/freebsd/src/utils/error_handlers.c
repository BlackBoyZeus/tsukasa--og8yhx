/*
 * Guardian System - Error Handling Utilities Implementation
 * FreeBSD Kernel Module
 *
 * Implements robust error handling, logging, and management functionality
 * for kernel-level operations with support for error chaining, per-CPU buffers,
 * rate limiting, and detailed context information.
 *
 * Version: 1.0.0
 * FreeBSD 13.0+ Kernel Module
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/pcpu.h>
#include "../include/guardian_errors.h"
#include "error_handlers.h"

/* Per-CPU error chain buffer aligned to cache line */
static __thread guardian_error_t g_error_chain_pcpu[GUARDIAN_MAX_ERROR_CHAIN] 
    __aligned(CACHE_LINE_SIZE);

/* Per-CPU error count */
static __thread atomic_t g_error_count_pcpu __aligned(CACHE_LINE_SIZE);

/* Per-CPU error log buffer */
static __thread char g_error_log_buffer_pcpu[GUARDIAN_ERROR_LOG_BUFFER_SIZE] 
    __aligned(CACHE_LINE_SIZE);

/* Global error mutex for synchronization */
static struct mtx g_error_mutex;

/* Global rate limiting counter */
static atomic_t g_error_rate_limit;

/* Error statistics structure */
struct guardian_error_stats {
    atomic_t total_errors;
    atomic_t errors_by_severity[5]; /* Indexed by GUARDIAN_ERROR_SEVERITY_LEVELS */
    atomic_t rate_limited_count;
} __aligned(CACHE_LINE_SIZE);

static struct guardian_error_stats g_error_stats;

/* Initialize error handling subsystem */
guardian_error_t guardian_error_init(void) {
    /* Initialize global mutex */
    mtx_init(&g_error_mutex, "guardian_error_mutex", NULL, MTX_DEF);

    /* Initialize per-CPU error chains */
    CPU_FOREACH(cpu) {
        memset(DPCPU_ID_PTR(cpu, g_error_chain_pcpu), 0, 
               sizeof(guardian_error_t) * GUARDIAN_MAX_ERROR_CHAIN);
        atomic_store_rel_int(DPCPU_ID_PTR(cpu, g_error_count_pcpu), 0);
        memset(DPCPU_ID_PTR(cpu, g_error_log_buffer_pcpu), 0, 
               GUARDIAN_ERROR_LOG_BUFFER_SIZE);
    }

    /* Initialize rate limiting */
    atomic_store_rel_int(&g_error_rate_limit, 0);

    /* Initialize error statistics */
    memset(&g_error_stats, 0, sizeof(struct guardian_error_stats));

    return GUARDIAN_SUCCESS;
}

/* Log an error with context information */
void guardian_error_log(
    guardian_error_t error_code,
    uint8_t severity,
    const char *file,
    int line,
    const char *func,
    const char *fmt,
    ...) {
    
    va_list args;
    char *log_buffer;
    size_t remaining;
    int current_count;

    /* Rate limiting check */
    if (atomic_load_acq_int(&g_error_rate_limit) >= GUARDIAN_ERROR_RATE_LIMIT) {
        atomic_add_rel_int(&g_error_stats.rate_limited_count, 1);
        return;
    }

    /* Validate severity */
    if (severity > GUARDIAN_SEV_CRITICAL) {
        severity = GUARDIAN_SEV_ERROR;
    }

    /* Get per-CPU buffer */
    log_buffer = DPCPU_GET(g_error_log_buffer_pcpu);
    remaining = GUARDIAN_ERROR_LOG_BUFFER_SIZE;

    /* Format base error information with bounds checking */
    int printed = snprintf(log_buffer, remaining, "[%s:%d][%s] ", 
                          file ? file : "unknown",
                          line,
                          func ? func : "unknown");
    
    if (printed > 0 && printed < remaining) {
        remaining -= printed;
        log_buffer += printed;

        /* Format variable message */
        va_start(args, fmt);
        vsnprintf(log_buffer, remaining, fmt, args);
        va_end(args);
    }

    /* Update error chain atomically */
    current_count = atomic_load_acq_int(&g_error_count_pcpu);
    if (current_count < GUARDIAN_MAX_ERROR_CHAIN) {
        g_error_chain_pcpu[current_count] = error_code;
        atomic_add_rel_int(&g_error_count_pcpu, 1);
    }

    /* Update statistics */
    atomic_add_rel_int(&g_error_stats.total_errors, 1);
    atomic_add_rel_int(&g_error_stats.errors_by_severity[severity], 1);

    /* Rate limiting increment */
    atomic_add_rel_int(&g_error_rate_limit, 1);

    /* Log to kernel log for high severity errors */
    if (severity >= GUARDIAN_SEV_ERROR) {
        log(LOG_ERR, "Guardian Error: %s\n", DPCPU_GET(g_error_log_buffer_pcpu));
    }
}

/* Clear error state */
void guardian_error_clear(void) {
    mtx_lock(&g_error_mutex);

    /* Clear per-CPU error chain */
    memset(DPCPU_GET(g_error_chain_pcpu), 0, 
           sizeof(guardian_error_t) * GUARDIAN_MAX_ERROR_CHAIN);
    atomic_store_rel_int(&g_error_count_pcpu, 0);
    memset(DPCPU_GET(g_error_log_buffer_pcpu), 0, GUARDIAN_ERROR_LOG_BUFFER_SIZE);

    mtx_unlock(&g_error_mutex);
}

/* Retrieve error chain */
guardian_error_t guardian_error_get_chain(
    guardian_error_t *chain,
    int *count,
    uint8_t min_severity) {
    
    int current_count;

    if (!chain || !count) {
        return GUARDIAN_E_INVALID_PARAM;
    }

    /* Get current error count */
    current_count = atomic_load_acq_int(&g_error_count_pcpu);
    *count = current_count;

    /* Copy error chain if there are errors */
    if (current_count > 0) {
        memcpy(chain, DPCPU_GET(g_error_chain_pcpu),
               sizeof(guardian_error_t) * current_count);
    }

    return GUARDIAN_SUCCESS;
}