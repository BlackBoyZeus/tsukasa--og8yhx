/*
 * Guardian System - System Monitoring Implementation
 * 
 * FreeBSD kernel-level system monitoring component providing real-time monitoring
 * of system resources, process states, and hardware metrics with enhanced security.
 *
 * Version: 1.0.0
 * FreeBSD Version: 13.0
 */

#include <sys/param.h>      /* FreeBSD 13.0 - System parameters */
#include <sys/kernel.h>     /* FreeBSD 13.0 - Kernel interfaces */
#include <sys/proc.h>       /* FreeBSD 13.0 - Process management */
#include <sys/sysctl.h>     /* FreeBSD 13.0 - System control */
#include <sys/resourcevar.h>/* FreeBSD 13.0 - Resource usage */
#include "system_monitor.h"
#include "kernel_utils.h"
#include "resource_monitor.h"

/* Global state with atomic operations */
static guardian_monitor_config_t g_monitor_config;
static struct thread *g_monitor_thread;
static struct mtx g_monitor_mutex;
static _Atomic bool g_monitor_running = false;
static guardian_security_context_t g_security_context;

/* Internal metrics buffer with secure allocation */
static guardian_system_metrics_t *g_metrics_buffer;

/* Security validation macro */
#define VALIDATE_SECURITY_CONTEXT(ctx) do { \
    if (!ctx || (ctx->security_flags & GUARDIAN_SECURITY_MAGIC) != GUARDIAN_SECURITY_MAGIC) { \
        GUARDIAN_ERROR_PUSH(GUARDIAN_ERROR_SECURITY, "Invalid security context"); \
        return GUARDIAN_STATUS_ERROR; \
    } \
} while (0)

/*
 * Enhanced system monitoring thread with security validation
 */
static void
system_monitor_thread(void *arg)
{
    guardian_resource_stats_t resource_stats;
    guardian_system_metrics_t current_metrics;
    struct timespec ts;
    int error;

    /* Thread initialization with security context */
    thread_lock(curthread);
    sched_prio(curthread, PRIBIO);
    thread_unlock(curthread);

    while (atomic_load(&g_monitor_running)) {
        /* Secure resource statistics collection */
        error = guardian_resource_get_stats(&resource_stats, &g_security_context);
        if (error != GUARDIAN_STATUS_SUCCESS) {
            GUARDIAN_ERROR_PUSH(GUARDIAN_ERROR_STATE, "Failed to get resource stats");
            continue;
        }

        /* Update metrics with atomic operations */
        mtx_lock(&g_monitor_mutex);
        
        /* CPU metrics */
        current_metrics.cpu_usage = resource_stats.cpu_usage;
        current_metrics.cpu_affinity = curthread->td_cpuset;
        
        /* Memory metrics with secure access */
        error = guardian_get_memory_stats_atomic(&current_metrics.memory_stats, 
                                               &g_security_context);
        if (error != GUARDIAN_STATUS_SUCCESS) {
            mtx_unlock(&g_monitor_mutex);
            continue;
        }

        /* Process metrics */
        current_metrics.process_count = resource_stats.process_count;
        
        /* System pressure metrics */
        current_metrics.pressure_metrics.cpu_pressure = 
            (resource_stats.cpu_usage > GUARDIAN_CPU_THRESHOLD_PERCENT) ? 100 : 
            (resource_stats.cpu_usage * 100) / GUARDIAN_CPU_THRESHOLD_PERCENT;
            
        current_metrics.pressure_metrics.memory_pressure = 
            (current_metrics.memory_stats.used * 100) / current_metrics.memory_stats.total;
            
        current_metrics.pressure_metrics.io_pressure = 
            resource_stats.hardware_metrics.gpu_usage;

        /* Update timestamp */
        nanouptime(&ts);
        current_metrics.timestamp = ts.tv_sec * 1000000000ULL + ts.tv_nsec;

        /* Secure copy to global buffer */
        memcpy(g_metrics_buffer, &current_metrics, sizeof(guardian_system_metrics_t));
        
        mtx_unlock(&g_monitor_mutex);

        /* Invoke registered callbacks with security context */
        for (uint32_t i = 0; i < g_monitor_config.callback_count; i++) {
            if (g_monitor_config.callbacks[i]) {
                g_monitor_config.callbacks[i](g_metrics_buffer, 
                                           g_monitor_config.callback_data[i]);
            }
        }

        /* Sleep with interrupt handling */
        error = tsleep(&g_monitor_thread, PRIBIO | PCATCH, "guardian_monitor", 
                      hz * g_monitor_config.interval_ms / 1000);
        if (error && error != EWOULDBLOCK) {
            break;
        }
    }

    kthread_exit();
}

/*
 * Initialize system monitoring with security validation
 */
int
system_monitor_init(guardian_monitor_config_t *config, 
                   guardian_security_context_t *security_ctx)
{
    int error;

    /* Validate security context */
    VALIDATE_SECURITY_CONTEXT(security_ctx);

    /* Validate configuration */
    if (!config || config->interval_ms < 100 || config->interval_ms > 10000) {
        GUARDIAN_ERROR_PUSH(GUARDIAN_ERROR_INVALID_PARAM, "Invalid monitor config");
        return GUARDIAN_STATUS_ERROR;
    }

    /* Initialize mutex with adaptive spinning */
    mtx_init(&g_monitor_mutex, "guardian_monitor_mtx", NULL, MTX_DEF | MTX_SPIN);

    /* Secure memory allocation for metrics buffer */
    g_metrics_buffer = guardian_kmalloc_secure(sizeof(guardian_system_metrics_t),
                                             M_WAITOK | M_ZERO, security_ctx);
    if (!g_metrics_buffer) {
        GUARDIAN_ERROR_PUSH(GUARDIAN_ERROR_MEMORY, "Failed to allocate metrics buffer");
        return GUARDIAN_STATUS_ERROR;
    }

    /* Copy configuration and security context */
    memcpy(&g_monitor_config, config, sizeof(guardian_monitor_config_t));
    memcpy(&g_security_context, security_ctx, sizeof(guardian_security_context_t));

    /* Create monitoring kernel thread */
    error = kthread_create(system_monitor_thread, NULL, &g_monitor_thread,
                          RFHIGHPID, 0, "guardian_monitor");
    if (error) {
        guardian_kfree_secure(g_metrics_buffer, security_ctx);
        mtx_destroy(&g_monitor_mutex);
        GUARDIAN_ERROR_PUSH(GUARDIAN_ERROR_STATE, "Failed to create monitor thread");
        return GUARDIAN_STATUS_ERROR;
    }

    /* Start monitoring */
    atomic_store(&g_monitor_running, true);

    return GUARDIAN_STATUS_SUCCESS;
}

/*
 * Clean up system monitoring with secure memory handling
 */
void
system_monitor_cleanup(void)
{
    /* Stop monitoring thread */
    atomic_store(&g_monitor_running, false);
    
    /* Wait for thread completion */
    if (g_monitor_thread) {
        tsleep(&g_monitor_thread, PRIBIO, "guardian_cleanup", hz);
    }

    /* Secure cleanup */
    mtx_lock(&g_monitor_mutex);
    
    if (g_metrics_buffer) {
        guardian_kfree_secure(g_metrics_buffer, &g_security_context);
        g_metrics_buffer = NULL;
    }
    
    memset(&g_monitor_config, 0, sizeof(guardian_monitor_config_t));
    memset(&g_security_context, 0, sizeof(guardian_security_context_t));
    
    mtx_unlock(&g_monitor_mutex);
    mtx_destroy(&g_monitor_mutex);
}

/*
 * Get current system metrics with security validation
 */
int
system_monitor_get_metrics(guardian_system_metrics_t *metrics,
                          guardian_security_context_t *security_ctx)
{
    /* Validate parameters */
    if (!metrics) {
        GUARDIAN_ERROR_PUSH(GUARDIAN_ERROR_INVALID_PARAM, "Invalid metrics pointer");
        return GUARDIAN_STATUS_ERROR;
    }

    VALIDATE_SECURITY_CONTEXT(security_ctx);

    /* Thread-safe metrics copy */
    mtx_lock(&g_monitor_mutex);
    memcpy(metrics, g_metrics_buffer, sizeof(guardian_system_metrics_t));
    mtx_unlock(&g_monitor_mutex);

    return GUARDIAN_STATUS_SUCCESS;
}