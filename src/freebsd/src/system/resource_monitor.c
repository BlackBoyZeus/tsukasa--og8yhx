/*
 * Guardian System - Resource Monitor Implementation
 * 
 * FreeBSD kernel module implementation for system resource monitoring with
 * gaming-specific optimizations, security validation, and power state awareness.
 *
 * Version: 1.0.0
 * FreeBSD Version: 13.0
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/proc.h>
#include <sys/sysctl.h>
#include <sys/resource.h>
#include <sys/power.h>

#include "resource_monitor.h"
#include "kernel_utils.h"

/* Global variables with cache-line alignment */
static guardian_resource_monitor_t* __attribute__((aligned(64))) g_resource_monitor;
static guardian_resource_stats_t* __attribute__((aligned(64))) g_resource_stats;
static guardian_game_stats_t* __attribute__((aligned(64))) g_game_stats;
static struct thread* __attribute__((aligned(64))) g_monitor_thread;
static _Atomic bool g_monitor_running;
static guardian_security_context_t* __attribute__((aligned(64))) g_security_context;

/* Internal function prototypes */
static void* monitor_thread_func(void* arg);
static guardian_status_t update_resource_stats(
    guardian_resource_stats_t* stats,
    guardian_game_stats_t* game_stats,
    guardian_security_context_t* security_context
);

/*
 * Initialize resource monitoring subsystem
 */
__attribute__((cold))
__attribute__((visibility("hidden")))
guardian_status_t resource_monitor_init(guardian_security_context_t* security_context) {
    guardian_status_t status;

    /* Validate security context */
    GUARDIAN_VALIDATE_SECURITY_CONTEXT(security_context);

    /* Allocate monitor structure with security validation */
    g_resource_monitor = guardian_secure_kmalloc(
        sizeof(guardian_resource_monitor_t),
        GUARDIAN_KMALLOC_WAIT,
        security_context
    );
    if (g_resource_monitor == NULL) {
        GUARDIAN_ERROR_PUSH(GUARDIAN_ERROR_MEMORY, "Failed to allocate resource monitor");
        return GUARDIAN_STATUS_ERROR;
    }

    /* Allocate statistics structures */
    g_resource_stats = guardian_secure_kmalloc(
        sizeof(guardian_resource_stats_t),
        GUARDIAN_KMALLOC_WAIT,
        security_context
    );
    g_game_stats = guardian_secure_kmalloc(
        sizeof(guardian_game_stats_t),
        GUARDIAN_KMALLOC_WAIT,
        security_context
    );
    if (!g_resource_stats || !g_game_stats) {
        GUARDIAN_ERROR_PUSH(GUARDIAN_ERROR_MEMORY, "Failed to allocate statistics structures");
        goto cleanup;
    }

    /* Store security context */
    g_security_context = security_context;

    /* Initialize monitoring state */
    g_monitor_running = false;
    memset(g_resource_stats, 0, sizeof(guardian_resource_stats_t));
    memset(g_game_stats, 0, sizeof(guardian_game_stats_t));

    /* Create monitoring thread */
    status = kthread_create(
        monitor_thread_func,
        NULL,
        &g_monitor_thread,
        "guardian_monitor"
    );
    if (status != 0) {
        GUARDIAN_ERROR_PUSH(GUARDIAN_ERROR_STATE, "Failed to create monitor thread");
        goto cleanup;
    }

    /* Set thread priority for real-time monitoring */
    thread_lock(g_monitor_thread);
    sched_prio(g_monitor_thread, PRIO_MIN);
    thread_unlock(g_monitor_thread);

    g_monitor_running = true;
    return GUARDIAN_STATUS_SUCCESS;

cleanup:
    if (g_resource_stats) {
        guardian_secure_kfree(g_resource_stats, security_context);
    }
    if (g_game_stats) {
        guardian_secure_kfree(g_game_stats, security_context);
    }
    if (g_resource_monitor) {
        guardian_secure_kfree(g_resource_monitor, security_context);
    }
    return GUARDIAN_STATUS_ERROR;
}

/*
 * Cleanup resource monitoring subsystem
 */
__attribute__((cold))
__attribute__((visibility("hidden")))
void resource_monitor_cleanup(guardian_security_context_t* security_context) {
    /* Validate security context */
    GUARDIAN_VALIDATE_SECURITY_CONTEXT(security_context);

    /* Stop monitoring thread */
    if (g_monitor_running) {
        g_monitor_running = false;
        tsleep(&g_monitor_thread, PWAIT, "guardian_cleanup", hz);
    }

    /* Free allocated resources with security validation */
    if (g_resource_stats) {
        guardian_secure_kfree(g_resource_stats, security_context);
    }
    if (g_game_stats) {
        guardian_secure_kfree(g_game_stats, security_context);
    }
    if (g_resource_monitor) {
        guardian_secure_kfree(g_resource_monitor, security_context);
    }
}

/*
 * Update system resource statistics
 */
__attribute__((hot))
__attribute__((visibility("hidden")))
guardian_status_t update_resource_stats(
    guardian_resource_stats_t* stats,
    guardian_game_stats_t* game_stats,
    guardian_security_context_t* security_context
) {
    guardian_memory_stats_t memory_stats;
    guardian_status_t status;

    /* Validate parameters and security context */
    if (!stats || !game_stats) {
        GUARDIAN_ERROR_PUSH(GUARDIAN_ERROR_INVALID_PARAM, "Invalid statistics pointers");
        return GUARDIAN_STATUS_ERROR;
    }
    GUARDIAN_VALIDATE_SECURITY_CONTEXT(security_context);

    /* Update CPU usage with gaming process priority */
    stats->cpu_usage = cp_time_array[CP_USER] + cp_time_array[CP_NICE] +
                      cp_time_array[CP_SYS] + cp_time_array[CP_INTR];

    /* Get memory statistics with security validation */
    status = guardian_get_memory_stats(&memory_stats, security_context);
    if (status != GUARDIAN_STATUS_SUCCESS) {
        return status;
    }
    memcpy(&stats->memory_stats, &memory_stats, sizeof(guardian_memory_stats_t));

    /* Update hardware-specific metrics */
    stats->hardware_metrics.temperature = read_cpu_temp();
    stats->hardware_metrics.fan_speed = read_fan_speed();
    stats->hardware_metrics.gpu_usage = read_gpu_usage();
    stats->hardware_metrics.gpu_memory = read_gpu_memory();

    /* Update power management statistics */
    stats->power_stats.current_power_draw = read_power_draw();
    stats->power_stats.power_state = read_power_state();
    stats->power_stats.thermal_throttling = check_thermal_throttling();

    /* Update timestamp */
    getnanouptime(&stats->timestamp);

    return GUARDIAN_STATUS_SUCCESS;
}

/*
 * Monitor thread function
 */
__attribute__((noreturn))
__attribute__((visibility("hidden")))
static void* monitor_thread_func(void* arg) {
    guardian_status_t status;
    struct timespec sleep_time;

    /* Initialize sleep interval */
    sleep_time.tv_sec = 0;
    sleep_time.tv_nsec = GUARDIAN_RESOURCE_UPDATE_INTERVAL_MS * 1000000;

    while (g_monitor_running) {
        /* Update resource statistics with security context */
        status = update_resource_stats(
            g_resource_stats,
            g_game_stats,
            g_security_context
        );

        if (status != GUARDIAN_STATUS_SUCCESS) {
            GUARDIAN_ERROR_PUSH(GUARDIAN_ERROR_STATE, "Failed to update resource stats");
            /* Continue monitoring despite error */
        }

        /* Check resource thresholds */
        if (g_resource_stats->cpu_usage > GUARDIAN_CPU_THRESHOLD_PERCENT ||
            g_resource_stats->memory_stats.used > 
            (g_resource_stats->memory_stats.total * GUARDIAN_MEMORY_THRESHOLD_PERCENT / 100)) {
            /* Trigger alert with security context */
            guardian_trigger_resource_alert(g_resource_stats, g_security_context);
        }

        /* Sleep for update interval */
        tsleep(&g_monitor_thread, PWAIT, "guardian_monitor", 
               GUARDIAN_RESOURCE_UPDATE_INTERVAL_MS * hz / 1000);
    }

    kthread_exit();
}

/* Export required functions */
SYSINIT(guardian_resource_monitor_init, SI_SUB_DRIVERS, SI_ORDER_FIRST,
        resource_monitor_init, NULL);
SYSUNINIT(guardian_resource_monitor_cleanup, SI_SUB_DRIVERS, SI_ORDER_FIRST,
          resource_monitor_cleanup, NULL);