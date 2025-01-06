/*
 * Guardian System - Process Control Implementation
 * 
 * FreeBSD kernel module implementation for secure process management and monitoring
 * with gaming-specific optimizations and enhanced security features.
 *
 * Version: 1.0.0
 * FreeBSD Version: 13.0
 */

#include <sys/types.h>
#include <sys/proc.h>
#include <sys/sched.h>
#include <sys/jail.h>
#include "process_control.h"
#include "jail_config.h"
#include "kernel_utils.h"

/* Global mutex for process control operations */
static struct mtx process_control_lock;
MTX_SYSINIT(process_control, &process_control_lock, "Guardian Process Control Lock", MTX_DEF);

/* Process tracking list head */
static LIST_HEAD(proclist, guardian_process) process_list = LIST_HEAD_INITIALIZER(process_list);

/* Game metrics cache */
static struct guardian_game_metrics_cache {
    uint64_t last_update;
    guardian_game_metrics_t metrics[GUARDIAN_PROCESS_MAX_PROCESSES];
    struct mtx lock;
} game_metrics_cache;

/* Initialize game metrics cache */
static void game_metrics_cache_init(void) {
    mtx_init(&game_metrics_cache.lock, "Game Metrics Cache Lock", NULL, MTX_DEF);
    game_metrics_cache.last_update = 0;
    memset(game_metrics_cache.metrics, 0, sizeof(game_metrics_cache.metrics));
}

/* Internal process tracking structure */
struct guardian_process {
    pid_t pid;
    guardian_process_state_t state;
    guardian_process_limits_t limits;
    guardian_game_metrics_t game_metrics;
    guardian_security_context_t security_context;
    LIST_ENTRY(guardian_process) entries;
};

/*
 * Internal implementation of process creation with gaming optimizations
 */
static guardian_status_t guardian_process_create_impl(
    guardian_process_info_t* process_info,
    guardian_security_context_t* security_context,
    guardian_game_config_t* game_config
) {
    struct guardian_process* proc;
    guardian_jail_config_t jail_config;
    guardian_status_t status;

    /* Validate input parameters */
    if (!process_info || !security_context || !game_config) {
        GUARDIAN_ERROR_PUSH(GUARDIAN_ERROR_INVALID_PARAM, "Invalid process creation parameters");
        return GUARDIAN_STATUS_ERROR;
    }

    /* Allocate process tracking structure */
    proc = guardian_kmalloc(sizeof(struct guardian_process), GUARDIAN_KMALLOC_WAIT, security_context);
    if (!proc) {
        return GUARDIAN_STATUS_ERROR;
    }

    /* Initialize process structure */
    proc->pid = process_info->pid;
    proc->state = GUARDIAN_PROCESS_GAMING_ACTIVE;
    memcpy(&proc->security_context, security_context, sizeof(guardian_security_context_t));

    /* Configure gaming-optimized resource limits */
    proc->limits.max_memory = GUARDIAN_PROCESS_MAX_MEMORY_GAMING;
    proc->limits.max_threads = GUARDIAN_PROCESS_MAX_THREADS;
    proc->limits.priority = game_config->priority_boost;
    proc->limits.cpu_affinity = GUARDIAN_PROCESS_GAMING_CPU_MASK;
    proc->limits.gaming_priority = GUARDIAN_PROCESS_DEFAULT_PRIORITY;
    proc->limits.real_time_quota = 75; /* 75% RT quota for gaming processes */

    /* Set up gaming-optimized jail environment */
    memset(&jail_config, 0, sizeof(jail_config));
    snprintf(jail_config.name, GUARDIAN_JAIL_MAX_NAME_LEN, "game_proc_%d", proc->pid);
    jail_config.resource_limits = proc->limits;
    jail_config.flags = GUARDIAN_JAIL_SECURE_EXEC | GUARDIAN_JAIL_PERFORMANCE_MONITOR;

    /* Create process jail */
    status = guardian_jail_create(&jail_config, &proc->limits, NULL);
    if (status != GUARDIAN_STATUS_SUCCESS) {
        guardian_kfree(proc, security_context);
        return status;
    }

    /* Initialize game metrics */
    memset(&proc->game_metrics, 0, sizeof(guardian_game_metrics_t));
    proc->game_metrics.frame_rate_target = game_config->frame_rate_target;
    proc->game_metrics.gpu_memory_reserved = game_config->gpu_memory_reservation;

    /* Add to process tracking list */
    mtx_lock(&process_control_lock);
    LIST_INSERT_HEAD(&process_list, proc, entries);
    mtx_unlock(&process_control_lock);

    return GUARDIAN_STATUS_SUCCESS;
}

/*
 * Internal implementation of process monitoring with gaming metrics
 */
static guardian_status_t guardian_process_monitor_impl(
    pid_t pid,
    guardian_process_stats_t* stats,
    guardian_game_metrics_t* game_metrics
) {
    struct guardian_process* proc;
    guardian_status_t status = GUARDIAN_STATUS_ERROR;

    /* Validate input parameters */
    if (!stats || !game_metrics) {
        GUARDIAN_ERROR_PUSH(GUARDIAN_ERROR_INVALID_PARAM, "Invalid monitoring parameters");
        return GUARDIAN_STATUS_ERROR;
    }

    /* Find process in tracking list */
    mtx_lock(&process_control_lock);
    LIST_FOREACH(proc, &process_list, entries) {
        if (proc->pid == pid) {
            /* Collect standard process metrics */
            stats->cpu_time_ns = proc_getcputime(pid);
            stats->memory_resident = proc_getresidentsize(pid);
            stats->memory_virtual = proc_getvirtualsize(pid);
            stats->thread_count = proc_getthreadcount(pid);
            stats->io_read_bytes = proc_getiostat(pid, PROC_IO_READ);
            stats->io_write_bytes = proc_getiostat(pid, PROC_IO_WRITE);

            /* Collect gaming-specific metrics */
            stats->frame_time_us = proc->game_metrics.frame_time_us;
            stats->frame_rate = proc->game_metrics.frame_rate;

            /* Update game metrics */
            memcpy(game_metrics, &proc->game_metrics, sizeof(guardian_game_metrics_t));

            /* Update metrics cache */
            mtx_lock(&game_metrics_cache.lock);
            memcpy(&game_metrics_cache.metrics[pid % GUARDIAN_PROCESS_MAX_PROCESSES],
                   game_metrics, sizeof(guardian_game_metrics_t));
            game_metrics_cache.last_update = time_uptime;
            mtx_unlock(&game_metrics_cache.lock);

            status = GUARDIAN_STATUS_SUCCESS;
            break;
        }
    }
    mtx_unlock(&process_control_lock);

    return status;
}

/*
 * Public interface for process creation
 */
guardian_status_t guardian_process_create(
    guardian_process_info_t* process_info,
    guardian_security_context_t* security_context,
    guardian_game_config_t* game_config
) {
    return guardian_process_create_impl(process_info, security_context, game_config);
}

/*
 * Public interface for process monitoring
 */
guardian_status_t guardian_process_monitor(
    pid_t pid,
    guardian_process_stats_t* stats,
    guardian_game_metrics_t* game_metrics
) {
    return guardian_process_monitor_impl(pid, stats, game_metrics);
}

/* Module initialization */
static int process_control_init(void) {
    game_metrics_cache_init();
    return 0;
}

/* Module cleanup */
static void process_control_cleanup(void) {
    struct guardian_process *proc, *tmp;

    mtx_lock(&process_control_lock);
    LIST_FOREACH_SAFE(proc, &process_list, entries, tmp) {
        LIST_REMOVE(proc, entries);
        guardian_kfree(proc, &proc->security_context);
    }
    mtx_unlock(&process_control_lock);

    mtx_destroy(&game_metrics_cache.lock);
    mtx_destroy(&process_control_lock);
}

SYSINIT(process_control, SI_SUB_DRIVERS, SI_ORDER_MIDDLE, process_control_init, NULL);
SYSUNINIT(process_control, SI_SUB_DRIVERS, SI_ORDER_MIDDLE, process_control_cleanup, NULL);