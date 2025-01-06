/*
 * Guardian System - System Monitoring Interface
 * 
 * Header file defining the system monitoring interface for the Guardian kernel module.
 * Provides structures and functions for real-time monitoring of system resources,
 * process states, and hardware metrics with enhanced CPU affinity tracking.
 *
 * Version: 1.0.0
 * FreeBSD Version: 13.0
 */

#ifndef _GUARDIAN_SYSTEM_MONITOR_H_
#define _GUARDIAN_SYSTEM_MONITOR_H_

#include <sys/sysctl.h>        /* FreeBSD 13.0 - System control and statistics */
#include <sys/proc.h>          /* FreeBSD 13.0 - Process management and CPU affinity */
#include <sys/resourcevar.h>   /* FreeBSD 13.0 - Resource usage statistics */
#include "guardian_types.h"     /* Common type definitions */
#include "guardian_errors.h"    /* Error handling framework */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * System monitoring constants
 */
#define GUARDIAN_MONITOR_INTERVAL_MS    1000    /* Default monitoring interval */
#define GUARDIAN_MAX_METRICS            128     /* Maximum number of tracked metrics */
#define GUARDIAN_MAX_SAMPLES            4096    /* Maximum samples in history */
#define GUARDIAN_METRIC_BUFFER_SIZE     16384   /* Metric buffer size in bytes */
#define GUARDIAN_MAX_CALLBACKS          32      /* Maximum monitoring callbacks */

/*
 * Monitoring metric types
 */
typedef enum guardian_metric_type {
    GUARDIAN_METRIC_CPU = 0,           /* CPU usage metrics */
    GUARDIAN_METRIC_MEMORY,            /* Memory usage metrics */
    GUARDIAN_METRIC_PROCESS,           /* Process metrics */
    GUARDIAN_METRIC_IO,                /* I/O metrics */
    GUARDIAN_METRIC_NETWORK,           /* Network metrics */
    GUARDIAN_METRIC_SECURITY,          /* Security metrics */
    GUARDIAN_METRIC_PRESSURE           /* System pressure metrics */
} guardian_metric_type_t;

/*
 * System pressure statistics
 */
typedef struct guardian_pressure_stats {
    uint32_t cpu_pressure;             /* CPU pressure metric */
    uint32_t memory_pressure;          /* Memory pressure metric */
    uint32_t io_pressure;             /* I/O pressure metric */
    uint64_t last_update;             /* Last update timestamp */
} guardian_pressure_stats_t;

/*
 * Monitoring callback function type
 */
typedef void (*guardian_monitor_callback_t)(
    const guardian_system_metrics_t* metrics,
    void* user_data
);

/*
 * Monitor configuration structure
 */
typedef struct guardian_monitor_config {
    uint32_t interval_ms;              /* Monitoring interval in milliseconds */
    uint32_t max_samples;              /* Maximum samples to retain */
    uint64_t metrics_mask;             /* Enabled metrics bitmap */
    uint64_t cpu_affinity_mask;        /* CPU affinity for monitoring threads */
    uint32_t callback_count;           /* Number of registered callbacks */
    guardian_monitor_callback_t callbacks[GUARDIAN_MAX_CALLBACKS];  /* Callback array */
    void* callback_data[GUARDIAN_MAX_CALLBACKS];                   /* Callback user data */
} guardian_monitor_config_t;

/*
 * System-wide metrics structure
 */
typedef struct guardian_system_metrics {
    uint32_t cpu_usage;                /* Overall CPU usage percentage */
    uint64_t cpu_affinity;             /* Current CPU affinity mask */
    guardian_memory_stats_t memory_stats;  /* Memory usage statistics */
    uint32_t process_count;            /* Number of active processes */
    uint64_t timestamp;                /* Metrics timestamp */
    guardian_pressure_stats_t pressure_metrics;  /* System pressure metrics */
} guardian_system_metrics_t;

/*
 * Function declarations
 */

/*
 * Initialize the system monitoring subsystem
 * @param config Pointer to monitor configuration structure
 * @return Status of initialization
 */
GUARDIAN_EXPORT guardian_status_t guardian_monitor_init(
    const guardian_monitor_config_t* config
);

/*
 * Retrieve current memory statistics
 * @param stats Pointer to memory statistics structure
 * @return Status of operation
 */
GUARDIAN_EXPORT guardian_status_t guardian_monitor_get_memory_stats(
    guardian_memory_stats_t* stats
);

/*
 * Register a monitoring callback
 * @param callback Callback function pointer
 * @param user_data User data passed to callback
 * @return Status of registration
 */
GUARDIAN_EXPORT guardian_status_t guardian_monitor_register_callback(
    guardian_monitor_callback_t callback,
    void* user_data
);

/*
 * Get current system metrics
 * @param metrics Pointer to metrics structure
 * @return Status of operation
 */
GUARDIAN_EXPORT guardian_status_t guardian_monitor_get_metrics(
    guardian_system_metrics_t* metrics
);

/*
 * Get CPU affinity information for a process
 * @param pid Process ID
 * @param affinity_mask Pointer to store affinity mask
 * @return Status of operation
 */
GUARDIAN_EXPORT guardian_status_t guardian_monitor_get_cpu_affinity(
    pid_t pid,
    uint64_t* affinity_mask
);

/*
 * Get system pressure metrics
 * @param pressure Pointer to pressure statistics structure
 * @return Status of operation
 */
GUARDIAN_EXPORT guardian_status_t guardian_monitor_get_pressure_stats(
    guardian_pressure_stats_t* pressure
);

/*
 * Cleanup and shutdown monitoring subsystem
 * @return Status of cleanup operation
 */
GUARDIAN_EXPORT guardian_status_t guardian_monitor_cleanup(void);

#ifdef __cplusplus
}
#endif

#endif /* _GUARDIAN_SYSTEM_MONITOR_H_ */