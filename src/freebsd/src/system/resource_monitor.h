/*
 * Guardian System - Resource Monitor Interface
 * 
 * This header defines interfaces and structures for monitoring system resources
 * in the Guardian system's FreeBSD kernel module with enhanced security features,
 * performance tracking, and hardware-specific optimizations.
 *
 * Version: 1.0.0
 * FreeBSD Version: 13.0
 */

#ifndef _GUARDIAN_RESOURCE_MONITOR_H_
#define _GUARDIAN_RESOURCE_MONITOR_H_

#include <sys/types.h>      /* FreeBSD 13.0 - System type definitions */
#include <sys/resource.h>   /* FreeBSD 13.0 - Enhanced resource limit definitions */
#include <sys/sysctl.h>     /* FreeBSD 13.0 - System control interface */
#include <sys/lock.h>       /* FreeBSD 13.0 - Kernel locking primitives */

#include "guardian_types.h"
#include "guardian_errors.h"
#include "sysctl_handlers.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * System-wide constants for resource monitoring
 */
#define GUARDIAN_RESOURCE_UPDATE_INTERVAL_MS    1000    /* Resource update interval */
#define GUARDIAN_MAX_RESOURCE_SAMPLES           60      /* Maximum resource samples retained */
#define GUARDIAN_CPU_THRESHOLD_PERCENT          90      /* CPU usage threshold */
#define GUARDIAN_MEMORY_THRESHOLD_PERCENT       85      /* Memory usage threshold */
#define GUARDIAN_RESOURCE_LOCK_TIMEOUT_MS       100     /* Resource lock timeout */
#define GUARDIAN_MAX_CONCURRENT_MONITORS        4       /* Maximum concurrent monitors */
#define GUARDIAN_MEMORY_PROTECTION_ENABLED      1       /* Memory protection flag */
#define GUARDIAN_POWER_MANAGEMENT_ENABLED       1       /* Power management flag */

/*
 * Hardware-specific resource metrics
 */
typedef struct guardian_hardware_stats {
    uint32_t temperature;           /* Hardware temperature in celsius */
    uint32_t fan_speed;            /* Fan speed in RPM */
    uint64_t gpu_usage;            /* GPU usage percentage */
    uint64_t gpu_memory;           /* GPU memory usage in bytes */
    uint32_t power_state;          /* Current power state */
    uint64_t performance_counters[8]; /* Hardware performance counters */
} guardian_hardware_stats_t;

/*
 * Power management statistics
 */
typedef struct guardian_power_stats {
    uint32_t current_power_draw;    /* Current power consumption in mW */
    uint32_t average_power_draw;    /* Average power consumption in mW */
    uint32_t power_state;           /* Current power state */
    uint32_t thermal_throttling;    /* Thermal throttling status */
    uint64_t energy_consumed;       /* Total energy consumed in mWh */
} guardian_power_stats_t;

/*
 * Resource monitoring configuration
 */
typedef struct guardian_resource_config {
    uint32_t update_interval;       /* Update interval in milliseconds */
    uint32_t sample_count;          /* Number of samples to retain */
    uint32_t cpu_threshold;         /* CPU usage threshold percentage */
    uint32_t memory_threshold;      /* Memory usage threshold percentage */
    uint32_t security_level;        /* Security level for monitoring */
    uint32_t flags;                 /* Configuration flags */
} guardian_resource_config_t;

/*
 * Resource statistics structure with atomic counters
 */
typedef struct guardian_resource_stats {
    _Atomic uint32_t cpu_usage;     /* CPU usage percentage */
    guardian_memory_stats_t memory_stats;  /* Memory statistics */
    _Atomic uint32_t process_count; /* Active process count */
    struct timespec timestamp;      /* Timestamp of last update */
    guardian_security_context_t security_context;  /* Security context */
    guardian_hardware_stats_t hardware_metrics;    /* Hardware-specific metrics */
    guardian_power_stats_t power_stats;           /* Power management stats */
} guardian_resource_stats_t;

/*
 * Resource monitor initialization
 * Thread-safe and security-context aware initialization
 */
__attribute__((warn_unused_result))
guardian_status_t guardian_resource_monitor_init(
    guardian_security_context_t *security_ctx,
    guardian_resource_config_t *config
);

/*
 * Resource monitoring functions
 */
guardian_status_t guardian_resource_monitor_start(void);
guardian_status_t guardian_resource_monitor_stop(void);
guardian_status_t guardian_resource_monitor_pause(void);
guardian_status_t guardian_resource_monitor_resume(void);

/*
 * Resource statistics retrieval
 * Thread-safe access to resource statistics
 */
guardian_status_t guardian_resource_get_stats(
    guardian_resource_stats_t *stats,
    guardian_security_context_t *security_ctx
);

/*
 * Threshold management
 */
guardian_status_t guardian_resource_set_thresholds(
    uint32_t cpu_threshold,
    uint32_t memory_threshold,
    guardian_security_context_t *security_ctx
);

/*
 * Hardware-specific monitoring
 */
guardian_status_t guardian_resource_get_hardware_stats(
    guardian_hardware_stats_t *stats,
    guardian_security_context_t *security_ctx
);

/*
 * Power management interface
 */
guardian_status_t guardian_resource_get_power_stats(
    guardian_power_stats_t *stats,
    guardian_security_context_t *security_ctx
);

/*
 * Resource monitoring cleanup
 */
void guardian_resource_monitor_cleanup(void);

/*
 * Resource monitoring event handlers
 */
typedef void (*guardian_resource_event_handler_t)(
    const guardian_resource_stats_t *stats,
    guardian_security_context_t *security_ctx
);

guardian_status_t guardian_resource_register_event_handler(
    guardian_resource_event_handler_t handler,
    guardian_security_context_t *security_ctx
);

#ifdef __cplusplus
}
#endif

#endif /* _GUARDIAN_RESOURCE_MONITOR_H_ */