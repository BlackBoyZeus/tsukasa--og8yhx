/*
 * Guardian System - Process Control and Monitoring Interfaces
 * 
 * This header defines secure process management, resource control, and state monitoring
 * capabilities optimized for gaming console processes with enhanced security features
 * and performance monitoring.
 *
 * Version: 1.0.0
 * FreeBSD Version: 13.0
 */

#ifndef _GUARDIAN_PROCESS_CONTROL_H_
#define _GUARDIAN_PROCESS_CONTROL_H_

#include <sys/types.h>  /* FreeBSD 13.0 - System type definitions */
#include <sys/proc.h>   /* FreeBSD 13.0 - Process management interfaces */
#include <sys/sched.h>  /* FreeBSD 13.0 - Scheduler interfaces */

#include "guardian_types.h"     /* Core type definitions */
#include "guardian_errors.h"    /* Error handling */
#include "guardian_syscalls.h"  /* System call interfaces */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Process control configuration constants
 */
#define GUARDIAN_PROCESS_MAX_THREADS         64    /* Maximum threads per gaming process */
#define GUARDIAN_PROCESS_MAX_PRIORITY        255   /* Maximum process priority */
#define GUARDIAN_PROCESS_DEFAULT_PRIORITY    128   /* Default process priority */
#define GUARDIAN_PROCESS_GAMING_CPU_MASK     0xF0  /* Gaming process CPU affinity mask */
#define GUARDIAN_PROCESS_MAX_MEMORY_GAMING   8589934592ULL  /* 8GB max for gaming processes */

/*
 * Gaming-specific process configuration
 */
typedef struct guardian_gaming_config {
    uint32_t priority_boost;           /* Real-time priority boost for gaming */
    uint64_t gpu_memory_reservation;   /* Reserved GPU memory in bytes */
    uint32_t frame_rate_target;        /* Target frame rate for scheduling */
    uint64_t audio_buffer_size;        /* Audio processing buffer size */
    uint32_t input_latency_us;         /* Input processing latency in microseconds */
} guardian_gaming_config_t;

/*
 * Process state enumeration with gaming-specific states
 */
typedef enum guardian_process_state {
    GUARDIAN_PROCESS_RUNNING = 0,      /* Process is running normally */
    GUARDIAN_PROCESS_SUSPENDED = 1,     /* Process is suspended */
    GUARDIAN_PROCESS_TERMINATED = 2,    /* Process has terminated */
    GUARDIAN_PROCESS_GAMING_ACTIVE = 3  /* Process is in active gaming state */
} guardian_process_state_t;

/*
 * Process resource limits structure with gaming optimizations
 */
typedef struct guardian_process_limits {
    size_t max_memory;          /* Maximum memory allocation */
    uint32_t max_threads;       /* Maximum thread count */
    uint8_t priority;           /* Base process priority */
    uint64_t cpu_affinity;      /* CPU affinity mask */
    uint8_t gaming_priority;    /* Gaming-specific priority */
    uint32_t real_time_quota;   /* Real-time CPU quota percentage */
} guardian_process_limits_t;

/*
 * Process monitoring statistics
 */
typedef struct guardian_process_stats {
    uint64_t cpu_time_ns;       /* CPU time in nanoseconds */
    uint64_t memory_resident;   /* Resident memory size */
    uint64_t memory_virtual;    /* Virtual memory size */
    uint32_t thread_count;      /* Current thread count */
    uint64_t io_read_bytes;     /* I/O bytes read */
    uint64_t io_write_bytes;    /* I/O bytes written */
    uint64_t frame_time_us;     /* Frame processing time in microseconds */
    uint32_t frame_rate;        /* Current frame rate */
} guardian_process_stats_t;

/*
 * Process creation with security context and gaming optimizations
 */
__attribute__((warn_unused_result))
guardian_status_t guardian_process_create(
    guardian_process_info_t* process_info,
    guardian_security_context_t* security_context,
    guardian_gaming_config_t* gaming_config
);

/*
 * Process termination with audit logging
 */
__attribute__((warn_unused_result))
guardian_status_t guardian_process_terminate(
    pid_t pid,
    guardian_error_info_t* error_info,
    guardian_audit_context_t* audit_context
);

/*
 * Process suspension with gaming state preservation
 */
__attribute__((warn_unused_result))
guardian_status_t guardian_process_suspend(
    pid_t pid,
    guardian_gaming_config_t* gaming_state,
    guardian_audit_context_t* audit_context
);

/*
 * Process resume with gaming state restoration
 */
__attribute__((warn_unused_result))
guardian_status_t guardian_process_resume(
    pid_t pid,
    guardian_gaming_config_t* gaming_state,
    guardian_audit_context_t* audit_context
);

/*
 * Process resource limits configuration
 */
__attribute__((warn_unused_result))
guardian_status_t guardian_process_set_limits(
    pid_t pid,
    guardian_process_limits_t* limits,
    guardian_audit_context_t* audit_context
);

/*
 * Process statistics retrieval
 */
__attribute__((warn_unused_result))
guardian_status_t guardian_process_get_stats(
    pid_t pid,
    guardian_process_stats_t* stats,
    guardian_audit_context_t* audit_context
);

/*
 * Process gaming configuration update
 */
__attribute__((warn_unused_result))
guardian_status_t guardian_process_update_gaming_config(
    pid_t pid,
    guardian_gaming_config_t* gaming_config,
    guardian_audit_context_t* audit_context
);

/*
 * Process security context validation
 */
__attribute__((warn_unused_result))
guardian_status_t guardian_process_validate_security(
    pid_t pid,
    guardian_security_context_t* security_context,
    guardian_audit_context_t* audit_context
);

#ifdef __cplusplus
}
#endif

#endif /* _GUARDIAN_PROCESS_CONTROL_H_ */