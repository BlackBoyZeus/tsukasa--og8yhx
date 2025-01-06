/*
 * Guardian System - GPU Access Management
 * 
 * This header defines the secure GPU access interface for the Guardian system's
 * FreeBSD kernel module, providing controlled access to GPU resources with
 * enhanced security features and performance optimization.
 *
 * Version: 1.0.0
 * FreeBSD Version: 13.0
 */

#ifndef _GUARDIAN_GPU_ACCESS_H_
#define _GUARDIAN_GPU_ACCESS_H_

#include <sys/types.h>      /* FreeBSD 13.0 - System type definitions */
#include <sys/param.h>      /* FreeBSD 13.0 - System parameters */
#include <machine/gpu.h>    /* FreeBSD 13.0 - Machine-specific GPU definitions */

#include "guardian_types.h"
#include "guardian_errors.h"
#include "guardian_ioctl.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * GPU subsystem configuration constants
 */
#define GUARDIAN_GPU_MAX_CONTEXTS      64     /* Maximum concurrent GPU contexts */
#define GUARDIAN_GPU_MAX_BUFFERS       1024   /* Maximum GPU memory buffers */
#define GUARDIAN_GPU_MAX_COMMANDS      4096   /* Maximum queued GPU commands */
#define GUARDIAN_GPU_SECURITY_LEVELS   4      /* Number of security levels */
#define GUARDIAN_GPU_MAX_BATCH_SIZE    256    /* Maximum command batch size */
#define GUARDIAN_GPU_MEMORY_ALIGNMENT  4096   /* Memory alignment requirement */

/*
 * GPU context security states
 */
#define GUARDIAN_GPU_STATE_INACTIVE    0x00
#define GUARDIAN_GPU_STATE_ACTIVE      0x01
#define GUARDIAN_GPU_STATE_SUSPENDED   0x02
#define GUARDIAN_GPU_STATE_ERROR       0x03

/*
 * GPU buffer access flags
 */
#define GUARDIAN_GPU_BUFFER_READ       0x01
#define GUARDIAN_GPU_BUFFER_WRITE      0x02
#define GUARDIAN_GPU_BUFFER_EXECUTE    0x04
#define GUARDIAN_GPU_BUFFER_DMA        0x08
#define GUARDIAN_GPU_BUFFER_SECURE     0x10

/*
 * Enhanced GPU context structure with security features
 */
typedef struct guardian_gpu_context {
    uint32_t id;                           /* Unique context identifier */
    pid_t process_id;                      /* Owner process ID */
    uint32_t state;                        /* Context state */
    uint32_t security_level;               /* Security classification */
    size_t memory_quota;                   /* Memory allocation quota */
    uint32_t command_quota;                /* Command queue quota */
    guardian_perf_counters_t performance_counters;  /* Performance metrics */
    void* _internal;                       /* Internal context data */
} guardian_gpu_context_t;

/*
 * Secure GPU memory buffer structure
 */
typedef struct guardian_gpu_buffer {
    uint32_t id;                           /* Buffer identifier */
    size_t size;                           /* Buffer size */
    uint32_t flags;                        /* Access flags */
    guardian_security_attrs_t security_attributes;  /* Security attributes */
    guardian_dma_protection_t dma_protection;      /* DMA protection */
    void* _internal;                       /* Internal buffer data */
} guardian_gpu_buffer_t;

/*
 * GPU command structure with validation
 */
typedef struct guardian_gpu_command {
    uint32_t type;                         /* Command type */
    uint32_t flags;                        /* Command flags */
    void* data;                            /* Command data */
    guardian_validation_token_t validation_token;  /* Security token */
    uint32_t batch_id;                     /* Batch identifier */
    void* _internal;                       /* Internal command data */
} guardian_gpu_command_t;

/*
 * Function declarations
 */

/*
 * Initialize the GPU access subsystem
 * Returns: Status code indicating success or failure
 */
__must_check
guardian_status_t guardian_gpu_init(
    guardian_gpu_config_t* config
);

/*
 * Allocate a new GPU context with security controls
 * Returns: Status code with context allocation result
 */
__must_check
__locked_after_allocation
guardian_status_t guardian_gpu_allocate_context(
    guardian_process_info_t* process_info,
    guardian_security_policy_t* security_policy,
    guardian_performance_params_t* perf_params
);

/*
 * Deallocate a GPU context
 */
void guardian_gpu_free_context(
    guardian_gpu_context_t* context
);

/*
 * Allocate secure GPU memory buffer
 */
__must_check
guardian_status_t guardian_gpu_allocate_buffer(
    guardian_gpu_context_t* context,
    size_t size,
    uint32_t flags,
    guardian_gpu_buffer_t** buffer
);

/*
 * Submit GPU commands with security validation
 */
__must_check
guardian_status_t guardian_gpu_submit_commands(
    guardian_gpu_context_t* context,
    guardian_gpu_command_t* commands,
    uint32_t count,
    guardian_validation_token_t* token
);

/*
 * Configure GPU security policy
 */
guardian_status_t guardian_gpu_set_security_policy(
    guardian_gpu_context_t* context,
    guardian_security_policy_t* policy
);

/*
 * Query GPU performance metrics
 */
guardian_status_t guardian_gpu_get_performance_stats(
    guardian_gpu_context_t* context,
    guardian_perf_counters_t* stats
);

#ifdef __cplusplus
}
#endif

#endif /* _GUARDIAN_GPU_ACCESS_H_ */