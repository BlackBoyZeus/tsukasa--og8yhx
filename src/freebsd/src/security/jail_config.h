/*
 * Guardian System - FreeBSD Jail Configuration
 * 
 * This header defines configuration structures and functions for FreeBSD jail-based
 * isolation in the Guardian system, providing secure container environments for
 * component isolation with enhanced security features.
 *
 * Version: 1.0.0
 * FreeBSD Version: 13.0
 */

#ifndef _GUARDIAN_JAIL_CONFIG_H_
#define _GUARDIAN_JAIL_CONFIG_H_

#include <sys/jail.h>    /* FreeBSD 13.0 - Jail management interfaces */
#include <sys/param.h>   /* FreeBSD 13.0 - System parameters and limits */
#include "guardian_types.h"
#include "guardian_errors.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * System-wide jail configuration constants
 */
#define GUARDIAN_JAIL_MAX_NAME_LEN      256
#define GUARDIAN_JAIL_MAX_PATH_LEN      1024
#define GUARDIAN_JAIL_MAX_MOUNTS        32
#define GUARDIAN_JAIL_MAX_IPS           8
#define GUARDIAN_JAIL_MAX_MAC_LEN       128
#define GUARDIAN_JAIL_MAX_AUDIT_EVENTS  64
#define GUARDIAN_JAIL_RESOURCE_LIMIT_COUNT 16

/*
 * Resource limits configuration structure
 */
typedef struct guardian_resource_limits {
    uint64_t max_memory;          /* Maximum memory in bytes */
    uint64_t max_cpu_time;        /* Maximum CPU time in microseconds */
    uint32_t max_processes;       /* Maximum number of processes */
    uint32_t max_files;          /* Maximum number of open files */
    uint32_t max_threads;        /* Maximum number of threads */
    uint64_t max_disk_space;     /* Maximum disk space in bytes */
    uint32_t max_sockets;        /* Maximum number of sockets */
    uint32_t max_mqueues;        /* Maximum number of message queues */
} guardian_resource_limits_t;

/*
 * Audit configuration structure
 */
typedef struct guardian_audit_config {
    uint32_t audit_flags;        /* Audit event flags */
    char audit_path[GUARDIAN_JAIL_MAX_PATH_LEN];  /* Audit log path */
    uint32_t audit_events[GUARDIAN_JAIL_MAX_AUDIT_EVENTS]; /* Tracked events */
    uint32_t audit_buffer_size;  /* Audit buffer size */
    uint32_t audit_retention;    /* Log retention period in days */
} guardian_audit_config_t;

/*
 * Network configuration structure
 */
typedef struct guardian_network_config {
    char ip_addresses[GUARDIAN_JAIL_MAX_IPS][INET6_ADDRSTRLEN];
    uint32_t ip_count;
    uint32_t vnet_flags;
    uint32_t firewall_rules;
    uint32_t bandwidth_limit;    /* In Kbps */
} guardian_network_config_t;

/*
 * Comprehensive jail configuration structure
 */
typedef struct guardian_jail_config {
    char name[GUARDIAN_JAIL_MAX_NAME_LEN];
    char path[GUARDIAN_JAIL_MAX_PATH_LEN];
    guardian_security_context_t security_context;
    char mac_label[GUARDIAN_JAIL_MAX_MAC_LEN];
    guardian_resource_limits_t resource_limits;
    guardian_audit_config_t audit_config;
    guardian_network_config_t network_config;
    uint32_t flags;
} guardian_jail_config_t;

/*
 * Jail configuration flags
 */
typedef enum guardian_jail_flags {
    GUARDIAN_JAIL_PERSIST             = (1 << 0),  /* Persist across reboots */
    GUARDIAN_JAIL_VNET               = (1 << 1),  /* Virtual network stack */
    GUARDIAN_JAIL_SECURE_EXEC        = (1 << 2),  /* Secure execution mode */
    GUARDIAN_JAIL_AUDIT              = (1 << 3),  /* Enable audit logging */
    GUARDIAN_JAIL_MAC                = (1 << 4),  /* Enable MAC framework */
    GUARDIAN_JAIL_PERFORMANCE_MONITOR = (1 << 5)   /* Enable performance monitoring */
} guardian_jail_flags_t;

/*
 * Cleanup flags for jail destruction
 */
typedef enum guardian_cleanup_flags {
    GUARDIAN_CLEANUP_FORCE           = (1 << 0),  /* Force cleanup */
    GUARDIAN_CLEANUP_PRESERVE_LOGS   = (1 << 1),  /* Preserve audit logs */
    GUARDIAN_CLEANUP_SECURE_WIPE     = (1 << 2)   /* Secure data wiping */
} guardian_cleanup_flags_t;

/*
 * Function declarations
 */

/*
 * Creates a new jail environment with enhanced security configuration
 */
__attribute__((warn_unused_result))
guardian_status_t guardian_jail_create(
    guardian_jail_config_t* config,
    guardian_resource_limits_t* limits,
    guardian_audit_config_t* audit_cfg
);

/*
 * Securely destroys an existing jail environment
 */
__attribute__((warn_unused_result))
guardian_status_t guardian_jail_destroy(
    int jail_id,
    guardian_cleanup_flags_t flags
);

/*
 * Updates jail configuration parameters
 */
__attribute__((warn_unused_result))
guardian_status_t guardian_jail_update_config(
    int jail_id,
    guardian_jail_config_t* new_config
);

/*
 * Retrieves current jail status and statistics
 */
guardian_status_t guardian_jail_get_status(
    int jail_id,
    guardian_jail_config_t* config,
    guardian_error_info_t* error_info
);

/*
 * Sets resource limits for an existing jail
 */
guardian_status_t guardian_jail_set_limits(
    int jail_id,
    guardian_resource_limits_t* limits
);

/*
 * Updates audit configuration for an existing jail
 */
guardian_status_t guardian_jail_update_audit(
    int jail_id,
    guardian_audit_config_t* audit_cfg
);

/*
 * Validates jail configuration parameters
 */
guardian_status_t guardian_jail_validate_config(
    guardian_jail_config_t* config,
    guardian_error_info_t* error_info
);

#ifdef __cplusplus
}
#endif

#endif /* _GUARDIAN_JAIL_CONFIG_H_ */