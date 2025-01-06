/*
 * guardian_types.h - Core type definitions for the Guardian security system
 *
 * Copyright (c) 2024. All rights reserved.
 * 
 * This header defines fundamental types and structures for the Guardian
 * FreeBSD kernel module, providing type-safe interfaces for system state,
 * memory management, security policies, and hardware interactions.
 */

#ifndef _GUARDIAN_TYPES_H_
#define _GUARDIAN_TYPES_H_

#include <sys/types.h>      /* FreeBSD 13.0 - Basic system types */
#include <sys/param.h>      /* FreeBSD 13.0 - System parameters */
#include <machine/types.h>  /* FreeBSD 13.0 - Machine-specific types */

/*
 * System-wide constants
 */
#define GUARDIAN_MAX_NAME_LENGTH     64
#define GUARDIAN_MAX_PATH_LENGTH     256
#define GUARDIAN_MAX_REGIONS         1024
#define GUARDIAN_MAX_POLICIES        128
#define GUARDIAN_INVALID_HANDLE      ((guardian_handle_t)0)

/*
 * Type-safe opaque handle for Guardian system resources
 */
typedef uint64_t guardian_handle_t;

/*
 * Memory protection and region flags
 */
#define GUARDIAN_MEM_READ           0x00000001
#define GUARDIAN_MEM_WRITE          0x00000002
#define GUARDIAN_MEM_EXECUTE        0x00000004
#define GUARDIAN_MEM_SECURE         0x00000008
#define GUARDIAN_MEM_LOCKED         0x00000010
#define GUARDIAN_MEM_ZERO_ON_FREE   0x00000020

/*
 * Security policy flags
 */
#define GUARDIAN_POLICY_ENABLED     0x00000001
#define GUARDIAN_POLICY_ENFORCING   0x00000002
#define GUARDIAN_POLICY_AUDITING    0x00000004
#define GUARDIAN_POLICY_CRITICAL    0x00000008

/*
 * System state structure providing comprehensive system information
 */
typedef struct guardian_system_state {
    uint32_t status;         /* Current system status flags */
    uint64_t uptime;         /* System uptime in milliseconds */
    uint64_t memory_usage;   /* Current memory usage in bytes */
    uint32_t active_policies;/* Number of active security policies */
} guardian_system_state_t;

/*
 * Memory-safe region descriptor with explicit protection flags
 */
typedef struct guardian_memory_region {
    void     *base_address;  /* Base address of memory region */
    size_t    size;         /* Size of region in bytes */
    uint32_t  flags;        /* Region flags */
    uint32_t  protection;   /* Memory protection flags */
} guardian_memory_region_t;

/*
 * Security policy descriptor for system protection rules
 */
typedef struct guardian_security_policy {
    uint32_t id;            /* Unique policy identifier */
    char     name[GUARDIAN_MAX_NAME_LENGTH]; /* Policy name */
    uint32_t flags;         /* Policy flags */
    uint32_t priority;      /* Policy priority level */
} guardian_security_policy_t;

/*
 * Hardware capabilities and information descriptor
 */
typedef struct guardian_hardware_info {
    uint32_t device_id;     /* Unique device identifier */
    uint64_t capabilities;  /* Hardware capability flags */
    uint64_t memory_size;   /* Total memory size in bytes */
    uint32_t features;      /* Supported feature flags */
} guardian_hardware_info_t;

/*
 * Status flags for guardian_system_state_t
 */
#define GUARDIAN_STATUS_INITIALIZED  0x00000001
#define GUARDIAN_STATUS_SECURE      0x00000002
#define GUARDIAN_STATUS_DEGRADED    0x00000004
#define GUARDIAN_STATUS_ERROR       0x00000008

/*
 * Hardware capability flags for guardian_hardware_info_t
 */
#define GUARDIAN_CAP_TPM            0x0000000000000001ULL
#define GUARDIAN_CAP_SECURE_BOOT    0x0000000000000002ULL
#define GUARDIAN_CAP_IOMMU          0x0000000000000004ULL
#define GUARDIAN_CAP_ENCRYPTION     0x0000000000000008ULL
#define GUARDIAN_CAP_VIRTUALIZATION 0x0000000000000010ULL

/*
 * Feature flags for guardian_hardware_info_t
 */
#define GUARDIAN_FEATURE_DMA_PROTECTION  0x00000001
#define GUARDIAN_FEATURE_MEMORY_ENCRYPT  0x00000002
#define GUARDIAN_FEATURE_SECURE_STORAGE  0x00000004
#define GUARDIAN_FEATURE_TRUSTED_EXEC    0x00000008

#endif /* _GUARDIAN_TYPES_H_ */