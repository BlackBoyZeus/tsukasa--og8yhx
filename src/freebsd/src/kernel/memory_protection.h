/*
 * Guardian System - Memory Protection Interface
 * 
 * This header defines the memory protection interface for the Guardian system's
 * FreeBSD kernel module, providing secure memory isolation, access control,
 * and monitoring capabilities for the gaming console environment.
 *
 * Version: 1.0.0
 * FreeBSD Version: 13.0
 */

#ifndef _GUARDIAN_MEMORY_PROTECTION_H_
#define _GUARDIAN_MEMORY_PROTECTION_H_

#include <sys/types.h>      /* FreeBSD 13.0 - System type definitions */
#include <vm/vm.h>          /* FreeBSD 13.0 - Virtual memory interfaces */
#include <vm/vm_param.h>    /* FreeBSD 13.0 - Virtual memory parameters */
#include <machine/cpu.h>    /* FreeBSD 13.0 - CPU-specific memory features */
#include "guardian_types.h"
#include "guardian_errors.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Memory region limits and protection flags
 */
#define GUARDIAN_MEM_REGION_MAX         1024    /* Maximum number of protected regions */
#define GUARDIAN_MEM_PROT_NONE         0x0     /* No access permissions */
#define GUARDIAN_MEM_PROT_READ         0x1     /* Read permission */
#define GUARDIAN_MEM_PROT_WRITE        0x2     /* Write permission */
#define GUARDIAN_MEM_PROT_EXEC         0x4     /* Execute permission */
#define GUARDIAN_MEM_PROT_DMA          0x8     /* DMA access permission */
#define GUARDIAN_MEM_PROT_CACHE_WB     0x10    /* Write-back cache policy */
#define GUARDIAN_MEM_PROT_CACHE_WT     0x20    /* Write-through cache policy */
#define GUARDIAN_MEM_PROT_NO_SIDE_CHANNEL 0x40 /* Side-channel protection */

/*
 * DMA protection configuration
 */
typedef struct guardian_dma_protection {
    uint64_t dma_mask;          /* DMA address mask */
    uint32_t dma_flags;         /* DMA protection flags */
    uint32_t reserved;          /* Reserved for alignment */
} guardian_dma_protection_t;

/*
 * Cache configuration
 */
typedef struct guardian_cache_config {
    uint32_t cache_policy;      /* Cache policy flags */
    uint32_t coherency_mask;    /* Cache coherency domain mask */
    uint32_t prefetch_flags;    /* Prefetch behavior flags */
    uint32_t reserved;          /* Reserved for alignment */
} guardian_cache_config_t;

/*
 * Memory protection audit information
 */
typedef struct guardian_audit_info {
    uint64_t access_count;      /* Number of memory accesses */
    uint64_t violation_count;   /* Number of protection violations */
    uint64_t last_access;       /* Timestamp of last access */
    uint32_t last_pid;          /* PID of last accessor */
    uint32_t reserved;          /* Reserved for alignment */
} guardian_audit_info_t;

/*
 * Memory protection region configuration
 */
typedef struct guardian_mp_protection {
    void* start_addr;                      /* Region start address */
    size_t size;                           /* Region size */
    uint32_t flags;                        /* Protection flags */
    guardian_memory_stats_t stats;         /* Memory statistics */
    guardian_dma_protection_t dma_protection; /* DMA protection config */
    guardian_cache_config_t cache_config;  /* Cache configuration */
    guardian_audit_info_t audit_info;      /* Audit information */
} guardian_mp_protection_t;

/*
 * Memory protection configuration
 */
typedef struct guardian_mp_config {
    uint32_t max_regions;                  /* Maximum number of regions */
    uint32_t default_flags;                /* Default protection flags */
    guardian_dma_protection_t default_dma; /* Default DMA protection */
    guardian_cache_config_t default_cache; /* Default cache config */
    uint64_t reserved[4];                  /* Reserved for future use */
} guardian_mp_config_t;

/*
 * Function declarations
 */

/*
 * Initialize memory protection subsystem
 * Must be called before any other memory protection operations
 */
guardian_status_t guardian_mp_init(
    guardian_mp_config_t* config
) __must_check;

/*
 * Apply protection to a memory region
 * Requires region_mutex to be held
 */
guardian_status_t guardian_mp_protect_region(
    guardian_memory_region_t* region,
    uint32_t protection_flags,
    guardian_audit_context_t* audit_ctx
) __must_check __lock_required(region_mutex);

/*
 * Query protection information for a memory region
 */
guardian_status_t guardian_mp_query_protection(
    const void* addr,
    guardian_mp_protection_t* protection
) __must_check;

/*
 * Update protection flags for an existing region
 */
guardian_status_t guardian_mp_update_protection(
    guardian_memory_region_t* region,
    uint32_t new_flags,
    guardian_audit_context_t* audit_ctx
) __must_check __lock_required(region_mutex);

/*
 * Configure DMA protection for a region
 */
guardian_status_t guardian_mp_configure_dma(
    guardian_memory_region_t* region,
    const guardian_dma_protection_t* dma_config,
    guardian_audit_context_t* audit_ctx
) __must_check __lock_required(region_mutex);

/*
 * Configure cache behavior for a region
 */
guardian_status_t guardian_mp_configure_cache(
    guardian_memory_region_t* region,
    const guardian_cache_config_t* cache_config,
    guardian_audit_context_t* audit_ctx
) __must_check __lock_required(region_mutex);

/*
 * Get memory protection statistics
 */
guardian_status_t guardian_mp_get_stats(
    guardian_memory_stats_t* stats
) __must_check;

/*
 * Reset memory protection subsystem
 * Warning: This will remove all protections
 */
guardian_status_t guardian_mp_reset(
    guardian_audit_context_t* audit_ctx
) __must_check;

#ifdef __cplusplus
}
#endif

#endif /* _GUARDIAN_MEMORY_PROTECTION_H_ */