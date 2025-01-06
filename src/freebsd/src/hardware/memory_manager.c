/*
 * Memory Manager Implementation - Guardian Security System
 * FreeBSD Kernel Module Implementation
 *
 * Copyright (c) 2024. All rights reserved.
 *
 * This module implements secure memory management for the Guardian system's
 * FreeBSD kernel module, providing hardware-optimized memory operations with
 * enhanced security features for the gaming console platform.
 *
 * Version: 1.0.0
 */

#include <sys/types.h>      /* FreeBSD 13.0 */
#include <sys/param.h>      /* FreeBSD 13.0 */
#include <vm/vm.h>         /* FreeBSD 13.0 */
#include <vm/vm_param.h>   /* FreeBSD 13.0 */
#include "memory_manager.h"
#include "../utils/error_handlers.h"
#include "../utils/debug_helpers.h"

/* Magic number for memory region validation */
#define MEMORY_REGION_MAGIC 0x47415244

/* Maximum number of concurrent memory regions */
#define MAX_MEMORY_REGIONS 1024

/* Hardware-specific memory alignment for gaming console */
#define MEMORY_ALIGNMENT 4096

/* DoD 5220.22-M secure wipe patterns */
static const uint8_t SECURE_WIPE_PATTERNS[] = {0x00, 0xFF, 0x00};
#define SECURE_WIPE_PASSES (sizeof(SECURE_WIPE_PATTERNS) / sizeof(uint8_t))

/* Memory region descriptor with enhanced security features */
typedef struct guardian_memory_region_internal {
    uint32_t magic;                /* Magic number for validation */
    void *base_address;           /* Base address of memory region */
    size_t size;                  /* Size of region in bytes */
    uint32_t flags;               /* Region flags */
    uint32_t protection;          /* Memory protection flags */
    bool dma_enabled;             /* DMA status flag */
    struct mtx lock;              /* Region mutex for thread safety */
} guardian_memory_region_internal_t;

/* Static array of memory regions for tracking */
static guardian_memory_region_internal_t memory_regions[MAX_MEMORY_REGIONS];
static struct mtx regions_lock;    /* Global lock for region array */

/*
 * Initialize a memory region descriptor with security validation
 */
static guardian_error_t init_memory_region(
    guardian_memory_region_internal_t *region,
    void *base_address,
    size_t size,
    uint32_t flags
) {
    if (!region || !base_address) {
        GUARDIAN_LOG_ERROR(GUARDIAN_E_INVALID_PARAM, GUARDIAN_SEV_ERROR,
                          "Invalid parameters in init_memory_region");
        return GUARDIAN_E_INVALID_PARAM;
    }

    mtx_init(&region->lock, "guardian_region_lock", NULL, MTX_DEF);
    region->magic = MEMORY_REGION_MAGIC;
    region->base_address = base_address;
    region->size = size;
    region->flags = flags;
    region->protection = GUARDIAN_MEM_READ | GUARDIAN_MEM_WRITE;
    region->dma_enabled = (flags & GUARDIAN_MEM_DMA) ? true : false;

    return GUARDIAN_SUCCESS;
}

/*
 * Securely wipe memory region contents using DoD patterns
 */
static void secure_wipe_region(void *address, size_t size) {
    for (size_t pass = 0; pass < SECURE_WIPE_PASSES; pass++) {
        memset(address, SECURE_WIPE_PATTERNS[pass], size);
        /* Force memory synchronization */
        wmb();
    }
}

/*
 * Validate memory region descriptor with enhanced security checks
 */
static guardian_error_t validate_region(
    guardian_memory_region_internal_t *region
) {
    if (!region || region->magic != MEMORY_REGION_MAGIC) {
        GUARDIAN_LOG_ERROR(GUARDIAN_E_SECURITY, GUARDIAN_SEV_ERROR,
                          "Invalid memory region magic");
        return GUARDIAN_E_SECURITY;
    }

    if (!region->base_address || region->size == 0) {
        GUARDIAN_LOG_ERROR(GUARDIAN_E_INVALID_PARAM, GUARDIAN_SEV_ERROR,
                          "Invalid memory region parameters");
        return GUARDIAN_E_INVALID_PARAM;
    }

    return GUARDIAN_SUCCESS;
}

guardian_memory_region_t* guardian_mem_alloc(
    guardian_handle_t handle,
    size_t size,
    uint32_t flags
) {
    guardian_error_t error;
    void *base_address;
    guardian_memory_region_internal_t *region = NULL;
    int region_index = -1;

    if (!handle || !size) {
        GUARDIAN_LOG_ERROR(GUARDIAN_E_INVALID_PARAM, GUARDIAN_SEV_ERROR,
                          "Invalid parameters in guardian_mem_alloc");
        return NULL;
    }

    /* Align size to hardware page boundary */
    size = roundup2(size, MEMORY_ALIGNMENT);

    /* Acquire global lock for region allocation */
    mtx_lock(&regions_lock);

    /* Find free region slot */
    for (int i = 0; i < MAX_MEMORY_REGIONS; i++) {
        if (memory_regions[i].magic != MEMORY_REGION_MAGIC) {
            region = &memory_regions[i];
            region_index = i;
            break;
        }
    }

    if (region_index == -1) {
        GUARDIAN_LOG_ERROR(GUARDIAN_E_MEMORY, GUARDIAN_SEV_ERROR,
                          "No free memory regions available");
        mtx_unlock(&regions_lock);
        return NULL;
    }

    /* Allocate physical memory pages */
    base_address = kmem_alloc_contig(kernel_arena, size,
                                   M_ZERO | M_WAITOK,
                                   0, ~0UL,
                                   MEMORY_ALIGNMENT,
                                   0,
                                   VM_MEMATTR_DEFAULT);

    if (!base_address) {
        GUARDIAN_LOG_ERROR(GUARDIAN_E_MEMORY, GUARDIAN_SEV_ERROR,
                          "Failed to allocate physical memory");
        mtx_unlock(&regions_lock);
        return NULL;
    }

    /* Initialize region descriptor */
    error = init_memory_region(region, base_address, size, flags);
    if (error != GUARDIAN_SUCCESS) {
        kmem_free(kernel_arena, (vm_offset_t)base_address, size);
        mtx_unlock(&regions_lock);
        return NULL;
    }

    /* Configure memory protection */
    if (flags & GUARDIAN_MEM_NOEXEC) {
        region->protection &= ~GUARDIAN_MEM_EXECUTE;
    }
    if (flags & GUARDIAN_MEM_READONLY) {
        region->protection &= ~GUARDIAN_MEM_WRITE;
    }

    guardian_debug_log(GUARDIAN_DEBUG_LEVEL_INFO,
                      "Allocated memory region %d: base=%p, size=%zu, flags=0x%x",
                      region_index, base_address, size, flags);

    mtx_unlock(&regions_lock);
    return (guardian_memory_region_t*)region;
}

guardian_error_t guardian_mem_free(
    guardian_handle_t handle,
    guardian_memory_region_t* region
) {
    guardian_memory_region_internal_t *internal_region;
    guardian_error_t error;

    if (!handle || !region) {
        GUARDIAN_LOG_ERROR(GUARDIAN_E_INVALID_PARAM, GUARDIAN_SEV_ERROR,
                          "Invalid parameters in guardian_mem_free");
        return GUARDIAN_E_INVALID_PARAM;
    }

    internal_region = (guardian_memory_region_internal_t*)region;

    /* Validate region with security checks */
    error = validate_region(internal_region);
    if (error != GUARDIAN_SUCCESS) {
        return error;
    }

    /* Acquire region lock */
    mtx_lock(&internal_region->lock);

    /* Check if region is in use by DMA */
    if (internal_region->dma_enabled) {
        GUARDIAN_LOG_ERROR(GUARDIAN_E_BUSY, GUARDIAN_SEV_ERROR,
                          "Cannot free region while DMA is active");
        mtx_unlock(&internal_region->lock);
        return GUARDIAN_E_BUSY;
    }

    /* Securely wipe memory contents */
    secure_wipe_region(internal_region->base_address, internal_region->size);

    /* Free physical memory */
    kmem_free(kernel_arena, (vm_offset_t)internal_region->base_address,
              internal_region->size);

    /* Clear region descriptor */
    internal_region->magic = 0;
    internal_region->base_address = NULL;
    internal_region->size = 0;
    internal_region->flags = 0;
    internal_region->protection = 0;
    internal_region->dma_enabled = false;

    mtx_unlock(&internal_region->lock);
    mtx_destroy(&internal_region->lock);

    guardian_debug_log(GUARDIAN_DEBUG_LEVEL_INFO,
                      "Freed memory region: %p", region);

    return GUARDIAN_SUCCESS;
}

guardian_error_t guardian_mem_get_info(
    guardian_handle_t handle,
    guardian_memory_region_t* region
) {
    guardian_memory_region_internal_t *internal_region;
    guardian_error_t error;

    if (!handle || !region) {
        GUARDIAN_LOG_ERROR(GUARDIAN_E_INVALID_PARAM, GUARDIAN_SEV_ERROR,
                          "Invalid parameters in guardian_mem_get_info");
        return GUARDIAN_E_INVALID_PARAM;
    }

    internal_region = (guardian_memory_region_internal_t*)region;

    /* Validate region with security checks */
    error = validate_region(internal_region);
    if (error != GUARDIAN_SUCCESS) {
        return error;
    }

    /* Acquire region lock */
    mtx_lock(&internal_region->lock);

    /* Fill region information structure */
    region->base_address = internal_region->base_address;
    region->size = internal_region->size;
    region->flags = internal_region->flags;
    region->protection = internal_region->protection;

    mtx_unlock(&internal_region->lock);

    guardian_debug_log(GUARDIAN_DEBUG_LEVEL_DEBUG,
                      "Retrieved info for region: %p", region);

    return GUARDIAN_SUCCESS;
}