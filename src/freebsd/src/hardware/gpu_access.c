/*
 * Guardian System - Secure GPU Access Implementation
 * FreeBSD Kernel Module
 *
 * Copyright (c) 2024. All rights reserved.
 *
 * Implements secure GPU access interface with hardware-level protection,
 * DMA security, and memory management for the Guardian system.
 */

#include <sys/types.h>      /* FreeBSD 13.0 */
#include <sys/param.h>      /* FreeBSD 13.0 */
#include <sys/mutex.h>      /* FreeBSD 13.0 */
#include <machine/gpu.h>    /* FreeBSD 13.0 */
#include "../include/guardian_types.h"
#include "../include/guardian_errors.h"
#include "gpu_access.h"

/* Global mutex for GPU operations synchronization */
static struct mtx gpu_mutex;

/* Memory region tracking */
static guardian_memory_region_t allocated_regions[GUARDIAN_GPU_MAX_REGIONS];
static uint32_t num_allocated_regions = 0;

/* GPU security context */
typedef struct guardian_gpu_security_ctx {
    uint32_t initialized;
    uint64_t capabilities;
    uint32_t dma_boundary_mask;
    void *secure_memory_base;
    size_t secure_memory_size;
} guardian_gpu_security_ctx_t;

static guardian_gpu_security_ctx_t gpu_security_context = {0};

/* Internal helper functions */
static guardian_error_t verify_gpu_security_features(void) {
    uint64_t hw_caps;
    
    /* Query hardware capabilities */
    if (gpu_get_capabilities(&hw_caps) != 0) {
        return GUARDIAN_E_SECURITY;
    }

    /* Verify required security features */
    if (!(hw_caps & GUARDIAN_CAP_IOMMU) || 
        !(hw_caps & GUARDIAN_CAP_ENCRYPTION)) {
        return GUARDIAN_E_NOT_SUPPORTED;
    }

    gpu_security_context.capabilities = hw_caps;
    return GUARDIAN_SUCCESS;
}

static guardian_error_t setup_dma_protection(void) {
    /* Configure DMA protection boundaries */
    if (gpu_configure_dma_protection(
            gpu_security_context.secure_memory_base,
            gpu_security_context.secure_memory_size) != 0) {
        return GUARDIAN_E_SECURITY;
    }
    
    gpu_security_context.dma_boundary_mask = gpu_get_dma_boundary_mask();
    return GUARDIAN_SUCCESS;
}

static int find_free_region_slot(void) {
    for (uint32_t i = 0; i < GUARDIAN_GPU_MAX_REGIONS; i++) {
        if (allocated_regions[i].base_address == NULL) {
            return i;
        }
    }
    return -1;
}

/* Implementation of public interface */
guardian_error_t guardian_gpu_init(guardian_handle_t *handle) {
    guardian_error_t ret;

    if (handle == NULL) {
        return GUARDIAN_E_INVALID_PARAM;
    }

    /* Initialize mutex */
    mtx_init(&gpu_mutex, "guardian_gpu_mutex", NULL, MTX_DEF);

    /* Verify GPU security features */
    ret = verify_gpu_security_features();
    if (ret != GUARDIAN_SUCCESS) {
        goto cleanup;
    }

    /* Initialize secure memory region */
    gpu_security_context.secure_memory_base = gpu_get_secure_memory_base();
    gpu_security_context.secure_memory_size = gpu_get_secure_memory_size();

    /* Setup DMA protection */
    ret = setup_dma_protection();
    if (ret != GUARDIAN_SUCCESS) {
        goto cleanup;
    }

    /* Initialize memory region tracking */
    memset(allocated_regions, 0, sizeof(allocated_regions));
    num_allocated_regions = 0;

    gpu_security_context.initialized = 1;
    *handle = (guardian_handle_t)&gpu_security_context;
    return GUARDIAN_SUCCESS;

cleanup:
    mtx_destroy(&gpu_mutex);
    memset(&gpu_security_context, 0, sizeof(gpu_security_context));
    return ret;
}

guardian_error_t guardian_gpu_alloc_memory(
    guardian_handle_t handle,
    size_t size,
    uint32_t flags,
    guardian_memory_region_t *region
) {
    guardian_error_t ret = GUARDIAN_SUCCESS;
    int slot;
    void *memory = NULL;

    if (!handle || !region || !size) {
        return GUARDIAN_E_INVALID_PARAM;
    }

    mtx_lock(&gpu_mutex);

    /* Validate security context */
    if (!gpu_security_context.initialized) {
        ret = GUARDIAN_E_NOT_INITIALIZED;
        goto unlock;
    }

    /* Check region limit */
    if (num_allocated_regions >= GUARDIAN_GPU_MAX_REGIONS) {
        ret = GUARDIAN_E_MEMORY;
        goto unlock;
    }

    /* Find free slot */
    slot = find_free_region_slot();
    if (slot < 0) {
        ret = GUARDIAN_E_MEMORY;
        goto unlock;
    }

    /* Allocate GPU memory with security flags */
    memory = gpu_secure_alloc(size, flags & GUARDIAN_GPU_FLAG_DMA_PROTECTED);
    if (!memory) {
        ret = GUARDIAN_E_MEMORY;
        goto unlock;
    }

    /* Setup memory protection */
    if (flags & GUARDIAN_GPU_FLAG_SECURE) {
        if (gpu_protect_memory(memory, size, flags) != 0) {
            gpu_secure_free(memory);
            ret = GUARDIAN_E_SECURITY;
            goto unlock;
        }
    }

    /* Initialize region structure */
    allocated_regions[slot].base_address = memory;
    allocated_regions[slot].size = size;
    allocated_regions[slot].flags = flags;
    allocated_regions[slot].protection = gpu_get_protection_flags(flags);

    /* Copy to output parameter */
    memcpy(region, &allocated_regions[slot], sizeof(guardian_memory_region_t));
    num_allocated_regions++;

unlock:
    mtx_unlock(&gpu_mutex);
    return ret;
}

guardian_error_t guardian_gpu_free_memory(
    guardian_handle_t handle,
    guardian_memory_region_t *region
) {
    guardian_error_t ret = GUARDIAN_SUCCESS;
    int found = 0;

    if (!handle || !region || !region->base_address) {
        return GUARDIAN_E_INVALID_PARAM;
    }

    mtx_lock(&gpu_mutex);

    /* Validate security context */
    if (!gpu_security_context.initialized) {
        ret = GUARDIAN_E_NOT_INITIALIZED;
        goto unlock;
    }

    /* Find and validate region */
    for (uint32_t i = 0; i < GUARDIAN_GPU_MAX_REGIONS; i++) {
        if (allocated_regions[i].base_address == region->base_address) {
            /* Secure memory wiping */
            if (allocated_regions[i].flags & GUARDIAN_GPU_FLAG_SECURE) {
                gpu_secure_wipe(region->base_address, region->size);
            }

            /* Release GPU memory */
            gpu_secure_free(region->base_address);
            memset(&allocated_regions[i], 0, sizeof(guardian_memory_region_t));
            num_allocated_regions--;
            found = 1;
            break;
        }
    }

    if (!found) {
        ret = GUARDIAN_E_INVALID_PARAM;
    }

unlock:
    mtx_unlock(&gpu_mutex);
    return ret;
}

guardian_error_t guardian_gpu_get_info(
    guardian_handle_t handle,
    guardian_hardware_info_t *info
) {
    guardian_error_t ret = GUARDIAN_SUCCESS;

    if (!handle || !info) {
        return GUARDIAN_E_INVALID_PARAM;
    }

    mtx_lock(&gpu_mutex);

    /* Validate security context */
    if (!gpu_security_context.initialized) {
        ret = GUARDIAN_E_NOT_INITIALIZED;
        goto unlock;
    }

    /* Query GPU hardware info */
    info->device_id = gpu_get_device_id();
    info->capabilities = gpu_security_context.capabilities;
    info->memory_size = gpu_security_context.secure_memory_size;
    info->features = gpu_get_security_features();

unlock:
    mtx_unlock(&gpu_mutex);
    return ret;
}