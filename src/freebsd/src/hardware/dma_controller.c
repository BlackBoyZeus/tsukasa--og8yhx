/*
 * DMA Controller Implementation for Guardian System
 * FreeBSD Kernel Module Implementation
 *
 * Copyright (c) 2024. All rights reserved.
 *
 * Implements secure DMA operations with enhanced memory protection,
 * validation, and comprehensive error handling for the Guardian system.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/bus.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/kernel.h>
#include <machine/bus.h>
#include <machine/atomic.h>

#include "../include/guardian_types.h"
#include "dma_controller.h"

/* DMA descriptor structure with enhanced security features */
typedef struct guardian_dma_descriptor {
    bus_dma_tag_t    tag;
    bus_dmamap_t     map;
    void            *vaddr;
    bus_addr_t       paddr;
    size_t           size;
    uint32_t         flags;
    uint32_t         security_status;
    struct guardian_dma_descriptor *next;
} guardian_dma_descriptor_t;

/* DMA security context for enhanced protection */
typedef struct guardian_dma_security_context {
    uint32_t         validation_flags;
    uint32_t         protection_level;
    uint64_t         secure_signature;
    volatile uint32_t status;
} guardian_dma_security_context_t;

/* Global state variables */
static struct mtx g_dma_lock;
static bool g_dma_initialized = false;
static guardian_dma_descriptor_t *g_dma_descriptor_pool = NULL;
static guardian_dma_security_context_t g_dma_security_context;

/* Security validation constants */
#define DMA_SECURITY_SIGNATURE    0xGUARD1AN5
#define DMA_MIN_PROTECTION_LEVEL  2
#define DMA_MAX_RETRIES          3

/* Forward declarations for internal functions */
static guardian_error_t validate_dma_parameters(
    guardian_handle_t handle,
    guardian_memory_region_t *src,
    guardian_memory_region_t *dst,
    size_t size,
    uint32_t flags
);

static guardian_error_t setup_dma_descriptor(
    guardian_dma_descriptor_t *desc,
    guardian_memory_region_t *region,
    uint32_t flags
);

static void cleanup_dma_resources(guardian_dma_descriptor_t *desc);

/*
 * Initialize the DMA controller subsystem with enhanced security validation
 */
guardian_error_t guardian_dma_init(
    guardian_handle_t *handle,
    guardian_dma_config_t *config
) {
    if (handle == NULL || config == NULL) {
        return GUARDIAN_E_INVALID_PARAM;
    }

    /* Prevent multiple initialization */
    if (atomic_cmpset_32((uint32_t *)&g_dma_initialized, false, true) == 0) {
        return GUARDIAN_E_BUSY;
    }

    /* Initialize synchronization primitive */
    mtx_init(&g_dma_lock, "guardian_dma_lock", NULL, MTX_DEF);

    /* Configure security context */
    g_dma_security_context.validation_flags = config->flags;
    g_dma_security_context.protection_level = 
        MAX(config->security_level, DMA_MIN_PROTECTION_LEVEL);
    g_dma_security_context.secure_signature = DMA_SECURITY_SIGNATURE;
    g_dma_security_context.status = 0;

    /* Initialize descriptor pool */
    g_dma_descriptor_pool = NULL;

    /* Generate and return secure handle */
    *handle = (guardian_handle_t)&g_dma_security_context;
    
    return GUARDIAN_SUCCESS;
}

/*
 * Perform secure DMA transfer operation with enhanced validation and protection
 */
guardian_error_t guardian_dma_transfer(
    guardian_handle_t handle,
    guardian_memory_region_t *src,
    guardian_memory_region_t *dst,
    size_t size,
    uint32_t flags
) {
    guardian_error_t error;
    guardian_dma_descriptor_t src_desc, dst_desc;
    int retry_count = 0;

    /* Validate parameters and security context */
    error = validate_dma_parameters(handle, src, dst, size, flags);
    if (error != GUARDIAN_SUCCESS) {
        return error;
    }

    /* Acquire lock for DMA operations */
    mtx_lock(&g_dma_lock);

    /* Setup source and destination descriptors */
    error = setup_dma_descriptor(&src_desc, src, flags);
    if (error != GUARDIAN_SUCCESS) {
        mtx_unlock(&g_dma_lock);
        return error;
    }

    error = setup_dma_descriptor(&dst_desc, dst, flags);
    if (error != GUARDIAN_SUCCESS) {
        cleanup_dma_resources(&src_desc);
        mtx_unlock(&g_dma_lock);
        return error;
    }

    /* Perform DMA transfer with retry mechanism */
    do {
        /* Sync source for device access */
        bus_dmamap_sync(src_desc.tag, src_desc.map, 
                       BUS_DMASYNC_PREREAD);
        
        /* Sync destination for device access */
        bus_dmamap_sync(dst_desc.tag, dst_desc.map,
                       BUS_DMASYNC_PREWRITE);

        /* Execute DMA transfer */
        error = bus_dmamap_load(dst_desc.tag, dst_desc.map,
                               dst_desc.vaddr, size,
                               NULL, BUS_DMA_NOWAIT);

        /* Verify transfer completion */
        if (error == GUARDIAN_SUCCESS) {
            /* Sync buffers post-transfer */
            bus_dmamap_sync(src_desc.tag, src_desc.map,
                           BUS_DMASYNC_POSTREAD);
            bus_dmamap_sync(dst_desc.tag, dst_desc.map,
                           BUS_DMASYNC_POSTWRITE);

            /* Verify transfer integrity if required */
            if (flags & GUARDIAN_DMA_FLAGS_VERIFY) {
                if (memcmp(src_desc.vaddr, dst_desc.vaddr, size) != 0) {
                    error = GUARDIAN_E_SECURITY;
                }
            }
        }

        retry_count++;
    } while (error != GUARDIAN_SUCCESS && retry_count < DMA_MAX_RETRIES);

    /* Cleanup resources */
    cleanup_dma_resources(&src_desc);
    cleanup_dma_resources(&dst_desc);

    mtx_unlock(&g_dma_lock);
    return error;
}

/*
 * Internal function to validate DMA parameters and security context
 */
static guardian_error_t validate_dma_parameters(
    guardian_handle_t handle,
    guardian_memory_region_t *src,
    guardian_memory_region_t *dst,
    size_t size,
    uint32_t flags
) {
    guardian_dma_security_context_t *ctx;

    if (!g_dma_initialized) {
        return GUARDIAN_E_NOT_INITIALIZED;
    }

    if (handle == GUARDIAN_INVALID_HANDLE || src == NULL || dst == NULL) {
        return GUARDIAN_E_INVALID_PARAM;
    }

    ctx = (guardian_dma_security_context_t *)handle;
    if (ctx->secure_signature != DMA_SECURITY_SIGNATURE) {
        return GUARDIAN_E_SECURITY;
    }

    /* Validate size and alignment */
    if (size == 0 || size > GUARDIAN_DMA_MAX_TRANSFER_SIZE ||
        ((uintptr_t)src->base_address & (GUARDIAN_DMA_ALIGNMENT - 1)) ||
        ((uintptr_t)dst->base_address & (GUARDIAN_DMA_ALIGNMENT - 1))) {
        return GUARDIAN_E_INVALID_PARAM;
    }

    /* Validate memory regions */
    if (!(src->flags & GUARDIAN_MEM_READ) ||
        !(dst->flags & GUARDIAN_MEM_WRITE)) {
        return GUARDIAN_E_PERMISSION;
    }

    return GUARDIAN_SUCCESS;
}

/*
 * Internal function to setup DMA descriptor
 */
static guardian_error_t setup_dma_descriptor(
    guardian_dma_descriptor_t *desc,
    guardian_memory_region_t *region,
    uint32_t flags
) {
    int error;

    /* Create DMA tag */
    error = bus_dma_tag_create(
        NULL,                          /* parent tag */
        GUARDIAN_DMA_ALIGNMENT,        /* alignment */
        0,                            /* boundary */
        BUS_SPACE_MAXADDR,           /* lowaddr */
        BUS_SPACE_MAXADDR,           /* highaddr */
        NULL, NULL,                  /* filter, filterarg */
        region->size,                /* maxsize */
        1,                          /* nsegments */
        region->size,               /* maxsegsz */
        BUS_DMA_ALLOCNOW,          /* flags */
        NULL, NULL,                /* lockfunc, lockarg */
        &desc->tag                 /* tag */
    );

    if (error != 0) {
        return GUARDIAN_E_MEMORY;
    }

    /* Create DMA map */
    error = bus_dmamap_create(desc->tag, 0, &desc->map);
    if (error != 0) {
        bus_dma_tag_destroy(desc->tag);
        return GUARDIAN_E_MEMORY;
    }

    desc->vaddr = region->base_address;
    desc->size = region->size;
    desc->flags = flags;
    desc->security_status = 0;

    return GUARDIAN_SUCCESS;
}

/*
 * Internal function to cleanup DMA resources
 */
static void cleanup_dma_resources(guardian_dma_descriptor_t *desc) {
    if (desc->map != NULL) {
        bus_dmamap_destroy(desc->tag, desc->map);
    }
    if (desc->tag != NULL) {
        bus_dma_tag_destroy(desc->tag);
    }
}