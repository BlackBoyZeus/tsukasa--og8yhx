/*
 * DMA Controller Interface for Guardian System
 * FreeBSD Kernel Module Implementation
 *
 * Copyright (c) 2024. All rights reserved.
 *
 * This header defines a secure DMA controller interface for the Guardian system,
 * providing memory-safe transfer operations between system memory and gaming
 * console hardware components with enhanced security features.
 */

#ifndef _GUARDIAN_DMA_CONTROLLER_H_
#define _GUARDIAN_DMA_CONTROLLER_H_

#include <sys/bus.h>      /* FreeBSD 13.0 - Bus and DMA interfaces */
#include <sys/lock.h>     /* FreeBSD 13.0 - Synchronization primitives */
#include <machine/bus.h>  /* FreeBSD 13.0 - Machine-specific bus operations */

#include "../include/guardian_types.h"
#include "../include/guardian_errors.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * DMA Configuration Constants
 */
#define GUARDIAN_DMA_MAX_TRANSFER_SIZE 0x100000  /* 1MB maximum transfer size */
#define GUARDIAN_DMA_ALIGNMENT         0x1000    /* 4KB alignment requirement */
#define GUARDIAN_DMA_MAX_SEGMENTS      256       /* Maximum scatter-gather segments */
#define GUARDIAN_DMA_TIMEOUT_MS        1000      /* Default timeout in milliseconds */

/*
 * DMA Operation Flags
 */
#define GUARDIAN_DMA_FLAGS_READ        0x0001    /* Memory read operation */
#define GUARDIAN_DMA_FLAGS_WRITE       0x0002    /* Memory write operation */
#define GUARDIAN_DMA_FLAGS_COHERENT    0x0004    /* Enforce cache coherency */
#define GUARDIAN_DMA_FLAGS_SECURE      0x0008    /* Enable secure transfer mode */
#define GUARDIAN_DMA_FLAGS_VERIFY      0x0010    /* Verify transfer integrity */

/*
 * Enhanced DMA Configuration Structure
 */
typedef struct guardian_dma_config {
    size_t    max_transfer_size;    /* Maximum single transfer size */
    size_t    alignment;            /* Required memory alignment */
    uint32_t  flags;               /* Configuration flags */
    uint32_t  security_level;      /* Security enforcement level */
    uint32_t  timeout_ms;          /* Operation timeout in milliseconds */
} guardian_dma_config_t;

/*
 * Initialize the DMA controller subsystem with enhanced security features.
 *
 * @param handle: Pointer to store the initialized DMA controller handle
 * @param config: Pointer to DMA configuration structure
 * @return: GUARDIAN_SUCCESS on success, error code otherwise
 */
guardian_error_t guardian_dma_init(
    guardian_handle_t *handle,
    guardian_dma_config_t *config
);

/*
 * Allocate secure DMA-capable memory region with protection.
 *
 * @param handle: DMA controller handle
 * @param size: Size of memory region to allocate
 * @param flags: Memory allocation and protection flags
 * @param region: Pointer to store allocated memory region descriptor
 * @return: GUARDIAN_SUCCESS on success, error code otherwise
 */
guardian_error_t guardian_dma_allocate(
    guardian_handle_t handle,
    size_t size,
    uint32_t flags,
    guardian_memory_region_t *region
);

/*
 * Perform secure DMA transfer operation with validation.
 *
 * @param handle: DMA controller handle
 * @param src: Source memory region descriptor
 * @param dst: Destination memory region descriptor
 * @param size: Size of data to transfer
 * @param flags: Transfer operation flags
 * @return: GUARDIAN_SUCCESS on success, error code otherwise
 */
guardian_error_t guardian_dma_transfer(
    guardian_handle_t handle,
    guardian_memory_region_t *src,
    guardian_memory_region_t *dst,
    size_t size,
    uint32_t flags
);

/*
 * Free previously allocated DMA memory region.
 *
 * @param handle: DMA controller handle
 * @param region: Pointer to memory region descriptor
 * @return: GUARDIAN_SUCCESS on success, error code otherwise
 */
guardian_error_t guardian_dma_free(
    guardian_handle_t handle,
    guardian_memory_region_t *region
);

/*
 * Query DMA controller capabilities and status.
 *
 * @param handle: DMA controller handle
 * @param info: Pointer to store hardware information
 * @return: GUARDIAN_SUCCESS on success, error code otherwise
 */
guardian_error_t guardian_dma_get_info(
    guardian_handle_t handle,
    guardian_hardware_info_t *info
);

/*
 * Synchronize DMA memory region for device access.
 *
 * @param handle: DMA controller handle
 * @param region: Memory region to synchronize
 * @param flags: Synchronization flags (GUARDIAN_DMA_FLAGS_*)
 * @return: GUARDIAN_SUCCESS on success, error code otherwise
 */
guardian_error_t guardian_dma_sync(
    guardian_handle_t handle,
    guardian_memory_region_t *region,
    uint32_t flags
);

#ifdef __cplusplus
}
#endif

#endif /* _GUARDIAN_DMA_CONTROLLER_H_ */