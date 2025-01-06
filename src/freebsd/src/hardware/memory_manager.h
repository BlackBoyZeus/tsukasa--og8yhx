/*
 * Memory Manager Interface - Guardian Security System
 * FreeBSD Kernel Module Implementation
 *
 * Copyright (c) 2024. All rights reserved.
 *
 * This header defines the secure memory management interface for the Guardian
 * system's FreeBSD kernel module, providing hardware-level memory operations
 * with enhanced security features for the gaming console platform.
 *
 * Version: 1.0.0
 */

#ifndef _GUARDIAN_MEMORY_MANAGER_H_
#define _GUARDIAN_MEMORY_MANAGER_H_

#include <sys/types.h>      /* FreeBSD 13.0 - Basic system types */
#include <sys/param.h>      /* FreeBSD 13.0 - System parameters */
#include <vm/vm.h>         /* FreeBSD 13.0 - Virtual memory interfaces */
#include <vm/vm_param.h>   /* FreeBSD 13.0 - Virtual memory parameters */

#include "../include/guardian_types.h"
#include "../include/guardian_errors.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Memory allocation flags defining memory region attributes and protection levels
 */
#define GUARDIAN_MEM_NORMAL    0x00    /* Standard memory allocation */
#define GUARDIAN_MEM_SECURE    0x01    /* Enhanced security features enabled */
#define GUARDIAN_MEM_DMA       0x02    /* DMA-capable memory region */
#define GUARDIAN_MEM_CACHED    0x04    /* Memory region is cached */
#define GUARDIAN_MEM_UNCACHED  0x08    /* Memory region is uncached */
#define GUARDIAN_MEM_NOEXEC    0x10    /* Non-executable memory region */
#define GUARDIAN_MEM_READONLY  0x20    /* Read-only memory region */

/*
 * Allocates a memory region with specified attributes and enhanced security features.
 *
 * @param handle: Valid Guardian system handle
 * @param size: Size of memory region to allocate in bytes
 * @param flags: Memory allocation flags (GUARDIAN_MEM_*)
 * @return: Pointer to allocated memory region descriptor or NULL on failure
 *
 * Thread-safe: Yes
 * IRQ-safe: No
 */
__attribute__((warn_unused_result))
guardian_memory_region_t* guardian_mem_alloc(
    guardian_handle_t handle,
    size_t size,
    uint32_t flags
);

/*
 * Frees a previously allocated memory region with secure wiping.
 *
 * @param handle: Valid Guardian system handle
 * @param region: Pointer to memory region descriptor to free
 * @return: GUARDIAN_SUCCESS on success, error code otherwise
 *
 * Thread-safe: Yes
 * IRQ-safe: No
 */
__attribute__((nonnull))
guardian_error_t guardian_mem_free(
    guardian_handle_t handle,
    guardian_memory_region_t* region
);

/*
 * Retrieves detailed information about a memory region including protection status.
 *
 * @param handle: Valid Guardian system handle
 * @param region: Pointer to memory region descriptor
 * @return: GUARDIAN_SUCCESS on success, error code otherwise
 *
 * Thread-safe: Yes
 * IRQ-safe: Yes
 */
__attribute__((nonnull))
guardian_error_t guardian_mem_get_info(
    guardian_handle_t handle,
    guardian_memory_region_t* region
);

#ifdef __cplusplus
}
#endif

#endif /* _GUARDIAN_MEMORY_MANAGER_H_ */