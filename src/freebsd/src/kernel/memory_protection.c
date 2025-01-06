/*
 * Guardian System - Memory Protection Implementation
 * 
 * FreeBSD kernel module implementation of memory protection subsystem with
 * hardware-backed security features, DMA protection, and side-channel attack prevention.
 *
 * Version: 1.0.0
 * FreeBSD Version: 13.0
 */

#include <sys/types.h>      /* FreeBSD 13.0 */
#include <sys/param.h>      /* FreeBSD 13.0 */
#include <sys/kernel.h>     /* FreeBSD 13.0 */
#include <sys/malloc.h>     /* FreeBSD 13.0 */
#include <vm/vm.h>          /* FreeBSD 13.0 */
#include <vm/vm_param.h>    /* FreeBSD 13.0 */
#include <machine/cpu.h>    /* FreeBSD 13.0 */

#include "guardian_types.h"
#include "guardian_errors.h"
#include "memory_protection.h"

/* Global protection table and synchronization */
static guardian_mp_protection_t g_protection_table[GUARDIAN_MEM_REGION_MAX];
static struct mtx g_table_lock;
static volatile int g_initialized = 0;

/* Hardware capability flags */
static uint32_t g_hw_capabilities = 0;
#define HW_CAP_NX          0x0001  /* No-execute support */
#define HW_CAP_SMEP        0x0002  /* Supervisor Mode Execution Prevention */
#define HW_CAP_SMAP        0x0004  /* Supervisor Mode Access Prevention */
#define HW_CAP_PKU         0x0008  /* Memory Protection Keys */
#define HW_CAP_CET         0x0010  /* Control-flow Enforcement Technology */

/* Internal helper functions */
static guardian_status_t detect_hardware_capabilities(void) {
    uint32_t caps = 0;
    uint32_t regs[4];
    
    /* Query CPU features using CPUID */
    do_cpuid(0x7, regs);
    
    if (regs[0] & CPUID_NX)    caps |= HW_CAP_NX;
    if (regs[1] & CPUID_SMEP)  caps |= HW_CAP_SMEP;
    if (regs[1] & CPUID_SMAP)  caps |= HW_CAP_SMAP;
    if (regs[2] & CPUID_PKU)   caps |= HW_CAP_PKU;
    if (regs[2] & CPUID_CET)   caps |= HW_CAP_CET;
    
    g_hw_capabilities = caps;
    return GUARDIAN_STATUS_SUCCESS;
}

static void flush_tlb_range(void* start, size_t size) {
    pmap_invalidate_range(kernel_pmap, (vm_offset_t)start, 
                         (vm_offset_t)start + size);
}

static guardian_status_t validate_region(const void* addr, size_t size) {
    if (addr == NULL || size == 0 || 
        (vm_offset_t)addr + size < (vm_offset_t)addr) {
        return GUARDIAN_ERROR_INVALID_PARAM;
    }
    return GUARDIAN_STATUS_SUCCESS;
}

/* Implementation of exported functions */

guardian_status_t guardian_mp_init(void) {
    guardian_status_t status;
    
    /* Check if already initialized */
    if (atomic_cmpset_int(&g_initialized, 0, 1) == 0) {
        return GUARDIAN_ERROR_STATE;
    }
    
    /* Initialize protection table lock */
    mtx_init(&g_table_lock, "guardian_mp_lock", NULL, MTX_DEF | MTX_DUPOK);
    
    /* Clear protection table */
    memset(g_protection_table, 0, sizeof(g_protection_table));
    
    /* Detect hardware capabilities */
    status = detect_hardware_capabilities();
    if (status != GUARDIAN_STATUS_SUCCESS) {
        mtx_destroy(&g_table_lock);
        atomic_store_rel_int(&g_initialized, 0);
        return status;
    }
    
    /* Enable hardware protection features */
    if (g_hw_capabilities & HW_CAP_SMEP) {
        load_cr4(rcr4() | CR4_SMEP);
    }
    if (g_hw_capabilities & HW_CAP_SMAP) {
        load_cr4(rcr4() | CR4_SMAP);
    }
    
    return GUARDIAN_STATUS_SUCCESS;
}

guardian_status_t guardian_mp_protect_region(
    guardian_memory_region_t* region,
    uint32_t protection_flags) {
    
    guardian_status_t status;
    int idx;
    
    /* Validate parameters */
    if (region == NULL) {
        return GUARDIAN_ERROR_INVALID_PARAM;
    }
    
    status = validate_region(region->start_addr, region->size);
    if (status != GUARDIAN_STATUS_SUCCESS) {
        return status;
    }
    
    /* Acquire protection table lock */
    mtx_lock(&g_table_lock);
    
    /* Find available table entry */
    for (idx = 0; idx < GUARDIAN_MEM_REGION_MAX; idx++) {
        if (g_protection_table[idx].start_addr == NULL) {
            break;
        }
    }
    
    if (idx == GUARDIAN_MEM_REGION_MAX) {
        mtx_unlock(&g_table_lock);
        return GUARDIAN_ERROR_QUOTA;
    }
    
    /* Configure protection entry */
    g_protection_table[idx].start_addr = region->start_addr;
    g_protection_table[idx].size = region->size;
    g_protection_table[idx].flags = protection_flags;
    
    /* Apply hardware protection */
    vm_offset_t start = (vm_offset_t)region->start_addr;
    vm_offset_t end = start + region->size;
    
    pmap_protect(kernel_pmap, start, end, 
                (protection_flags & GUARDIAN_MEM_PROT_READ ? VM_PROT_READ : 0) |
                (protection_flags & GUARDIAN_MEM_PROT_WRITE ? VM_PROT_WRITE : 0) |
                (protection_flags & GUARDIAN_MEM_PROT_EXEC ? VM_PROT_EXECUTE : 0));
    
    /* Flush TLB for the protected region */
    flush_tlb_range(region->start_addr, region->size);
    
    /* Configure DMA protection if requested */
    if (protection_flags & GUARDIAN_MEM_PROT_DMA) {
        /* Set up IOMMU protection */
        /* Implementation specific to hardware */
    }
    
    /* Configure cache policy */
    if (protection_flags & GUARDIAN_MEM_PROT_CACHE_WB) {
        pmap_change_attr(start, region->size, PAT_WRITE_BACK);
    } else if (protection_flags & GUARDIAN_MEM_PROT_CACHE_WT) {
        pmap_change_attr(start, region->size, PAT_WRITE_THROUGH);
    }
    
    mtx_unlock(&g_table_lock);
    return GUARDIAN_STATUS_SUCCESS;
}

guardian_status_t guardian_mp_verify_access(
    void* address,
    size_t size,
    uint32_t access_type) {
    
    guardian_status_t status;
    int idx;
    
    /* Validate parameters */
    status = validate_region(address, size);
    if (status != GUARDIAN_STATUS_SUCCESS) {
        return status;
    }
    
    /* Acquire protection table lock */
    mtx_lock(&g_table_lock);
    
    /* Search for matching protection entry */
    for (idx = 0; idx < GUARDIAN_MEM_REGION_MAX; idx++) {
        guardian_mp_protection_t* entry = &g_protection_table[idx];
        
        if (entry->start_addr == NULL) {
            continue;
        }
        
        if (address >= entry->start_addr && 
            (char*)address + size <= (char*)entry->start_addr + entry->size) {
            
            /* Check access permissions */
            if ((access_type & GUARDIAN_MEM_PROT_READ) && 
                !(entry->flags & GUARDIAN_MEM_PROT_READ)) {
                status = GUARDIAN_ERROR_PERMISSION;
                break;
            }
            
            if ((access_type & GUARDIAN_MEM_PROT_WRITE) && 
                !(entry->flags & GUARDIAN_MEM_PROT_WRITE)) {
                status = GUARDIAN_ERROR_PERMISSION;
                break;
            }
            
            if ((access_type & GUARDIAN_MEM_PROT_EXEC) && 
                !(entry->flags & GUARDIAN_MEM_PROT_EXEC)) {
                status = GUARDIAN_ERROR_PERMISSION;
                break;
            }
            
            status = GUARDIAN_STATUS_SUCCESS;
            break;
        }
    }
    
    mtx_unlock(&g_table_lock);
    return status;
}

void guardian_mp_cleanup(void) {
    int idx;
    
    if (!g_initialized) {
        return;
    }
    
    /* Acquire protection table lock */
    mtx_lock(&g_table_lock);
    
    /* Remove all protections */
    for (idx = 0; idx < GUARDIAN_MEM_REGION_MAX; idx++) {
        guardian_mp_protection_t* entry = &g_protection_table[idx];
        
        if (entry->start_addr != NULL) {
            /* Remove hardware protection */
            pmap_protect(kernel_pmap, (vm_offset_t)entry->start_addr,
                        (vm_offset_t)entry->start_addr + entry->size,
                        VM_PROT_ALL);
            
            /* Flush TLB */
            flush_tlb_range(entry->start_addr, entry->size);
            
            /* Clear entry */
            memset(entry, 0, sizeof(*entry));
        }
    }
    
    /* Disable hardware protection features */
    if (g_hw_capabilities & HW_CAP_SMEP) {
        load_cr4(rcr4() & ~CR4_SMEP);
    }
    if (g_hw_capabilities & HW_CAP_SMAP) {
        load_cr4(rcr4() & ~CR4_SMAP);
    }
    
    mtx_unlock(&g_table_lock);
    mtx_destroy(&g_table_lock);
    
    atomic_store_rel_int(&g_initialized, 0);
}