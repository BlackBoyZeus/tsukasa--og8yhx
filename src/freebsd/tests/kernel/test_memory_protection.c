/*
 * Guardian System - Memory Protection Test Suite
 * 
 * This file implements comprehensive unit tests for the Guardian system's
 * memory protection subsystem in the FreeBSD kernel module.
 *
 * Version: 1.0.0
 * FreeBSD Version: 13.0
 */

#include <sys/types.h>      /* FreeBSD 13.0 */
#include <sys/param.h>      /* FreeBSD 13.0 */
#include <sys/module.h>     /* FreeBSD 13.0 */
#include <sys/kernel.h>     /* FreeBSD 13.0 */
#include <sys/systm.h>      /* FreeBSD 13.0 */
#include "memory_protection.h"
#include "guardian_types.h"

/* Test configuration constants */
#define TEST_MEMORY_SIZE        4096
#define TEST_ALIGNMENT         PAGE_SIZE
#define TEST_DMA_BUFFER_SIZE   8192
#define TEST_CACHE_LINE_SIZE   64

/* Test suite forward declarations */
static int test_mp_init(void);
static int test_mp_dma_protection(void);
static int test_mp_cache_coherency(void);

/* Helper functions */
static void *allocate_aligned_memory(size_t size, size_t alignment);
static void free_aligned_memory(void *ptr);
static int verify_memory_protection(void *addr, size_t size, uint32_t expected_flags);
static int test_memory_access(void *addr, size_t size, uint32_t access_type);

/* Test suite definition */
struct kunit_test_suite memory_protection_test_suite = {
    .name = "memory_protection",
    .init = NULL,
    .fini = NULL,
    .tests = {
        KUNIT_TEST_CASE(test_mp_init),
        KUNIT_TEST_CASE(test_mp_dma_protection),
        KUNIT_TEST_CASE(test_mp_cache_coherency),
        {}
    }
};

/*
 * Test memory protection initialization
 */
static int
test_mp_init(void)
{
    guardian_status_t status;
    guardian_mp_config_t config = {
        .max_regions = GUARDIAN_MEM_REGION_MAX,
        .default_flags = GUARDIAN_MEM_PROT_READ | GUARDIAN_MEM_PROT_WRITE,
        .default_dma = {
            .dma_mask = 0xFFFFFFFFULL,
            .dma_flags = GUARDIAN_MEM_PROT_DMA
        },
        .default_cache = {
            .cache_policy = GUARDIAN_MEM_PROT_CACHE_WB,
            .coherency_mask = 0xFF,
            .prefetch_flags = 0
        }
    };

    /* Test initialization */
    status = guardian_mp_init(&config);
    if (status != GUARDIAN_STATUS_SUCCESS) {
        printf("Memory protection initialization failed: %d\n", status);
        return -1;
    }

    /* Verify protection tables setup */
    guardian_memory_stats_t stats;
    status = guardian_mp_get_stats(&stats);
    if (status != GUARDIAN_STATUS_SUCCESS || stats.total == 0) {
        printf("Failed to verify protection tables\n");
        return -1;
    }

    return 0;
}

/*
 * Test DMA memory protection features
 */
static int
test_mp_dma_protection(void)
{
    guardian_status_t status;
    void *dma_buffer;
    guardian_mp_protection_t protection = {0};

    /* Allocate DMA-capable memory */
    dma_buffer = allocate_aligned_memory(TEST_DMA_BUFFER_SIZE, TEST_ALIGNMENT);
    if (dma_buffer == NULL) {
        printf("Failed to allocate DMA buffer\n");
        return -1;
    }

    /* Configure DMA protection */
    protection.start_addr = dma_buffer;
    protection.size = TEST_DMA_BUFFER_SIZE;
    protection.flags = GUARDIAN_MEM_PROT_READ | GUARDIAN_MEM_PROT_WRITE | GUARDIAN_MEM_PROT_DMA;
    protection.dma_protection.dma_mask = 0xFFFFFFFFULL;
    protection.dma_protection.dma_flags = GUARDIAN_MEM_PROT_DMA;

    /* Apply protection */
    status = guardian_mp_protect_region((guardian_memory_region_t *)&protection, 
                                      protection.flags, NULL);
    if (status != GUARDIAN_STATUS_SUCCESS) {
        printf("Failed to apply DMA protection\n");
        free_aligned_memory(dma_buffer);
        return -1;
    }

    /* Test DMA access restrictions */
    if (test_memory_access(dma_buffer, TEST_DMA_BUFFER_SIZE, 
                          GUARDIAN_MEM_PROT_DMA) != 0) {
        printf("DMA protection verification failed\n");
        free_aligned_memory(dma_buffer);
        return -1;
    }

    free_aligned_memory(dma_buffer);
    return 0;
}

/*
 * Test cache coherency protection
 */
static int
test_mp_cache_coherency(void)
{
    guardian_status_t status;
    void *cache_buffer;
    guardian_mp_protection_t protection = {0};

    /* Allocate cache-aligned memory */
    cache_buffer = allocate_aligned_memory(TEST_MEMORY_SIZE, TEST_CACHE_LINE_SIZE);
    if (cache_buffer == NULL) {
        printf("Failed to allocate cache-aligned buffer\n");
        return -1;
    }

    /* Configure cache protection */
    protection.start_addr = cache_buffer;
    protection.size = TEST_MEMORY_SIZE;
    protection.flags = GUARDIAN_MEM_PROT_READ | GUARDIAN_MEM_PROT_WRITE | 
                      GUARDIAN_MEM_PROT_CACHE_WB | GUARDIAN_MEM_PROT_NO_SIDE_CHANNEL;
    protection.cache_config.cache_policy = GUARDIAN_MEM_PROT_CACHE_WB;
    protection.cache_config.coherency_mask = 0xFF;
    protection.cache_config.prefetch_flags = 0;

    /* Apply protection */
    status = guardian_mp_protect_region((guardian_memory_region_t *)&protection,
                                      protection.flags, NULL);
    if (status != GUARDIAN_STATUS_SUCCESS) {
        printf("Failed to apply cache protection\n");
        free_aligned_memory(cache_buffer);
        return -1;
    }

    /* Test cache coherency */
    if (test_memory_access(cache_buffer, TEST_MEMORY_SIZE,
                          GUARDIAN_MEM_PROT_CACHE_WB) != 0) {
        printf("Cache coherency verification failed\n");
        free_aligned_memory(cache_buffer);
        return -1;
    }

    free_aligned_memory(cache_buffer);
    return 0;
}

/*
 * Helper function to allocate aligned memory
 */
static void *
allocate_aligned_memory(size_t size, size_t alignment)
{
    void *ptr;
    if (kmem_alloc_contig(&ptr, size, alignment, 0, ~0UL, 
                          PAGE_SIZE, 0, VM_MEMATTR_DEFAULT) != 0) {
        return NULL;
    }
    return ptr;
}

/*
 * Helper function to free aligned memory
 */
static void
free_aligned_memory(void *ptr)
{
    if (ptr != NULL) {
        kmem_free(ptr, TEST_MEMORY_SIZE);
    }
}

/*
 * Helper function to verify memory protection
 */
static int
verify_memory_protection(void *addr, size_t size, uint32_t expected_flags)
{
    guardian_mp_protection_t protection;
    guardian_status_t status;

    status = guardian_mp_query_protection(addr, &protection);
    if (status != GUARDIAN_STATUS_SUCCESS) {
        return -1;
    }

    return (protection.flags & expected_flags) == expected_flags ? 0 : -1;
}

/*
 * Helper function to test memory access
 */
static int
test_memory_access(void *addr, size_t size, uint32_t access_type)
{
    guardian_status_t status;
    
    /* Verify access permissions */
    status = guardian_mp_verify_access(addr, size, access_type);
    if (status != GUARDIAN_STATUS_SUCCESS) {
        return -1;
    }

    /* Verify protection flags */
    return verify_memory_protection(addr, size, access_type);
}

/* Register the test suite */
KUNIT_TEST_SUITE_REGISTER(memory_protection_test_suite);