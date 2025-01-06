/*
 * Guardian System - Memory Manager Test Suite
 * 
 * Comprehensive test suite for the Guardian system's memory management subsystem,
 * validating memory safety, performance, and hardware integration requirements.
 *
 * Version: 1.0.0
 * FreeBSD Version: 13.0
 */

#include <sys/types.h>      /* FreeBSD 13.0 - System type definitions */
#include <sys/param.h>      /* FreeBSD 13.0 - System parameters and constants */
#include <sys/module.h>     /* FreeBSD 13.0 - Kernel module testing utilities */
#include <sys/kernel.h>     /* FreeBSD 13.0 - Kernel functions and utilities */
#include "../../src/hardware/memory_manager.h"
#include "../../src/utils/error_handlers.h"

/* Test configuration constants */
#define TEST_MEMORY_SIZE    4096    /* Standard test allocation size */
#define TEST_ITERATIONS     1000    /* Number of test iterations */
#define TEST_TIMEOUT_MS     5000    /* Test timeout in milliseconds */

/* Test statistics structure */
typedef struct test_stats {
    uint64_t total_allocations;
    uint64_t total_frees;
    uint64_t failed_allocations;
    uint64_t protection_violations;
    uint64_t total_cycles;
    uint64_t max_latency;
    uint64_t min_latency;
} test_stats_t;

/* Global test statistics */
static test_stats_t g_test_stats;

/* Forward declarations of helper functions */
static void init_test_stats(void);
static void update_latency_stats(uint64_t latency);
static guardian_status_t verify_memory_contents(void* ptr, size_t size);
static uint64_t get_cycle_count(void);

/*
 * Test memory manager initialization
 */
TEST_CASE(test_memory_init)
{
    guardian_status_t status;
    guardian_security_context_t sec_ctx = {0};
    guardian_memory_stats_t initial_stats;

    /* Initialize error handling with security context */
    status = guardian_error_init(&sec_ctx);
    if (status != GUARDIAN_STATUS_SUCCESS) {
        return -1;
    }

    /* Initialize memory manager */
    status = guardian_memory_init();
    if (status != GUARDIAN_STATUS_SUCCESS) {
        guardian_error_log(&GUARDIAN_ERROR_INFO(status, "Memory manager initialization failed"), 
                         GUARDIAN_SEVERITY_ERROR, NULL);
        return -1;
    }

    /* Verify initial memory statistics */
    status = guardian_memory_get_stats(&initial_stats);
    if (status != GUARDIAN_STATUS_SUCCESS || initial_stats.used != 0) {
        guardian_error_log(&GUARDIAN_ERROR_INFO(status, "Invalid initial memory stats"), 
                         GUARDIAN_SEVERITY_ERROR, NULL);
        return -1;
    }

    return 0;
}

/*
 * Test memory allocation and deallocation
 */
TEST_CASE(test_memory_alloc_free)
{
    void* ptr_array[TEST_ITERATIONS];
    guardian_status_t status;
    uint32_t test_flags = GUARDIAN_MEM_READ | GUARDIAN_MEM_WRITE | GUARDIAN_MEM_SECURE;
    
    init_test_stats();

    /* Test multiple allocations with different sizes */
    for (int i = 0; i < TEST_ITERATIONS; i++) {
        uint64_t start_cycle = get_cycle_count();
        
        /* Allocate memory with security flags */
        ptr_array[i] = guardian_memory_alloc(TEST_MEMORY_SIZE + (i % 512), test_flags);
        
        uint64_t latency = get_cycle_count() - start_cycle;
        update_latency_stats(latency);

        if (ptr_array[i] == NULL) {
            g_test_stats.failed_allocations++;
            guardian_error_log(&GUARDIAN_ERROR_INFO(GUARDIAN_ERROR_MEMORY, "Allocation failed"), 
                             GUARDIAN_SEVERITY_ERROR, NULL);
            continue;
        }

        g_test_stats.total_allocations++;

        /* Verify memory alignment */
        if (((uintptr_t)ptr_array[i] % GUARDIAN_MEMORY_ALIGNMENT) != 0) {
            guardian_error_log(&GUARDIAN_ERROR_INFO(GUARDIAN_ERROR_MEMORY, "Invalid memory alignment"), 
                             GUARDIAN_SEVERITY_ERROR, NULL);
            return -1;
        }

        /* Verify memory contents */
        status = verify_memory_contents(ptr_array[i], TEST_MEMORY_SIZE + (i % 512));
        if (status != GUARDIAN_STATUS_SUCCESS) {
            return -1;
        }
    }

    /* Free all allocated memory */
    for (int i = 0; i < TEST_ITERATIONS; i++) {
        if (ptr_array[i] != NULL) {
            status = guardian_memory_free(ptr_array[i]);
            if (status != GUARDIAN_STATUS_SUCCESS) {
                guardian_error_log(&GUARDIAN_ERROR_INFO(status, "Memory free failed"), 
                                 GUARDIAN_SEVERITY_ERROR, NULL);
                return -1;
            }
            g_test_stats.total_frees++;
        }
    }

    /* Verify all memory was freed */
    guardian_memory_stats_t final_stats;
    status = guardian_memory_get_stats(&final_stats);
    if (status != GUARDIAN_STATUS_SUCCESS || final_stats.used != 0) {
        guardian_error_log(&GUARDIAN_ERROR_INFO(status, "Memory leak detected"), 
                         GUARDIAN_SEVERITY_ERROR, NULL);
        return -1;
    }

    return 0;
}

/*
 * Test memory protection mechanisms
 */
TEST_CASE(test_memory_protection)
{
    guardian_status_t status;
    void* test_ptr = guardian_memory_alloc(TEST_MEMORY_SIZE, GUARDIAN_MEM_READ | GUARDIAN_MEM_WRITE);
    
    if (test_ptr == NULL) {
        guardian_error_log(&GUARDIAN_ERROR_INFO(GUARDIAN_ERROR_MEMORY, "Protection test allocation failed"), 
                         GUARDIAN_SEVERITY_ERROR, NULL);
        return -1;
    }

    /* Test changing protection flags */
    status = guardian_memory_protect(test_ptr, TEST_MEMORY_SIZE, GUARDIAN_MEM_READ);
    if (status != GUARDIAN_STATUS_SUCCESS) {
        guardian_error_log(&GUARDIAN_ERROR_INFO(status, "Failed to change memory protection"), 
                         GUARDIAN_SEVERITY_ERROR, NULL);
        guardian_memory_free(test_ptr);
        return -1;
    }

    /* Verify protection flags */
    guardian_memory_region_t region;
    status = guardian_memory_query(test_ptr, &region);
    if (status != GUARDIAN_STATUS_SUCCESS || (region.flags & GUARDIAN_MEM_WRITE)) {
        guardian_error_log(&GUARDIAN_ERROR_INFO(status, "Protection flags verification failed"), 
                         GUARDIAN_SEVERITY_ERROR, NULL);
        guardian_memory_free(test_ptr);
        return -1;
    }

    guardian_memory_free(test_ptr);
    return 0;
}

/*
 * Stress test memory management
 */
TEST_CASE(test_memory_stress)
{
    guardian_status_t status;
    void* ptr_array[TEST_ITERATIONS];
    guardian_memory_stats_t initial_stats, final_stats;
    
    /* Get initial memory stats */
    status = guardian_memory_get_stats(&initial_stats);
    if (status != GUARDIAN_STATUS_SUCCESS) {
        return -1;
    }

    /* Perform rapid allocations and deallocations */
    for (int i = 0; i < TEST_ITERATIONS; i++) {
        /* Allocate with varying sizes */
        size_t size = TEST_MEMORY_SIZE * ((i % 4) + 1);
        ptr_array[i] = guardian_memory_alloc(size, GUARDIAN_MEM_READ | GUARDIAN_MEM_WRITE);
        
        if (ptr_array[i] == NULL) {
            g_test_stats.failed_allocations++;
            continue;
        }

        /* Free every other allocation immediately */
        if (i % 2 == 0) {
            status = guardian_memory_free(ptr_array[i]);
            if (status != GUARDIAN_STATUS_SUCCESS) {
                return -1;
            }
            ptr_array[i] = NULL;
        }
    }

    /* Free remaining allocations */
    for (int i = 0; i < TEST_ITERATIONS; i++) {
        if (ptr_array[i] != NULL) {
            status = guardian_memory_free(ptr_array[i]);
            if (status != GUARDIAN_STATUS_SUCCESS) {
                return -1;
            }
        }
    }

    /* Verify final memory state */
    status = guardian_memory_get_stats(&final_stats);
    if (status != GUARDIAN_STATUS_SUCCESS || final_stats.used != initial_stats.used) {
        guardian_error_log(&GUARDIAN_ERROR_INFO(status, "Memory leak detected in stress test"), 
                         GUARDIAN_SEVERITY_ERROR, NULL);
        return -1;
    }

    return 0;
}

/*
 * Test memory error handling
 */
TEST_CASE(test_memory_error_handling)
{
    guardian_status_t status;
    
    /* Test invalid allocation size */
    void* ptr = guardian_memory_alloc(0, GUARDIAN_MEM_READ);
    if (ptr != NULL) {
        guardian_error_log(&GUARDIAN_ERROR_INFO(GUARDIAN_ERROR_INVALID_PARAM, "Zero size allocation not caught"), 
                         GUARDIAN_SEVERITY_ERROR, NULL);
        guardian_memory_free(ptr);
        return -1;
    }

    /* Test invalid protection flags */
    ptr = guardian_memory_alloc(TEST_MEMORY_SIZE, GUARDIAN_MEM_READ);
    if (ptr == NULL) {
        return -1;
    }

    status = guardian_memory_protect(ptr, TEST_MEMORY_SIZE, 0xFFFFFFFF);
    if (status == GUARDIAN_STATUS_SUCCESS) {
        guardian_error_log(&GUARDIAN_ERROR_INFO(GUARDIAN_ERROR_INVALID_PARAM, "Invalid protection flags not caught"), 
                         GUARDIAN_SEVERITY_ERROR, NULL);
        guardian_memory_free(ptr);
        return -1;
    }

    guardian_memory_free(ptr);
    return 0;
}

/* Helper function implementations */
static void init_test_stats(void)
{
    memset(&g_test_stats, 0, sizeof(test_stats_t));
    g_test_stats.min_latency = UINT64_MAX;
}

static void update_latency_stats(uint64_t latency)
{
    g_test_stats.total_cycles += latency;
    if (latency > g_test_stats.max_latency) {
        g_test_stats.max_latency = latency;
    }
    if (latency < g_test_stats.min_latency) {
        g_test_stats.min_latency = latency;
    }
}

static guardian_status_t verify_memory_contents(void* ptr, size_t size)
{
    if (ptr == NULL || size == 0) {
        return GUARDIAN_ERROR_INVALID_PARAM;
    }

    /* Write pattern */
    uint8_t* bytes = (uint8_t*)ptr;
    for (size_t i = 0; i < size; i++) {
        bytes[i] = (uint8_t)(i & 0xFF);
    }

    /* Verify pattern */
    for (size_t i = 0; i < size; i++) {
        if (bytes[i] != (uint8_t)(i & 0xFF)) {
            return GUARDIAN_ERROR_CORRUPTION;
        }
    }

    return GUARDIAN_STATUS_SUCCESS;
}

static uint64_t get_cycle_count(void)
{
    uint64_t cycles;
    __asm__ volatile("rdtsc" : "=A" (cycles));
    return cycles;
}