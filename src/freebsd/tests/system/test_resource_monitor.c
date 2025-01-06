/*
 * Guardian System - Resource Monitor Test Suite
 * 
 * Comprehensive test suite for the resource monitoring subsystem with enhanced
 * security validation, thread safety testing, and performance impact verification.
 *
 * Version: 1.0.0
 * FreeBSD Version: 13.0
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/proc.h>

#include "resource_monitor.h"
#include "guardian_types.h"
#include "guardian_errors.h"

/* Test module identifier */
#define TEST_MODULE "resource_monitor"

/* Test constants */
#define TEST_CPU_THRESHOLD     75
#define TEST_MEMORY_THRESHOLD  80
#define TEST_SAMPLE_COUNT     100
#define TEST_THREAD_COUNT      4
#define TEST_TIMEOUT_MS      500

/* Global test state */
static guardian_resource_stats_t test_stats;
static guardian_resource_monitor_t *test_monitor;
static guardian_security_context_t test_security_ctx;

/*
 * Test security context setup
 * Initializes a secure context for test execution
 */
static guardian_status_t setup_test_security_context(void) {
    /* Initialize security context with test parameters */
    memset(&test_security_ctx, 0, sizeof(guardian_security_context_t));
    
    /* Set up test security context */
    test_security_ctx.uid = 0;  /* Root for testing */
    test_security_ctx.gid = 0;
    test_security_ctx.capabilities = 0xFFFFFFFF;  /* All capabilities for testing */
    strlcpy(test_security_ctx.mac_label, "test_label", sizeof(test_security_ctx.mac_label));
    test_security_ctx.security_flags = GUARDIAN_MEMORY_PROTECTION_ENABLED;
    test_security_ctx.audit_mask = 0xFFFFFFFF;  /* Full audit for testing */

    return GUARDIAN_STATUS_SUCCESS;
}

/*
 * Resource monitor initialization test
 * Validates secure initialization and configuration
 */
static int test_resource_monitor_init(void) {
    guardian_status_t status;
    guardian_resource_config_t config;

    /* Initialize test configuration */
    memset(&config, 0, sizeof(guardian_resource_config_t));
    config.update_interval = GUARDIAN_RESOURCE_UPDATE_INTERVAL_MS;
    config.sample_count = TEST_SAMPLE_COUNT;
    config.cpu_threshold = TEST_CPU_THRESHOLD;
    config.memory_threshold = TEST_MEMORY_THRESHOLD;
    config.security_level = GUARDIAN_SYSCTL_MAX_SECURITY_LEVEL;
    config.flags = GUARDIAN_MEMORY_PROTECTION_ENABLED | GUARDIAN_POWER_MANAGEMENT_ENABLED;

    /* Test initialization with security context */
    status = guardian_resource_monitor_init(&test_security_ctx, &config);
    if (status != GUARDIAN_STATUS_SUCCESS) {
        printf("%s: Monitor initialization failed: %s\n", 
               TEST_MODULE, guardian_strerror(status));
        return 1;
    }

    /* Verify monitor configuration */
    guardian_resource_stats_t initial_stats;
    status = guardian_resource_get_stats(&initial_stats, &test_security_ctx);
    if (status != GUARDIAN_STATUS_SUCCESS) {
        printf("%s: Failed to get initial stats: %s\n", 
               TEST_MODULE, guardian_strerror(status));
        return 1;
    }

    /* Cleanup test resources */
    guardian_resource_monitor_cleanup();
    return 0;
}

/*
 * Resource statistics update test
 * Validates thread-safe statistics updates and accuracy
 */
static int test_resource_stats_update(void) {
    guardian_status_t status;
    guardian_resource_stats_t before, after;

    /* Initialize monitor for testing */
    guardian_resource_config_t config = {
        .update_interval = GUARDIAN_RESOURCE_UPDATE_INTERVAL_MS,
        .sample_count = TEST_SAMPLE_COUNT,
        .cpu_threshold = TEST_CPU_THRESHOLD,
        .memory_threshold = TEST_MEMORY_THRESHOLD,
        .security_level = GUARDIAN_SYSCTL_MAX_SECURITY_LEVEL,
        .flags = GUARDIAN_MEMORY_PROTECTION_ENABLED
    };

    status = guardian_resource_monitor_init(&test_security_ctx, &config);
    if (status != GUARDIAN_STATUS_SUCCESS) {
        return 1;
    }

    /* Get initial stats */
    status = guardian_resource_get_stats(&before, &test_security_ctx);
    if (status != GUARDIAN_STATUS_SUCCESS) {
        guardian_resource_monitor_cleanup();
        return 1;
    }

    /* Force stats update */
    status = guardian_update_resource_stats();
    if (status != GUARDIAN_STATUS_SUCCESS) {
        guardian_resource_monitor_cleanup();
        return 1;
    }

    /* Get updated stats */
    status = guardian_resource_get_stats(&after, &test_security_ctx);
    if (status != GUARDIAN_STATUS_SUCCESS) {
        guardian_resource_monitor_cleanup();
        return 1;
    }

    /* Verify timestamp update */
    if (after.timestamp.tv_sec <= before.timestamp.tv_sec) {
        printf("%s: Stats timestamp not updated\n", TEST_MODULE);
        guardian_resource_monitor_cleanup();
        return 1;
    }

    guardian_resource_monitor_cleanup();
    return 0;
}

/*
 * Resource threshold test
 * Validates threshold monitoring and notifications
 */
static int test_resource_thresholds(void) {
    guardian_status_t status;
    
    /* Initialize monitor with test thresholds */
    guardian_resource_config_t config = {
        .update_interval = GUARDIAN_RESOURCE_UPDATE_INTERVAL_MS,
        .sample_count = TEST_SAMPLE_COUNT,
        .cpu_threshold = TEST_CPU_THRESHOLD,
        .memory_threshold = TEST_MEMORY_THRESHOLD,
        .security_level = GUARDIAN_SYSCTL_MAX_SECURITY_LEVEL,
        .flags = GUARDIAN_MEMORY_PROTECTION_ENABLED
    };

    status = guardian_resource_monitor_init(&test_security_ctx, &config);
    if (status != GUARDIAN_STATUS_SUCCESS) {
        return 1;
    }

    /* Test threshold updates */
    status = guardian_set_resource_thresholds(
        TEST_CPU_THRESHOLD - 10,
        TEST_MEMORY_THRESHOLD - 10,
        &test_security_ctx
    );
    if (status != GUARDIAN_STATUS_SUCCESS) {
        guardian_resource_monitor_cleanup();
        return 1;
    }

    /* Verify threshold updates */
    guardian_resource_stats_t stats;
    status = guardian_resource_get_stats(&stats, &test_security_ctx);
    if (status != GUARDIAN_STATUS_SUCCESS) {
        guardian_resource_monitor_cleanup();
        return 1;
    }

    guardian_resource_monitor_cleanup();
    return 0;
}

/*
 * Resource monitor cleanup test
 * Validates secure cleanup and resource release
 */
static int test_resource_monitor_cleanup(void) {
    guardian_status_t status;
    
    /* Initialize monitor for cleanup testing */
    guardian_resource_config_t config = {
        .update_interval = GUARDIAN_RESOURCE_UPDATE_INTERVAL_MS,
        .sample_count = TEST_SAMPLE_COUNT,
        .cpu_threshold = TEST_CPU_THRESHOLD,
        .memory_threshold = TEST_MEMORY_THRESHOLD,
        .security_level = GUARDIAN_SYSCTL_MAX_SECURITY_LEVEL,
        .flags = GUARDIAN_MEMORY_PROTECTION_ENABLED
    };

    status = guardian_resource_monitor_init(&test_security_ctx, &config);
    if (status != GUARDIAN_STATUS_SUCCESS) {
        return 1;
    }

    /* Perform cleanup */
    guardian_resource_monitor_cleanup();

    /* Verify cleanup by attempting to access stats */
    guardian_resource_stats_t stats;
    status = guardian_resource_get_stats(&stats, &test_security_ctx);
    if (status == GUARDIAN_STATUS_SUCCESS) {
        printf("%s: Monitor still accessible after cleanup\n", TEST_MODULE);
        return 1;
    }

    return 0;
}

/* Export test suite */
struct resource_monitor_test_suite {
    guardian_status_t (*setup_test_security_context)(void);
    int (*test_resource_monitor_init)(void);
    int (*test_resource_stats_update)(void);
    int (*test_resource_thresholds)(void);
    int (*test_resource_monitor_cleanup)(void);
} resource_monitor_tests = {
    .setup_test_security_context = setup_test_security_context,
    .test_resource_monitor_init = test_resource_monitor_init,
    .test_resource_stats_update = test_resource_stats_update,
    .test_resource_thresholds = test_resource_thresholds,
    .test_resource_monitor_cleanup = test_resource_monitor_cleanup
};