/*
 * Guardian System - Capsicum Security Test Suite
 * 
 * Comprehensive test suite for validating the enhanced Capsicum capability mode
 * implementation with gaming console specific security features.
 *
 * Version: 1.0.0
 * FreeBSD Version: 13.0
 */

#include <atf-c.h>          /* Version: 0.20 - FreeBSD Automated Testing Framework */
#include <sys/capability.h>  /* Version: 13.0 - FreeBSD Capsicum capability mode interfaces */
#include <sys/param.h>      /* Version: 13.0 - System parameters and limits */
#include "capsicum_wrapper.h"
#include "guardian_types.h"

/* Test configuration constants */
#define TEST_TIMEOUT 30
#define HW_CAPS_MASK 0xFFFFFFFF
#define TEST_AUDIT_BUFFER_SIZE 1024
#define TEST_FILE_PATH "/tmp/capsicum_test"

/* Test case declarations */
ATF_TC_WITH_CLEANUP(capability_mode);
ATF_TC_WITH_CLEANUP(hw_capabilities);
ATF_TC_WITH_CLEANUP(performance_impact);

/* Global test context */
static guardian_security_context_t g_test_context;
static char g_audit_buffer[TEST_AUDIT_BUFFER_SIZE];

/*
 * Test case setup for capability mode validation
 */
ATF_TC_HEAD(capability_mode, tc)
{
    atf_tc_set_md_var(tc, "timeout", TEST_TIMEOUT);
    atf_tc_set_md_var(tc, "descr", 
        "Validates basic capability mode functionality with security context");
}

/*
 * Main test body for capability mode functionality
 */
ATF_TC_BODY(capability_mode, tc)
{
    guardian_status_t status;
    bool is_sandboxed;
    
    /* Initialize security context */
    memset(&g_test_context, 0, sizeof(guardian_security_context_t));
    g_test_context.capabilities = GUARDIAN_CAP_DEFAULT_MASK;
    g_test_context.security_flags = HW_CAPS_MASK;
    
    /* Test initial state */
    is_sandboxed = guardian_cap_sandboxed();
    ATF_CHECK(!is_sandboxed);
    
    /* Initialize Capsicum wrapper */
    status = guardian_cap_init(&g_test_context);
    ATF_CHECK_EQ(status, GUARDIAN_STATUS_SUCCESS);
    
    /* Enter capability mode */
    status = guardian_cap_enter();
    ATF_CHECK_EQ(status, GUARDIAN_STATUS_SUCCESS);
    
    /* Verify capability mode state */
    is_sandboxed = guardian_cap_sandboxed();
    ATF_CHECK(is_sandboxed);
    
    /* Test file descriptor capability restrictions */
    int fd = open(TEST_FILE_PATH, O_RDWR | O_CREAT, 0600);
    ATF_REQUIRE(fd >= 0);
    
    status = guardian_cap_rights_limit(fd, 
        GUARDIAN_CAP_READ | GUARDIAN_CAP_WRITE,
        &g_test_context);
    ATF_CHECK_EQ(status, GUARDIAN_STATUS_SUCCESS);
    
    /* Verify hardware capability restrictions */
    status = guardian_cap_hw_rights_limit(
        GUARDIAN_CAP_GPU_ACCESS | GUARDIAN_CAP_DMA_CONTROL,
        &g_test_context);
    ATF_CHECK_EQ(status, GUARDIAN_STATUS_SUCCESS);
    
    /* Attempt privileged operations (should fail) */
    status = guardian_cap_rights_limit(fd, 
        GUARDIAN_CAP_EXEC | GUARDIAN_CAP_MMAP,
        &g_test_context);
    ATF_CHECK_EQ(status, GUARDIAN_STATUS_ERROR);
    
    /* Verify audit logging */
    status = guardian_cap_audit_log(g_audit_buffer, TEST_AUDIT_BUFFER_SIZE);
    ATF_CHECK_EQ(status, GUARDIAN_STATUS_SUCCESS);
    ATF_CHECK(strlen(g_audit_buffer) > 0);
    
    close(fd);
}

/*
 * Test case cleanup for capability mode
 */
ATF_TC_CLEANUP(capability_mode, tc)
{
    unlink(TEST_FILE_PATH);
}

/*
 * Test case setup for hardware capabilities
 */
ATF_TC_HEAD(hw_capabilities, tc)
{
    atf_tc_set_md_var(tc, "timeout", TEST_TIMEOUT);
    atf_tc_set_md_var(tc, "descr", 
        "Validates hardware-specific capability restrictions");
}

/*
 * Main test body for hardware capabilities
 */
ATF_TC_BODY(hw_capabilities, tc)
{
    guardian_status_t status;
    guardian_hw_caps_t hw_caps;
    
    /* Initialize hardware capabilities */
    hw_caps = GUARDIAN_CAP_GPU_ACCESS | GUARDIAN_CAP_DMA_CONTROL | 
              GUARDIAN_CAP_SECURE_MEM;
    
    /* Test hardware capability restrictions */
    status = test_hw_capabilities(hw_caps);
    ATF_CHECK_EQ(status, GUARDIAN_STATUS_SUCCESS);
    
    /* Verify GPU access controls */
    status = guardian_cap_hw_rights_limit(GUARDIAN_CAP_GPU_ACCESS, 
                                        &g_test_context);
    ATF_CHECK_EQ(status, GUARDIAN_STATUS_SUCCESS);
    
    /* Test DMA restrictions */
    status = guardian_cap_hw_rights_limit(GUARDIAN_CAP_DMA_CONTROL, 
                                        &g_test_context);
    ATF_CHECK_EQ(status, GUARDIAN_STATUS_SUCCESS);
    
    /* Verify secure memory access */
    status = guardian_cap_hw_rights_limit(GUARDIAN_CAP_SECURE_MEM, 
                                        &g_test_context);
    ATF_CHECK_EQ(status, GUARDIAN_STATUS_SUCCESS);
}

/*
 * Test case cleanup for hardware capabilities
 */
ATF_TC_CLEANUP(hw_capabilities, tc)
{
    /* Reset hardware capabilities */
    guardian_cap_hw_rights_limit(0, &g_test_context);
}

/*
 * Test case setup for performance impact
 */
ATF_TC_HEAD(performance_impact, tc)
{
    atf_tc_set_md_var(tc, "timeout", TEST_TIMEOUT);
    atf_tc_set_md_var(tc, "descr", 
        "Measures performance impact of capability mode transitions");
}

/*
 * Main test body for performance impact
 */
ATF_TC_BODY(performance_impact, tc)
{
    struct timespec start, end;
    guardian_status_t status;
    
    /* Measure capability mode entry time */
    clock_gettime(CLOCK_MONOTONIC, &start);
    status = guardian_cap_enter();
    clock_gettime(CLOCK_MONOTONIC, &end);
    
    ATF_CHECK_EQ(status, GUARDIAN_STATUS_SUCCESS);
    
    /* Verify performance requirements */
    long elapsed_ns = (end.tv_sec - start.tv_sec) * 1000000000 +
                     (end.tv_nsec - start.tv_nsec);
    ATF_CHECK(elapsed_ns < 1000000); /* Less than 1ms */
    
    /* Test rapid capability rights modifications */
    int fd = open(TEST_FILE_PATH, O_RDWR | O_CREAT, 0600);
    ATF_REQUIRE(fd >= 0);
    
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (int i = 0; i < 1000; i++) {
        status = guardian_cap_rights_limit(fd, 
            GUARDIAN_CAP_READ | GUARDIAN_CAP_WRITE,
            &g_test_context);
        ATF_CHECK_EQ(status, GUARDIAN_STATUS_SUCCESS);
    }
    clock_gettime(CLOCK_MONOTONIC, &end);
    
    elapsed_ns = (end.tv_sec - start.tv_sec) * 1000000000 +
                (end.tv_nsec - start.tv_nsec);
    ATF_CHECK(elapsed_ns / 1000 < 100000); /* Less than 100μs per operation */
    
    close(fd);
}

/*
 * Test case cleanup for performance impact
 */
ATF_TC_CLEANUP(performance_impact, tc)
{
    unlink(TEST_FILE_PATH);
}

/*
 * Test program initialization
 */
ATF_TP_ADD_TCS(tp)
{
    ATF_TP_ADD_TC(tp, capability_mode);
    ATF_TP_ADD_TC(tp, hw_capabilities);
    ATF_TP_ADD_TC(tp, performance_impact);
    
    return atf_no_error();
}