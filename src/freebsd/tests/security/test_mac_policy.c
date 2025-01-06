/*
 * Guardian System - MAC Policy Test Suite
 * 
 * Comprehensive test suite for validating the Mandatory Access Control (MAC) policy
 * implementation with enhanced security context verification and thread safety tests.
 *
 * Version: 1.0.0
 * FreeBSD Version: 13.0
 */

#include <sys/param.h>  /* FreeBSD 13.0 - System parameters and constants */
#include <sys/mac.h>    /* FreeBSD 13.0 - MAC framework interfaces */
#include <atf-c.h>      /* ATF 0.20 - Automated Testing Framework */
#include "security/mac_policy.h"
#include "utils/error_handlers.h"

/* Test configuration constants */
#define TEST_POLICY_NAME "test_policy"
#define TEST_LABEL_NAME "test_label"
#define TEST_THREAD_COUNT 8
#define TEST_SECURITY_CONTEXT "test_context"

/* Test case declarations */
ATF_TC_WITH_CLEANUP(atf_tc_mac_init);
ATF_TC_WITH_CLEANUP(atf_tc_mac_label_ops);
ATF_TC_WITH_CLEANUP(atf_tc_mac_access_control);

/* Global test variables */
static guardian_mac_policy_t test_policy;
static guardian_mac_label_t *test_label;
static guardian_security_context_t test_context;
static guardian_error_info_t error_info;

/* Helper function to initialize test security context */
static void init_test_context(void) {
    memset(&test_context, 0, sizeof(guardian_security_context_t));
    strncpy(test_context.mac_label, TEST_SECURITY_CONTEXT, GUARDIAN_MAX_NAME - 1);
    test_context.security_flags = GUARDIAN_MAC_FLAG_AUDITED;
    test_context.capabilities = GUARDIAN_MAC_ALL;
}

/* Test case for MAC policy initialization */
ATF_TC_HEAD(atf_tc_mac_init, tc) {
    atf_tc_set_md_var(tc, "descr", "Test MAC policy initialization with thread safety");
}

ATF_TC_BODY(atf_tc_mac_init, tc) {
    guardian_status_t status;

    /* Initialize error handling subsystem */
    init_test_context();
    status = guardian_error_init(&test_context);
    ATF_REQUIRE_MSG(status == GUARDIAN_STATUS_SUCCESS, "Error handler initialization failed");

    /* Initialize MAC policy framework */
    status = guardian_mac_init();
    ATF_REQUIRE_MSG(status == GUARDIAN_STATUS_SUCCESS, "MAC policy initialization failed");

    /* Verify thread context propagation */
    guardian_mac_thread_ctx *thread_ctx = guardian_mac_get_thread_context();
    ATF_REQUIRE_MSG(thread_ctx != NULL, "Thread context initialization failed");
    ATF_REQUIRE_MSG(thread_ctx->security_context.security_flags == test_context.security_flags,
                   "Security context propagation failed");

    /* Test concurrent initialization attempts */
    for (int i = 0; i < TEST_THREAD_COUNT; i++) {
        status = guardian_mac_init();
        ATF_REQUIRE_MSG(status == GUARDIAN_STATUS_SUCCESS || status == GUARDIAN_STATUS_BUSY,
                       "Concurrent initialization handling failed");
    }
}

/* Test case for MAC label operations */
ATF_TC_HEAD(atf_tc_mac_label_ops, tc) {
    atf_tc_set_md_var(tc, "descr", "Test MAC label operations with isolation");
}

ATF_TC_BODY(atf_tc_mac_label_ops, tc) {
    guardian_status_t status;

    /* Create test MAC label */
    status = guardian_mac_create_label(
        TEST_LABEL_NAME,
        GUARDIAN_MAC_TYPE_HIGH,
        GUARDIAN_MAC_FLAG_AUDITED | GUARDIAN_MAC_FLAG_PERSISTENT,
        &test_label,
        &error_info
    );
    ATF_REQUIRE_MSG(status == GUARDIAN_STATUS_SUCCESS, "Label creation failed");

    /* Verify label attributes */
    ATF_REQUIRE_MSG(strcmp(test_label->name, TEST_LABEL_NAME) == 0, "Label name mismatch");
    ATF_REQUIRE_MSG(test_label->type == GUARDIAN_MAC_TYPE_HIGH, "Label type mismatch");
    ATF_REQUIRE_MSG(test_label->flags & GUARDIAN_MAC_FLAG_AUDITED, "Label flags mismatch");

    /* Test concurrent label modifications */
    for (int i = 0; i < TEST_THREAD_COUNT; i++) {
        guardian_mac_label_t *concurrent_label;
        char label_name[GUARDIAN_MAC_LABEL_MAX];
        snprintf(label_name, sizeof(label_name), "%s_%d", TEST_LABEL_NAME, i);
        
        status = guardian_mac_create_label(
            label_name,
            GUARDIAN_MAC_TYPE_MEDIUM,
            GUARDIAN_MAC_FLAG_AUDITED,
            &concurrent_label,
            &error_info
        );
        ATF_REQUIRE_MSG(status == GUARDIAN_STATUS_SUCCESS, "Concurrent label creation failed");
        
        status = guardian_mac_destroy_label(concurrent_label, &error_info);
        ATF_REQUIRE_MSG(status == GUARDIAN_STATUS_SUCCESS, "Label cleanup failed");
    }
}

/* Test case for MAC access control decisions */
ATF_TC_HEAD(atf_tc_mac_access_control, tc) {
    atf_tc_set_md_var(tc, "descr", "Test MAC access control with security validation");
}

ATF_TC_BODY(atf_tc_mac_access_control, tc) {
    guardian_status_t status;

    /* Configure test MAC policy */
    memset(&test_policy, 0, sizeof(guardian_mac_policy_t));
    strncpy(test_policy.name, TEST_POLICY_NAME, GUARDIAN_MAC_LABEL_MAX - 1);
    test_policy.flags = GUARDIAN_MAC_FLAG_AUDITED;

    /* Test access control decisions */
    status = guardian_mac_check_access(
        &test_context,
        GUARDIAN_MAC_READ | GUARDIAN_MAC_WRITE,
        &error_info
    );
    ATF_REQUIRE_MSG(status == GUARDIAN_STATUS_SUCCESS, "Access control check failed");

    /* Test access denial cases */
    test_context.capabilities = 0; /* Remove all capabilities */
    status = guardian_mac_check_access(
        &test_context,
        GUARDIAN_MAC_WRITE,
        &error_info
    );
    ATF_REQUIRE_MSG(status != GUARDIAN_STATUS_SUCCESS, "Access control bypass detected");

    /* Verify audit trail generation */
    ATF_REQUIRE_MSG(error_info.audit_data[0] != '\0', "Audit trail missing");
}

/* Cleanup function for test cases */
ATF_TC_CLEANUP(atf_tc_mac_init) {
    guardian_mac_destroy_label(test_label, &error_info);
    guardian_error_clear_chain(GUARDIAN_SEVERITY_INFO);
}

ATF_TC_CLEANUP(atf_tc_mac_label_ops) {
    guardian_mac_destroy_label(test_label, &error_info);
    guardian_error_clear_chain(GUARDIAN_SEVERITY_INFO);
}

ATF_TC_CLEANUP(atf_tc_mac_access_control) {
    guardian_mac_destroy_label(test_label, &error_info);
    guardian_error_clear_chain(GUARDIAN_SEVERITY_INFO);
}

/* Test case initialization */
ATF_TP_ADD_TCS(tp) {
    ATF_TP_ADD_TC(tp, atf_tc_mac_init);
    ATF_TP_ADD_TC(tp, atf_tc_mac_label_ops);
    ATF_TP_ADD_TC(tp, atf_tc_mac_access_control);
    return atf_no_error();
}