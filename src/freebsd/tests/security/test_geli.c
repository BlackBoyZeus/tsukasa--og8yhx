/*
 * Guardian System - GELI Manager Test Suite
 * 
 * Comprehensive test suite for GELI encryption functionality with enhanced
 * security validations for gaming console environments.
 *
 * Version: 1.0.0
 * FreeBSD Version: 13.0
 * ATF Version: 0.20
 */

#include <sys/types.h>      /* FreeBSD 13.0 - System type definitions */
#include <sys/param.h>      /* FreeBSD 13.0 - System parameters */
#include <atf-c.h>         /* ATF 0.20 - Automated Testing Framework */
#include "geli_manager.h"   /* v1.0.0 - GELI encryption management */
#include "guardian_errors.h" /* v1.0.0 - Error handling utilities */

/* Test device path for GELI operations */
#define TEST_DEVICE_PATH "/dev/md0"

/* Test key data (32 bytes for AES-256) */
static const uint8_t TEST_KEY_DATA[GELI_KEY_LENGTH] = {
    0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
    0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00
};

/* Test case setup and cleanup macros */
ATF_TC_WITH_CLEANUP(test_geli_init_provider);
ATF_TC_WITH_CLEANUP(test_geli_attach_provider);
ATF_TC_WITH_CLEANUP(test_geli_detach_provider);

/* Test case head declarations */
ATF_TC_HEAD(test_geli_init_provider, tc)
{
    atf_tc_set_md_var(tc, "descr", 
        "Test GELI provider initialization with gaming-optimized parameters");
}

ATF_TC_HEAD(test_geli_attach_provider, tc)
{
    atf_tc_set_md_var(tc, "descr", 
        "Test GELI provider attachment with security context validation");
}

ATF_TC_HEAD(test_geli_detach_provider, tc)
{
    atf_tc_set_md_var(tc, "descr", 
        "Test GELI provider detachment with secure cleanup");
}

/* Test case implementations */
ATF_TC_BODY(test_geli_init_provider, tc)
{
    guardian_error_info_t error_info = {0};
    guardian_status_t status;

    /* Test initialization with valid parameters */
    status = geli_init_provider(
        TEST_DEVICE_PATH,
        TEST_KEY_DATA,
        GELI_KEY_LENGTH,
        GELI_SECURE_MEMORY_FLAG | GELI_PROVIDER_TPM_SEALED,
        &error_info
    );
    ATF_CHECK_MSG(status == GUARDIAN_STATUS_SUCCESS,
        "GELI initialization failed: %s", error_info.message);

    /* Verify provider info after initialization */
    geli_provider_info_t provider_info = {0};
    status = geli_get_provider_info(TEST_DEVICE_PATH, &provider_info, &error_info);
    ATF_CHECK_MSG(status == GUARDIAN_STATUS_SUCCESS,
        "Failed to get provider info: %s", error_info.message);

    /* Validate provider configuration */
    ATF_CHECK_EQ(provider_info.sector_size, GELI_SECTOR_SIZE);
    ATF_CHECK_EQ(provider_info.key_length, GELI_KEY_LENGTH);
    ATF_CHECK(provider_info.security_flags & GELI_PROVIDER_VALID);
    ATF_CHECK(provider_info.security_flags & GELI_PROVIDER_TPM_SEALED);

    /* Test initialization with invalid key length */
    status = geli_init_provider(
        TEST_DEVICE_PATH,
        TEST_KEY_DATA,
        GELI_KEY_LENGTH - 1,  /* Invalid key length */
        GELI_SECURE_MEMORY_FLAG,
        &error_info
    );
    ATF_CHECK_MSG(status == GUARDIAN_STATUS_ERROR,
        "GELI initialization should fail with invalid key length");
}

ATF_TC_BODY(test_geli_attach_provider, tc)
{
    guardian_error_info_t error_info = {0};
    guardian_status_t status;

    /* Initialize provider first */
    status = geli_init_provider(
        TEST_DEVICE_PATH,
        TEST_KEY_DATA,
        GELI_KEY_LENGTH,
        GELI_SECURE_MEMORY_FLAG | GELI_PROVIDER_TPM_SEALED,
        &error_info
    );
    ATF_REQUIRE_MSG(status == GUARDIAN_STATUS_SUCCESS,
        "GELI initialization failed: %s", error_info.message);

    /* Test attachment with valid parameters */
    status = geli_attach_provider(
        TEST_DEVICE_PATH,
        TEST_KEY_DATA,
        GELI_KEY_LENGTH,
        GELI_SECURE_MEMORY_FLAG,
        &error_info
    );
    ATF_CHECK_MSG(status == GUARDIAN_STATUS_SUCCESS,
        "GELI attachment failed: %s", error_info.message);

    /* Verify provider status after attachment */
    geli_provider_info_t provider_info = {0};
    status = geli_get_provider_info(TEST_DEVICE_PATH, &provider_info, &error_info);
    ATF_CHECK_MSG(status == GUARDIAN_STATUS_SUCCESS,
        "Failed to get provider info: %s", error_info.message);
    ATF_CHECK(provider_info.provider_status & GELI_PROVIDER_VALID);

    /* Test attachment with invalid key */
    uint8_t invalid_key[GELI_KEY_LENGTH] = {0};
    status = geli_attach_provider(
        TEST_DEVICE_PATH,
        invalid_key,
        GELI_KEY_LENGTH,
        GELI_SECURE_MEMORY_FLAG,
        &error_info
    );
    ATF_CHECK_MSG(status == GUARDIAN_STATUS_ERROR,
        "GELI attachment should fail with invalid key");
}

ATF_TC_BODY(test_geli_detach_provider, tc)
{
    guardian_error_info_t error_info = {0};
    guardian_status_t status;

    /* Initialize and attach provider first */
    status = geli_init_provider(
        TEST_DEVICE_PATH,
        TEST_KEY_DATA,
        GELI_KEY_LENGTH,
        GELI_SECURE_MEMORY_FLAG | GELI_PROVIDER_TPM_SEALED,
        &error_info
    );
    ATF_REQUIRE_MSG(status == GUARDIAN_STATUS_SUCCESS,
        "GELI initialization failed: %s", error_info.message);

    status = geli_attach_provider(
        TEST_DEVICE_PATH,
        TEST_KEY_DATA,
        GELI_KEY_LENGTH,
        GELI_SECURE_MEMORY_FLAG,
        &error_info
    );
    ATF_REQUIRE_MSG(status == GUARDIAN_STATUS_SUCCESS,
        "GELI attachment failed: %s", error_info.message);

    /* Test detachment */
    status = geli_detach_provider(
        TEST_DEVICE_PATH,
        GELI_SECURE_MEMORY_FLAG,
        &error_info
    );
    ATF_CHECK_MSG(status == GUARDIAN_STATUS_SUCCESS,
        "GELI detachment failed: %s", error_info.message);

    /* Verify provider status after detachment */
    geli_provider_info_t provider_info = {0};
    status = geli_get_provider_info(TEST_DEVICE_PATH, &provider_info, &error_info);
    ATF_CHECK_MSG(status == GUARDIAN_STATUS_SUCCESS,
        "Failed to get provider info: %s", error_info.message);
    ATF_CHECK(!(provider_info.provider_status & GELI_PROVIDER_VALID));
}

/* Cleanup handlers */
ATF_TC_CLEANUP(test_geli_init_provider, tc)
{
    guardian_error_info_t error_info = {0};
    geli_detach_provider(TEST_DEVICE_PATH, GELI_SECURE_MEMORY_FLAG, &error_info);
}

ATF_TC_CLEANUP(test_geli_attach_provider, tc)
{
    guardian_error_info_t error_info = {0};
    geli_detach_provider(TEST_DEVICE_PATH, GELI_SECURE_MEMORY_FLAG, &error_info);
}

ATF_TC_CLEANUP(test_geli_detach_provider, tc)
{
    /* No cleanup needed as provider is already detached */
}

/* Test program entry point */
ATF_TP_ADD_TCS(tp)
{
    ATF_TP_ADD_TC(tp, test_geli_init_provider);
    ATF_TP_ADD_TC(tp, test_geli_attach_provider);
    ATF_TP_ADD_TC(tp, test_geli_detach_provider);

    return atf_no_error();
}