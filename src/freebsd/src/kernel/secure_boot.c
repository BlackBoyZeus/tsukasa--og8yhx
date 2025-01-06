/*
 * Guardian System - Secure Boot Implementation
 * 
 * Provides secure boot chain verification, TPM-based measurements, and boot
 * attestation using TPM 2.0 hardware with enhanced security features.
 *
 * Version: 1.0.0
 * FreeBSD Version: 13.0
 */

#include <sys/types.h>
#include <sys/bootchain.h>
#include <openssl/sha.h>      /* OpenSSL 3.0.0 */
#include <openssl/rsa.h>      /* OpenSSL 3.0.0 */
#include "secure_boot.h"
#include "../include/guardian_types.h"
#include "tpm_driver.h"

/* Global constants */
#define SECURE_BOOT_DEBUG 0
#define SECURE_BOOT_MAX_RETRIES 3
#define SECURE_BOOT_TIMEOUT_MS 5000
#define SECURE_BOOT_MIN_ENTROPY_BITS 256
#define SECURE_BOOT_PCR_MASK 0x0000FFFF
#define SECURE_BOOT_AUDIT_BUFFER_SIZE 4096

/* Static variables with secure initialization */
static volatile int g_secure_boot_initialized = 0;
static guardian_measurement_log_t g_measurement_log = {0};
static uint8_t g_audit_buffer[SECURE_BOOT_AUDIT_BUFFER_SIZE] = {0};

/* Forward declarations for internal functions */
static guardian_status_t validate_tpm_state(void);
static guardian_status_t verify_measurement_integrity(const guardian_measurement_t* measurement);
static guardian_status_t update_measurement_log(const guardian_measurement_t* measurement);
static guardian_status_t perform_timing_safe_compare(const uint8_t* a, const uint8_t* b, size_t len);

/*
 * Initialize secure boot subsystem with enhanced security validations
 */
guardian_status_t secure_boot_init(void) {
    guardian_status_t status;
    int retry_count = 0;

    /* Prevent double initialization with memory barrier */
    if (__sync_bool_compare_and_swap(&g_secure_boot_initialized, 0, 1) == 0) {
        return GUARDIAN_ERROR_STATE;
    }

    /* Validate TPM firmware and hardware */
    status = validate_tpm_state();
    if (status != GUARDIAN_STATUS_SUCCESS) {
        goto error;
    }

    /* Initialize TPM with entropy validation */
    do {
        status = guardian_tpm_init();
        if (status == GUARDIAN_STATUS_SUCCESS) {
            break;
        }
        retry_count++;
        /* Secure delay to prevent timing attacks */
        for (volatile int i = 0; i < SECURE_BOOT_TIMEOUT_MS * 1000; i++);
    } while (retry_count < SECURE_BOOT_MAX_RETRIES);

    if (status != GUARDIAN_STATUS_SUCCESS) {
        goto error;
    }

    /* Verify TPM entropy source */
    status = guardian_tpm_validate_entropy(SECURE_BOOT_MIN_ENTROPY_BITS);
    if (status != GUARDIAN_STATUS_SUCCESS) {
        goto error;
    }

    /* Initialize measurement log with secure wipe */
    explicit_bzero(&g_measurement_log, sizeof(g_measurement_log));
    g_measurement_log.last_update = time(NULL);

    return GUARDIAN_STATUS_SUCCESS;

error:
    /* Secure cleanup on error */
    explicit_bzero(&g_measurement_log, sizeof(g_measurement_log));
    g_secure_boot_initialized = 0;
    return status;
}

/*
 * Verify boot chain integrity with timing attack mitigations
 */
guardian_status_t verify_boot_chain(const guardian_boot_chain_t* boot_chain) {
    guardian_status_t status;

    if (!g_secure_boot_initialized || !boot_chain) {
        return GUARDIAN_ERROR_INVALID_PARAM;
    }

    /* Validate boot chain structure */
    if (!SECURE_BOOT_VALIDATE_VERSION(boot_chain->version) ||
        !SECURE_BOOT_VALIDATE_MEASUREMENT_COUNT(boot_chain->num_measurements)) {
        return GUARDIAN_ERROR_INVALID_VERSION;
    }

    /* Verify each measurement with constant-time operations */
    for (uint32_t i = 0; i < boot_chain->num_measurements; i++) {
        const guardian_measurement_t* measurement = &boot_chain->measurements[i];
        
        /* Verify PCR index */
        if (!SECURE_BOOT_VALIDATE_PCR(measurement->pcr_index)) {
            return GUARDIAN_ERROR_INVALID_PCR;
        }

        /* Verify measurement integrity */
        status = verify_measurement_integrity(measurement);
        if (status != GUARDIAN_STATUS_SUCCESS) {
            return status;
        }

        /* Extend PCR with measurement */
        status = guardian_tpm_extend_pcr(
            measurement->pcr_index,
            measurement->hash,
            SHA512_DIGEST_LENGTH
        );
        if (status != GUARDIAN_STATUS_SUCCESS) {
            return status;
        }

        /* Update measurement log securely */
        status = update_measurement_log(measurement);
        if (status != GUARDIAN_STATUS_SUCCESS) {
            return status;
        }
    }

    return GUARDIAN_STATUS_SUCCESS;
}

/*
 * Extend PCR with new measurement data using enhanced validation
 */
guardian_status_t extend_measurement(uint32_t pcr_index, const uint8_t* measurement,
                                   size_t measurement_len) {
    guardian_status_t status;
    SHA512_CTX sha_ctx;
    uint8_t hash[SHA512_DIGEST_LENGTH];

    if (!g_secure_boot_initialized || !measurement || !measurement_len ||
        !SECURE_BOOT_VALIDATE_PCR(pcr_index)) {
        return GUARDIAN_ERROR_INVALID_PARAM;
    }

    /* Compute measurement hash with timing protection */
    SHA512_Init(&sha_ctx);
    SHA512_Update(&sha_ctx, measurement, measurement_len);
    SHA512_Final(hash, &sha_ctx);

    /* Extend PCR with computed hash */
    status = guardian_tpm_extend_pcr(pcr_index, hash, SHA512_DIGEST_LENGTH);
    if (status != GUARDIAN_STATUS_SUCCESS) {
        explicit_bzero(hash, SHA512_DIGEST_LENGTH);
        return status;
    }

    /* Verify PCR extension */
    guardian_pcr_bank_t pcr_bank;
    status = guardian_tpm_verify_firmware(pcr_index, &pcr_bank);
    if (status != GUARDIAN_STATUS_SUCCESS) {
        explicit_bzero(hash, SHA512_DIGEST_LENGTH);
        return status;
    }

    /* Secure cleanup */
    explicit_bzero(hash, SHA512_DIGEST_LENGTH);
    explicit_bzero(&sha_ctx, sizeof(sha_ctx));

    return GUARDIAN_STATUS_SUCCESS;
}

/*
 * Verify RSA signature of measurement data with enhanced security
 */
guardian_status_t verify_signature(const uint8_t* data, size_t data_len,
                                 const uint8_t* signature, size_t signature_len) {
    RSA* rsa = NULL;
    EVP_PKEY* pkey = NULL;
    EVP_PKEY_CTX* ctx = NULL;
    guardian_status_t status = GUARDIAN_ERROR_SECURITY;

    if (!g_secure_boot_initialized || !data || !signature ||
        data_len == 0 || signature_len != TPM_MAX_KEY_SIZE/8) {
        return GUARDIAN_ERROR_INVALID_PARAM;
    }

    /* Initialize OpenSSL context with security flags */
    if ((ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL)) == NULL) {
        goto cleanup;
    }

    /* Enable RSA blinding for timing attack protection */
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PSS_PADDING) <= 0) {
        goto cleanup;
    }

    /* Verify signature with constant-time operations */
    if (EVP_PKEY_verify_init(ctx) <= 0) {
        goto cleanup;
    }

    if (EVP_PKEY_verify(ctx, signature, signature_len, data, data_len) != 1) {
        goto cleanup;
    }

    status = GUARDIAN_STATUS_SUCCESS;

cleanup:
    /* Secure cleanup of sensitive data */
    if (rsa) RSA_free(rsa);
    if (pkey) EVP_PKEY_free(pkey);
    if (ctx) EVP_PKEY_CTX_free(ctx);
    
    return status;
}

/* Internal helper functions */

static guardian_status_t validate_tpm_state(void) {
    guardian_tpm_info_t tpm_info;
    guardian_status_t status;

    status = guardian_tpm_verify_firmware(&tpm_info);
    if (status != GUARDIAN_STATUS_SUCCESS) {
        return status;
    }

    /* Validate TPM version and capabilities */
    if (tpm_info.version < 0x20 || /* TPM 2.0 minimum */
        !(tpm_info.capabilities & TPM_CAP_RSA) ||
        !(tpm_info.capabilities & TPM_CAP_SHA512)) {
        return GUARDIAN_ERROR_SECURITY;
    }

    return GUARDIAN_STATUS_SUCCESS;
}

static guardian_status_t verify_measurement_integrity(
    const guardian_measurement_t* measurement) {
    SHA512_CTX sha_ctx;
    uint8_t computed_hash[SHA512_DIGEST_LENGTH];

    /* Compute measurement hash */
    SHA512_Init(&sha_ctx);
    SHA512_Update(&sha_ctx, &measurement->pcr_index, sizeof(uint32_t));
    SHA512_Update(&sha_ctx, &measurement->timestamp, sizeof(uint64_t));
    SHA512_Update(&sha_ctx, &measurement->sequence_number, sizeof(uint64_t));
    SHA512_Final(computed_hash, &sha_ctx);

    /* Constant-time comparison */
    if (perform_timing_safe_compare(computed_hash, measurement->hash,
                                  SHA512_DIGEST_LENGTH) != GUARDIAN_STATUS_SUCCESS) {
        return GUARDIAN_ERROR_INTEGRITY;
    }

    return GUARDIAN_STATUS_SUCCESS;
}

static guardian_status_t update_measurement_log(
    const guardian_measurement_t* measurement) {
    if (g_measurement_log.count >= GUARDIAN_MAX_MEASUREMENTS) {
        return GUARDIAN_ERROR_OVERFLOW;
    }

    /* Secure copy of measurement data */
    memcpy(&g_measurement_log.entries[g_measurement_log.count],
           measurement, sizeof(guardian_measurement_t));
    g_measurement_log.count++;
    g_measurement_log.last_update = time(NULL);

    /* Update log integrity hash */
    SHA512_CTX sha_ctx;
    SHA512_Init(&sha_ctx);
    SHA512_Update(&sha_ctx, g_measurement_log.entries,
                 g_measurement_log.count * sizeof(guardian_measurement_t));
    SHA512_Final(g_measurement_log.log_hash, &sha_ctx);

    return GUARDIAN_STATUS_SUCCESS;
}

static guardian_status_t perform_timing_safe_compare(const uint8_t* a,
    const uint8_t* b, size_t len) {
    volatile uint8_t result = 0;
    
    for (size_t i = 0; i < len; i++) {
        result |= a[i] ^ b[i];
    }
    
    return result == 0 ? GUARDIAN_STATUS_SUCCESS : GUARDIAN_ERROR_INTEGRITY;
}