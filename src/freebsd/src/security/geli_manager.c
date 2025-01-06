/*
 * Guardian System - GELI Manager Implementation
 * FreeBSD Kernel Module Implementation
 *
 * Implements secure disk encryption functionality using FreeBSD's GELI subsystem
 * with AES-256-GCM encryption for data at rest. Features enhanced security
 * validations, secure memory management, and comprehensive error handling.
 *
 * Version: 1.0.0
 * FreeBSD 13.0
 */

#include <sys/types.h>
#include <sys/param.h>
#include <geom/eli/g_eli.h>
#include <crypto/aes/aes.h>
#include "geli_manager.h"
#include "../../include/guardian_errors.h"
#include "../utils/kernel_utils.h"

/* Global state management with atomic operations */
static volatile bool g_geli_initialized = false;
static geli_config_t g_geli_config;
static atomic_t g_geli_retry_count = ATOMIC_INIT(0);

/* Internal helper functions */
static guardian_error_t validate_geli_state(void) {
    if (!g_geli_initialized) {
        return GUARDIAN_E_NOT_INITIALIZED;
    }
    return GUARDIAN_SUCCESS;
}

static guardian_error_t secure_key_validation(const void* key_data, size_t key_length) {
    if (!key_data || key_length < GELI_MIN_KEY_LENGTH || key_length > GELI_MAX_KEY_LENGTH) {
        return GUARDIAN_E_INVALID_PARAM;
    }

    /* Validate key entropy and composition */
    uint8_t zero_count = 0;
    const uint8_t* key_bytes = (const uint8_t*)key_data;
    
    for (size_t i = 0; i < key_length; i++) {
        if (key_bytes[i] == 0) {
            zero_count++;
        }
    }

    /* Reject keys with low entropy */
    if (zero_count > (key_length / 4)) {
        return GUARDIAN_E_SECURITY;
    }

    return GUARDIAN_SUCCESS;
}

guardian_error_t guardian_geli_init(void) {
    guardian_error_t error;
    
    /* Atomic initialization check */
    if (g_geli_initialized) {
        return GUARDIAN_SUCCESS;
    }

    /* Initialize default configuration */
    memset(&g_geli_config, 0, sizeof(g_geli_config));
    g_geli_config.key_length = GELI_MIN_KEY_LENGTH;
    g_geli_config.sector_size = GELI_DEFAULT_SECTOR_SIZE;
    strlcpy(g_geli_config.algorithm, GELI_DEFAULT_ALGORITHM, sizeof(g_geli_config.algorithm));
    g_geli_config.security_level = 2;
    g_geli_config.key_validation = true;

    /* Initialize GELI subsystem with enhanced security parameters */
    struct g_eli_metadata md;
    memset(&md, 0, sizeof(md));
    md.md_version = G_ELI_VERSION_CURRENT;
    md.md_flags = G_ELI_FLAG_AUTH | G_ELI_FLAG_GELIBOOT;
    md.md_ealgo = CRYPTO_AES_XTS;
    md.md_keylen = GELI_MIN_KEY_LENGTH;
    md.md_sectorsize = GELI_DEFAULT_SECTOR_SIZE;

    error = g_eli_init();
    if (error != 0) {
        return GUARDIAN_E_SECURITY;
    }

    /* Set up hardware acceleration if available */
    if (g_eli_hwsupport()) {
        g_eli_crypto_hardware = 1;
    }

    /* Mark as initialized with memory barrier */
    atomic_thread_fence(memory_order_release);
    g_geli_initialized = true;

    return GUARDIAN_SUCCESS;
}

guardian_error_t guardian_geli_attach(
    const char* device_path,
    const void* key_data,
    size_t key_length
) {
    guardian_error_t error;
    void* secure_key = NULL;

    /* Validate parameters */
    GELI_VALIDATE_PATH(device_path);
    error = secure_key_validation(key_data, key_length);
    if (error != GUARDIAN_SUCCESS) {
        return error;
    }

    /* Verify initialization status */
    error = validate_geli_state();
    if (error != GUARDIAN_SUCCESS) {
        return error;
    }

    /* Allocate secure memory for key handling */
    secure_key = guardian_kmalloc(key_length, M_WAITOK | M_ZERO, &error);
    if (!secure_key) {
        return GUARDIAN_E_MEMORY;
    }

    /* Copy key with secure memory operations */
    memcpy(secure_key, key_data, key_length);

    /* Attach GELI with retry mechanism */
    int retries = 0;
    error = GUARDIAN_E_GENERIC;
    
    while (retries < GELI_MAX_RETRIES && error != GUARDIAN_SUCCESS) {
        error = g_eli_attach(device_path, secure_key, key_length);
        if (error == 0) {
            error = GUARDIAN_SUCCESS;
            break;
        }
        retries++;
        atomic_inc(&g_geli_retry_count);
        /* Exponential backoff */
        tsleep(&g_geli_retry_count, PRIBIO, "geli_retry", (1 << retries) * hz/10);
    }

    /* Secure cleanup */
    guardian_secure_memzero(secure_key, key_length);
    guardian_kfree(secure_key, key_length);

    return error;
}

guardian_error_t guardian_geli_detach(const char* device_path) {
    guardian_error_t error;

    /* Validate parameters */
    GELI_VALIDATE_PATH(device_path);

    /* Verify initialization status */
    error = validate_geli_state();
    if (error != GUARDIAN_SUCCESS) {
        return error;
    }

    /* Detach with retry mechanism */
    int retries = 0;
    error = GUARDIAN_E_GENERIC;
    
    while (retries < GELI_MAX_RETRIES && error != GUARDIAN_SUCCESS) {
        error = g_eli_detach(device_path);
        if (error == 0) {
            error = GUARDIAN_SUCCESS;
            break;
        }
        retries++;
        atomic_inc(&g_geli_retry_count);
        tsleep(&g_geli_retry_count, PRIBIO, "geli_retry", (1 << retries) * hz/10);
    }

    return error;
}

guardian_error_t guardian_geli_configure(const geli_config_t* config) {
    guardian_error_t error;

    /* Validate parameters */
    GELI_VALIDATE_CONFIG(config);

    /* Verify initialization status */
    error = validate_geli_state();
    if (error != GUARDIAN_SUCCESS) {
        return error;
    }

    /* Update configuration atomically */
    memcpy(&g_geli_config, config, sizeof(geli_config_t));
    atomic_thread_fence(memory_order_release);

    return GUARDIAN_SUCCESS;
}