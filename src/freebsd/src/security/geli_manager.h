/*
 * Guardian System - GELI Manager Interface
 * FreeBSD Kernel Module Implementation
 *
 * This header defines the interface for managing GELI (GEOM Layer Encryption Interface)
 * operations with enhanced security controls, validation, and error handling.
 * Implements AES-256-GCM encryption for data at rest using FreeBSD's GELI subsystem.
 *
 * Version: 1.0.0
 * FreeBSD 13.0
 */

#ifndef _GUARDIAN_GELI_MANAGER_H_
#define _GUARDIAN_GELI_MANAGER_H_

#include <sys/types.h>
#include <geom/eli/g_eli.h>
#include "../../include/guardian_errors.h"
#include "../utils/kernel_utils.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * GELI configuration constants with secure defaults
 */
#define GELI_MAX_KEY_LENGTH      64    /* Maximum key length in bytes */
#define GELI_MIN_KEY_LENGTH      32    /* Minimum key length in bytes */
#define GELI_DEFAULT_SECTOR_SIZE 4096  /* Default sector size in bytes */
#define GELI_DEFAULT_ALGORITHM   "AES-XTS"  /* Default encryption algorithm */
#define GELI_MAX_RETRIES        3     /* Maximum retry attempts */
#define GELI_TIMEOUT_MS         5000  /* Operation timeout in milliseconds */

/*
 * Enhanced GELI configuration structure with security parameters
 */
typedef struct geli_config {
    char algorithm[32];        /* Encryption algorithm identifier */
    size_t key_length;        /* Key length in bytes */
    size_t sector_size;       /* Sector size in bytes */
    uint32_t security_level;  /* Security level (0-3) */
    bool key_validation;      /* Enable key validation */
} geli_config_t;

/*
 * Initializes the GELI encryption subsystem with enhanced security validation
 *
 * @param config: Pointer to GELI configuration structure
 * @return: GUARDIAN_SUCCESS on success, error code otherwise
 */
__must_check
guardian_error_t guardian_geli_init(const geli_config_t* config);

/*
 * Attaches GELI encryption to a storage device with comprehensive security validation
 *
 * @param device_path: Path to the storage device
 * @param key_data: Encryption key data
 * @param key_length: Length of the encryption key
 * @param config: GELI configuration for the attachment
 * @return: GUARDIAN_SUCCESS on success, error code otherwise
 */
__must_check __wur
guardian_error_t guardian_geli_attach(
    const char* device_path,
    const void* key_data,
    size_t key_length,
    const geli_config_t* config
);

/*
 * Detaches GELI encryption from a storage device with secure cleanup
 *
 * @param device_path: Path to the storage device
 * @return: GUARDIAN_SUCCESS on success, error code otherwise
 */
__must_check __wur
guardian_error_t guardian_geli_detach(const char* device_path);

/*
 * Internal validation macros
 */
#define GELI_VALIDATE_CONFIG(config) do { \
    if ((config) == NULL || \
        (config)->key_length < GELI_MIN_KEY_LENGTH || \
        (config)->key_length > GELI_MAX_KEY_LENGTH || \
        (config)->sector_size == 0 || \
        (config)->security_level > 3) { \
        return GUARDIAN_E_INVALID_PARAM; \
    } \
} while (0)

#define GELI_VALIDATE_KEY(key, length) do { \
    if ((key) == NULL || \
        (length) < GELI_MIN_KEY_LENGTH || \
        (length) > GELI_MAX_KEY_LENGTH) { \
        return GUARDIAN_E_INVALID_PARAM; \
    } \
} while (0)

#define GELI_VALIDATE_PATH(path) do { \
    if ((path) == NULL || \
        strlen(path) == 0 || \
        strlen(path) >= MAXPATHLEN) { \
        return GUARDIAN_E_INVALID_PARAM; \
    } \
} while (0)

#ifdef __cplusplus
}
#endif

#endif /* _GUARDIAN_GELI_MANAGER_H_ */