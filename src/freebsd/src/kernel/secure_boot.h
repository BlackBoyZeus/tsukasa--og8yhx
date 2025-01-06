/*
 * Guardian System - Secure Boot Implementation
 * 
 * Provides secure boot chain verification, measurement, and attestation using TPM 2.0
 * hardware with enhanced security features including timing attack mitigations and
 * entropy validation.
 *
 * Version: 1.0.0
 * FreeBSD Version: 13.0
 */

#ifndef _GUARDIAN_SECURE_BOOT_H_
#define _GUARDIAN_SECURE_BOOT_H_

#include <sys/types.h>      /* FreeBSD 13.0 - System type definitions */
#include <sys/bootchain.h>  /* FreeBSD 13.0 - Boot chain interface */
#include "../include/guardian_types.h"
#include "../include/guardian_errors.h"
#include "tpm_driver.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Secure Boot Version and Constants
 */
#define GUARDIAN_SECURE_BOOT_VERSION    0x0100  /* Version 1.0 */
#define GUARDIAN_MAX_MEASUREMENTS       32      /* Maximum measurements in chain */

/*
 * PCR Bank Assignments
 */
#define GUARDIAN_PCR_BOOT_CHAIN        0       /* Boot chain measurements */
#define GUARDIAN_PCR_KERNEL            1       /* Kernel measurements */
#define GUARDIAN_PCR_MODULES           2       /* Kernel module measurements */
#define GUARDIAN_PCR_CONFIG            3       /* Configuration measurements */
#define GUARDIAN_PCR_RUNTIME           4       /* Runtime measurements */

/*
 * Enhanced measurement structure with timing and sequence validation
 */
typedef struct guardian_measurement {
    uint32_t pcr_index;                        /* PCR bank index */
    uint8_t hash[SHA512_DIGEST_LENGTH];        /* SHA-512 measurement hash */
    uint8_t signature[TPM_MAX_KEY_SIZE/8];     /* RSA-4096 signature */
    uint64_t timestamp;                        /* Measurement timestamp */
    uint64_t sequence_number;                  /* Anti-replay sequence number */
} guardian_measurement_t;

/*
 * Measurement log for audit and verification
 */
typedef struct guardian_measurement_log {
    uint32_t count;                            /* Number of measurements */
    uint64_t last_update;                      /* Last update timestamp */
    uint8_t log_hash[SHA512_DIGEST_LENGTH];    /* Log integrity hash */
    guardian_measurement_t entries[GUARDIAN_MAX_MEASUREMENTS];  /* Log entries */
} guardian_measurement_log_t;

/*
 * Enhanced boot chain structure with measurement log
 */
typedef struct guardian_boot_chain {
    uint16_t version;                          /* Boot chain version */
    uint32_t num_measurements;                 /* Number of measurements */
    guardian_measurement_t measurements[GUARDIAN_MAX_MEASUREMENTS];  /* Measurements */
    guardian_measurement_log_t measurement_log; /* Measurement audit log */
} guardian_boot_chain_t;

/*
 * Function Declarations
 */

/*
 * Initialize secure boot subsystem
 * 
 * Validates TPM 2.0 presence, initializes PCR banks, and sets up
 * timing attack mitigations.
 *
 * Returns:
 *   guardian_status_t - Status code indicating success or detailed error
 */
guardian_status_t guardian_secure_boot_init(void);

/*
 * Verify boot chain integrity
 *
 * Performs comprehensive verification of boot chain measurements with
 * timing attack protection and entropy validation.
 *
 * Parameters:
 *   boot_chain - Pointer to boot chain structure containing measurements
 *
 * Returns:
 *   guardian_status_t - Status code with detailed verification results
 */
guardian_status_t guardian_verify_boot_chain(
    const guardian_boot_chain_t* boot_chain);

/*
 * Internal helper macros for secure operations
 */
#define SECURE_BOOT_VALIDATE_VERSION(ver) \
    ((ver) == GUARDIAN_SECURE_BOOT_VERSION)

#define SECURE_BOOT_VALIDATE_PCR(idx) \
    ((idx) >= GUARDIAN_PCR_BOOT_CHAIN && (idx) <= GUARDIAN_PCR_RUNTIME)

#define SECURE_BOOT_VALIDATE_MEASUREMENT_COUNT(count) \
    ((count) > 0 && (count) <= GUARDIAN_MAX_MEASUREMENTS)

/*
 * Error codes specific to secure boot operations
 */
#define GUARDIAN_ERROR_SECURE_BOOT_BASE    (GUARDIAN_ERROR_SECURITY | 0x2000)
#define GUARDIAN_ERROR_INVALID_VERSION     (GUARDIAN_ERROR_SECURE_BOOT_BASE | 0x01)
#define GUARDIAN_ERROR_INVALID_PCR         (GUARDIAN_ERROR_SECURE_BOOT_BASE | 0x02)
#define GUARDIAN_ERROR_INVALID_MEASUREMENT (GUARDIAN_ERROR_SECURE_BOOT_BASE | 0x03)
#define GUARDIAN_ERROR_SEQUENCE_INVALID    (GUARDIAN_ERROR_SECURE_BOOT_BASE | 0x04)
#define GUARDIAN_ERROR_SIGNATURE_INVALID   (GUARDIAN_ERROR_SECURE_BOOT_BASE | 0x05)
#define GUARDIAN_ERROR_ENTROPY_LOW         (GUARDIAN_ERROR_SECURE_BOOT_BASE | 0x06)
#define GUARDIAN_ERROR_TIMING_VIOLATION    (GUARDIAN_ERROR_SECURE_BOOT_BASE | 0x07)

#ifdef __cplusplus
}
#endif

#endif /* _GUARDIAN_SECURE_BOOT_H_ */