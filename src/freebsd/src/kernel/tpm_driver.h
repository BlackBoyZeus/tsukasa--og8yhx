/*
 * Guardian System - TPM Driver Interface
 * 
 * Provides secure boot, key management, and hardware-based security operations
 * for the gaming console platform using TPM 2.0 with enhanced security features.
 *
 * Version: 1.0.0
 * FreeBSD Version: 13.0
 */

#ifndef _GUARDIAN_TPM_DRIVER_H_
#define _GUARDIAN_TPM_DRIVER_H_

#include <sys/types.h>      /* FreeBSD 13.0 - System type definitions */
#include <sys/tpm.h>        /* FreeBSD 13.0 - TPM device interface */
#include <crypto/sha2.h>    /* FreeBSD 13.0 - SHA-512 support */
#include "guardian_types.h"
#include "guardian_errors.h"
#include "guardian_ioctl.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * TPM Configuration Constants
 */
#define TPM_MAX_PCR_BANKS      24    /* Maximum number of PCR measurement banks */
#define TPM_MAX_KEY_SIZE       4096  /* Maximum RSA key size for secure boot */
#define TPM_MAX_SEALED_DATA    1024  /* Maximum size of sealed data block */

/*
 * TPM Device Information Structure
 */
typedef struct guardian_tpm_info {
    uint32_t version;           /* TPM specification version */
    uint32_t manufacturer;      /* TPM manufacturer ID */
    uint64_t capabilities;      /* TPM capability flags */
    uint32_t security_level;    /* TPM security certification level */
    uint32_t firmware_version;  /* TPM firmware version */
} guardian_tpm_info_t;

/*
 * PCR Measurement Bank Structure
 */
typedef struct guardian_pcr_bank {
    uint32_t index;                           /* PCR bank index */
    uint8_t value[SHA512_DIGEST_LENGTH];      /* Current PCR value */
    uint64_t last_extended;                   /* Last extension timestamp */
    uint8_t integrity_hash[SHA512_DIGEST_LENGTH]; /* PCR integrity verification */
} guardian_pcr_bank_t;

/*
 * TPM Key Management Structure
 */
typedef struct guardian_tpm_key {
    uint32_t handle;                          /* Key handle */
    uint32_t type;                            /* Key type and algorithm */
    uint32_t size;                            /* Key size in bits */
    uint8_t policy_digest[SHA512_DIGEST_LENGTH]; /* Key usage policy */
    uint64_t creation_time;                   /* Key creation timestamp */
} guardian_tpm_key_t;

/*
 * TPM Operation Status Codes
 */
#define TPM_STATUS_SUCCESS           GUARDIAN_STATUS_SUCCESS
#define TPM_STATUS_DEVICE_ERROR     (GUARDIAN_ERROR_IO | 0x1000)
#define TPM_STATUS_INTEGRITY_ERROR  (GUARDIAN_ERROR_INTEGRITY | 0x1000)
#define TPM_STATUS_POLICY_ERROR     (GUARDIAN_ERROR_SECURITY | 0x1000)

/*
 * Function Declarations
 */

/*
 * Initialize the TPM device with enhanced security checks
 *
 * Returns:
 *   guardian_status_t - Status of TPM initialization
 */
guardian_status_t tpm_init(void);

/*
 * Extend a PCR measurement bank using SHA-512
 *
 * Parameters:
 *   pcr_index      - Index of PCR bank to extend
 *   measurement    - Measurement data to extend
 *   measurement_size - Size of measurement data
 *
 * Returns:
 *   guardian_status_t - Status of PCR extension operation
 */
guardian_status_t tpm_extend_pcr(
    uint32_t pcr_index,
    const uint8_t* measurement,
    size_t measurement_size
);

/*
 * Seal sensitive data using TPM
 *
 * Parameters:
 *   data        - Data to seal
 *   data_size   - Size of input data
 *   sealed_data - Buffer for sealed data
 *   sealed_size - Size of sealed data buffer/resulting size
 *
 * Returns:
 *   guardian_status_t - Status of sealing operation
 */
guardian_status_t tpm_seal_data(
    const uint8_t* data,
    size_t data_size,
    uint8_t* sealed_data,
    size_t* sealed_size
);

/*
 * TPM IOCTL Commands
 */
#define TPM_IOC_GET_INFO    _IOR(GUARDIAN_IOC_MAGIC, 20, guardian_tpm_info_t)
#define TPM_IOC_READ_PCR    _IOWR(GUARDIAN_IOC_MAGIC, 21, guardian_pcr_bank_t)
#define TPM_IOC_CREATE_KEY  _IOWR(GUARDIAN_IOC_MAGIC, 22, guardian_tpm_key_t)

#ifdef __cplusplus
}
#endif

#endif /* _GUARDIAN_TPM_DRIVER_H_ */