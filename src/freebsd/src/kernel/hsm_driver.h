/*
 * Guardian System - Hardware Security Module (HSM) Driver Interface
 * 
 * This header defines the interface for the HSM driver in the Guardian system's
 * FreeBSD kernel module, providing secure key management, cryptographic operations,
 * and hardware-backed security features for the gaming console.
 *
 * Version: 1.0.0
 * FreeBSD Version: 13.0
 */

#ifndef _HSM_DRIVER_H_
#define _HSM_DRIVER_H_

#include <sys/types.h>              /* FreeBSD 13.0 - System type definitions */
#include <opencrypto/cryptodev.h>   /* FreeBSD 13.0 - Crypto device interface */
#include <sys/pkcs11.h>            /* FreeBSD 13.0 - PKCS#11 interface */
#include "guardian_types.h"         /* Guardian system type definitions */
#include "guardian_errors.h"        /* Guardian error handling */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * HSM Configuration Constants
 */
#define HSM_MAX_KEY_SIZE        4096    /* Maximum key size in bits */
#define HSM_MAX_SLOTS          16       /* Maximum HSM slot count */
#define HSM_MAX_SESSIONS       32       /* Maximum concurrent sessions */
#define HSM_MAX_OBJECTS        256      /* Maximum stored objects */
#define HSM_MIN_ENTROPY_BITS   256      /* Minimum entropy requirement */
#define HSM_TPM_VERSION        2.0      /* Required TPM version */
#define HSM_AUDIT_BUFFER_SIZE  4096     /* Audit log buffer size */

/*
 * HSM Key Types
 */
typedef enum hsm_key_type {
    HSM_KEY_RSA = 0x0001,    /* RSA key pair */
    HSM_KEY_EC  = 0x0002,    /* Elliptic curve key pair */
    HSM_KEY_AES = 0x0003     /* AES symmetric key */
} hsm_key_type_t;

/*
 * HSM Key Attributes
 */
typedef struct hsm_key_attributes {
    uint32_t key_type;           /* Type of key */
    size_t key_size;            /* Key size in bits */
    uint32_t usage_flags;       /* Key usage flags */
    uint32_t access_flags;      /* Access control flags */
    uint64_t validity_period;   /* Key validity period */
    uint8_t label[32];         /* Key label */
    uint8_t id[32];            /* Key identifier */
} hsm_key_attributes_t;

/*
 * HSM Entropy Source Configuration
 */
typedef struct hsm_entropy_source {
    uint32_t source_type;       /* Type of entropy source */
    uint32_t quality_bits;      /* Entropy quality in bits */
    uint32_t flags;            /* Source configuration flags */
} hsm_entropy_source_t;

/*
 * HSM Capability Information
 */
typedef struct hsm_capability {
    uint32_t hw_version;           /* HSM hardware version */
    uint64_t supported_algorithms; /* Supported crypto algorithms */
    size_t max_key_size;          /* Maximum supported key size */
    uint32_t tpm_features;        /* Available TPM features */
} hsm_capability_t;

/*
 * HSM Operation Flags
 */
#define HSM_FLAG_SECURE_BOOT      0x0001  /* Secure boot enabled */
#define HSM_FLAG_TPM_PRESENT      0x0002  /* TPM available */
#define HSM_FLAG_FIPS_MODE        0x0004  /* FIPS 140-3 mode */
#define HSM_FLAG_AUDIT_ENABLED    0x0008  /* Audit logging enabled */
#define HSM_FLAG_KEY_BACKUP       0x0010  /* Key backup enabled */

/*
 * Function Declarations
 */

/*
 * Initialize HSM driver with hardware capability detection
 */
__must_check guardian_status_t
hsm_init(guardian_device_info_t* device_info, uint32_t flags,
         hsm_capability_t* capabilities);

/*
 * Generate cryptographic key with enhanced security validations
 */
__must_check guardian_status_t
hsm_generate_key(uint32_t key_type, size_t key_size, uint32_t* key_handle,
                 hsm_key_attributes_t* attributes,
                 hsm_entropy_source_t entropy_source);

/*
 * Import external key with security validation
 */
__must_check guardian_status_t
hsm_import_key(const uint8_t* key_data, size_t key_length,
               hsm_key_attributes_t* attributes, uint32_t* key_handle);

/*
 * Export key with security controls
 */
__must_check guardian_status_t
hsm_export_key(uint32_t key_handle, uint8_t* key_data,
               size_t* key_length, uint32_t flags);

/*
 * Perform cryptographic operation
 */
__must_check guardian_status_t
hsm_crypto_operation(uint32_t key_handle, uint32_t operation,
                    const uint8_t* input, size_t input_length,
                    uint8_t* output, size_t* output_length);

/*
 * Get HSM status and statistics
 */
__must_check guardian_status_t
hsm_get_status(uint32_t* status, hsm_capability_t* capabilities);

/*
 * Perform HSM self-test
 */
__must_check guardian_status_t
hsm_self_test(uint32_t test_flags, uint32_t* test_results);

/*
 * Configure HSM audit logging
 */
__must_check guardian_status_t
hsm_configure_audit(uint32_t audit_flags, const char* audit_path);

/*
 * Backup HSM keys to secure storage
 */
__must_check guardian_status_t
hsm_backup_keys(const char* backup_path, uint32_t flags);

/*
 * Restore HSM keys from secure backup
 */
__must_check guardian_status_t
hsm_restore_keys(const char* backup_path, uint32_t flags);

/*
 * Zeroize HSM and clear all keys
 */
__must_check guardian_status_t
hsm_zeroize(uint32_t zeroize_flags);

#ifdef __cplusplus
}
#endif

#endif /* _HSM_DRIVER_H_ */