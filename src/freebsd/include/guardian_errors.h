/*
 * Guardian System - Error Handling Framework
 * FreeBSD Kernel Module Implementation
 * 
 * This header defines the core error handling types, codes and utilities
 * for the Guardian system's kernel-level operations. It provides a comprehensive
 * framework for type-safe error handling with support for audit logging and
 * thread-safe error reporting.
 *
 * External Dependencies:
 * - sys/types.h (FreeBSD 13.0): Basic system types
 * - sys/param.h (FreeBSD 13.0): Kernel parameters
 */

#ifndef _GUARDIAN_ERRORS_H_
#define _GUARDIAN_ERRORS_H_

#include <sys/types.h>
#include <sys/param.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Type-safe error code definition ensuring consistent 32-bit size
 * across all supported architectures.
 */
typedef int32_t guardian_error_t;

/*
 * Success and error code definitions.
 * Range: GUARDIAN_ERROR_MIN (-10) to GUARDIAN_ERROR_MAX (0)
 */
#define GUARDIAN_SUCCESS           0   /* Operation completed successfully */
#define GUARDIAN_E_GENERIC        -1   /* Generic error for unclassified failures */
#define GUARDIAN_E_MEMORY        -2   /* Memory allocation or access failure */
#define GUARDIAN_E_IO            -3   /* I/O operation failure */
#define GUARDIAN_E_INVALID_PARAM -4   /* Invalid parameter or argument provided */
#define GUARDIAN_E_PERMISSION    -5   /* Operation not permitted or access denied */
#define GUARDIAN_E_TIMEOUT       -6   /* Operation timed out */
#define GUARDIAN_E_BUSY          -7   /* Resource or system busy */
#define GUARDIAN_E_NOT_INITIALIZED -8  /* Component or resource not initialized */
#define GUARDIAN_E_NOT_SUPPORTED -9   /* Operation or feature not supported */
#define GUARDIAN_E_SECURITY      -10  /* Security violation or constraint */

/* Error range bounds for validation */
#define GUARDIAN_ERROR_MIN       -10  /* Minimum valid error code */
#define GUARDIAN_ERROR_MAX        0   /* Maximum valid error code */

/*
 * Thread-safe conversion of guardian error codes to human-readable messages.
 * Optimized for kernel context with no memory allocation or I/O operations.
 *
 * @param error_code: The guardian_error_t code to convert
 * @return: Static, thread-safe error message string that is sanitized for security
 * 
 * Note: Returns "Unknown error" for undefined error codes
 */
__attribute__((const))
const char *guardian_strerror(guardian_error_t error_code);

#ifdef __cplusplus
}
#endif

#endif /* _GUARDIAN_ERRORS_H_ */