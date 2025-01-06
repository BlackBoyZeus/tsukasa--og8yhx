/*
 * Guardian System - Console Hardware Driver Interface
 * 
 * This header defines the secure hardware driver interface for the gaming console,
 * providing low-level access with comprehensive security controls and performance
 * optimizations.
 *
 * Version: 1.0.0
 * FreeBSD Version: 13.0
 */

#ifndef _GUARDIAN_CONSOLE_DRIVER_H_
#define _GUARDIAN_CONSOLE_DRIVER_H_

#include <sys/types.h>    /* FreeBSD 13.0 */
#include <sys/param.h>    /* FreeBSD 13.0 */
#include <sys/systm.h>    /* FreeBSD 13.0 */
#include <sys/kernel.h>   /* FreeBSD 13.0 */

#include "guardian_types.h"
#include "guardian_errors.h"
#include "guardian_ioctl.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Console driver configuration constants
 */
#define GUARDIAN_CONSOLE_MAX_REGIONS     16   /* Maximum memory regions */
#define GUARDIAN_CONSOLE_MAX_DEVICES     8    /* Maximum hardware devices */
#define GUARDIAN_CONSOLE_BUFFER_SIZE     4096 /* I/O buffer size */
#define GUARDIAN_CONSOLE_SECURITY_LEVEL  3    /* Default security level */
#define GUARDIAN_CONSOLE_MAX_RETRIES     3    /* Maximum operation retries */
#define GUARDIAN_CONSOLE_TIMEOUT_MS      100  /* Operation timeout in ms */

/*
 * Memory region protection flags
 */
#define GUARDIAN_REGION_READ       0x0001  /* Read access permitted */
#define GUARDIAN_REGION_WRITE      0x0002  /* Write access permitted */
#define GUARDIAN_REGION_EXECUTE    0x0004  /* Execute access permitted */
#define GUARDIAN_REGION_DMA        0x0008  /* DMA operations permitted */
#define GUARDIAN_REGION_SECURE     0x0010  /* Enhanced security required */
#define GUARDIAN_REGION_CACHED     0x0020  /* Region can be cached */
#define GUARDIAN_REGION_LOCKED     0x0040  /* Region memory-locked */
#define GUARDIAN_REGION_ENCRYPTED  0x0080  /* Region requires encryption */

/*
 * Console memory region descriptor
 */
typedef struct guardian_console_region {
    uint32_t id;                  /* Region identifier */
    uintptr_t base_addr;         /* Base physical address */
    size_t size;                 /* Region size in bytes */
    uint32_t flags;              /* Access flags */
    uint8_t security_level;      /* Required security level */
    uint32_t access_mask;        /* Access permission mask */
    uint32_t protection_bits;    /* Memory protection bits */
} guardian_console_region_t;

/*
 * Console security configuration
 */
typedef struct guardian_console_security_config {
    uint32_t security_level;           /* Required security level */
    uint64_t validation_mask;          /* Security validation mask */
    guardian_security_context_t ctx;    /* Security context */
    uint32_t encryption_flags;         /* Encryption requirements */
    uint32_t integrity_checks;         /* Required integrity checks */
} guardian_console_security_config_t;

/*
 * Console performance metrics
 */
typedef struct guardian_console_metrics {
    uint64_t read_ops;           /* Total read operations */
    uint64_t write_ops;          /* Total write operations */
    uint64_t security_checks;    /* Security validations performed */
    uint64_t errors;             /* Error count */
    uint64_t retries;           /* Operation retry count */
    uint64_t avg_latency_ns;    /* Average operation latency */
} guardian_console_metrics_t;

/*
 * Console driver operation handlers
 */
typedef struct guardian_console_ops {
    /* Core operations */
    guardian_status_t (*init)(guardian_device_info_t* device_info,
                            guardian_console_security_config_t* security_config);
    
    guardian_status_t (*read)(uint32_t region_id, void* buffer, size_t size,
                            guardian_security_context_t* sec_ctx);
    
    guardian_status_t (*write)(uint32_t region_id, const void* buffer, size_t size,
                             guardian_security_context_t* sec_ctx);
    
    guardian_status_t (*ioctl)(guardian_ioctl_request_t* request,
                              guardian_ioctl_response_t* response);

    /* Security operations */
    guardian_status_t (*validate_security)(guardian_security_context_t* sec_ctx,
                                         uint32_t operation);
    
    /* Performance monitoring */
    guardian_status_t (*monitor_performance)(guardian_console_metrics_t* metrics);
    
    /* Error handling */
    guardian_status_t (*handle_error)(guardian_error_info_t* error_info);
} guardian_console_ops_t;

/*
 * Core driver interface functions
 */

/**
 * Initialize the console driver with security validation
 * @param device_info Device configuration information
 * @param security_config Security configuration parameters
 * @return Operation status with detailed error information
 */
guardian_status_t guardian_console_init(
    guardian_device_info_t* device_info,
    guardian_security_config_t* security_config) __must_check;

/**
 * Secure read operation from console hardware
 * @param region_id Target memory region identifier
 * @param buffer Output buffer for read data
 * @param size Number of bytes to read
 * @param sec_ctx Security context for validation
 * @return Operation status with metrics
 */
guardian_status_t guardian_console_read(
    uint32_t region_id,
    void* buffer,
    size_t size,
    guardian_security_context_t* sec_ctx) __must_check __non_null(2,4);

/**
 * Secure write operation to console hardware
 * @param region_id Target memory region identifier
 * @param buffer Input buffer containing data to write
 * @param size Number of bytes to write
 * @param sec_ctx Security context for validation
 * @return Operation status with metrics
 */
guardian_status_t guardian_console_write(
    uint32_t region_id,
    const void* buffer,
    size_t size,
    guardian_security_context_t* sec_ctx) __must_check __non_null(2,4);

#ifdef __cplusplus
}
#endif

#endif /* _GUARDIAN_CONSOLE_DRIVER_H_ */