/*
 * Guardian System - Kernel Module Interface
 * 
 * Core header file defining the main kernel module interface for the Guardian system,
 * providing fundamental structures, functions, and macros for kernel module
 * initialization, management, and interaction with the FreeBSD kernel.
 *
 * Version: 1.0.0
 * FreeBSD Version: 13.0
 */

#ifndef _GUARDIAN_MODULE_H_
#define _GUARDIAN_MODULE_H_

#include <sys/module.h>   /* FreeBSD 13.0 - Kernel module support */
#include <sys/kernel.h>   /* FreeBSD 13.0 - Kernel interfaces */
#include <sys/systm.h>    /* FreeBSD 13.0 - System functions */
#include <sys/lock.h>     /* FreeBSD 13.0 - Kernel locking primitives */

#include "guardian_errors.h"  /* Error handling and audit */
#include "guardian_types.h"   /* Core type definitions */
#include "guardian_ioctl.h"   /* IOCTL interface */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Module configuration constants
 */
#define GUARDIAN_MODULE_NAME           "guardian"
#define GUARDIAN_MODULE_VERSION        "1.0.0"
#define GUARDIAN_MAX_DEVICES          32
#define GUARDIAN_MAX_HANDLERS         16
#define GUARDIAN_SECURITY_LEVEL       3
#define GUARDIAN_AUDIT_BUFFER_SIZE    4096
#define GUARDIAN_MAX_SECURITY_CONTEXTS 64

/*
 * Module initialization flags
 */
#define GUARDIAN_INIT_SECURE          0x00000001
#define GUARDIAN_INIT_AUDIT           0x00000002
#define GUARDIAN_INIT_DEBUG           0x00000004
#define GUARDIAN_INIT_HARDWARE        0x00000008
#define GUARDIAN_INIT_PERFORMANCE     0x00000010

/*
 * Module state flags
 */
#define GUARDIAN_STATE_INITIALIZED    0x00000001
#define GUARDIAN_STATE_RUNNING        0x00000002
#define GUARDIAN_STATE_ERROR          0x00000004
#define GUARDIAN_STATE_SHUTDOWN       0x00000008

/*
 * Module capability flags
 */
#define GUARDIAN_CAP_HARDWARE_ACCESS  0x00000001
#define GUARDIAN_CAP_MEMORY_PROTECT   0x00000002
#define GUARDIAN_CAP_PROCESS_CONTROL  0x00000004
#define GUARDIAN_CAP_AUDIT_CONTROL    0x00000008
#define GUARDIAN_CAP_SECURITY_ADMIN   0x00000010

/*
 * Enhanced module information structure
 */
typedef struct guardian_module_info {
    const char* name;                          /* Module name */
    const char* version;                       /* Module version */
    guardian_status_t status;                  /* Current status */
    uint32_t security_level;                   /* Security level */
    guardian_audit_context_t audit_context;    /* Audit context */
    uint32_t state_flags;                      /* State flags */
    uint32_t capabilities;                     /* Capability flags */
    guardian_security_context_t security_ctx;  /* Security context */
    guardian_device_info_t devices[GUARDIAN_MAX_DEVICES];  /* Managed devices */
    uint32_t device_count;                     /* Number of active devices */
    void* reserved;                            /* Reserved for future use */
} guardian_module_info_t;

/*
 * Module operation handlers structure
 */
typedef struct guardian_module_ops {
    /* Core operations */
    guardian_status_t (*init)(void* arg, guardian_security_context_t* sec_ctx);
    guardian_status_t (*cleanup)(guardian_security_context_t* sec_ctx);
    
    /* IOCTL interface */
    guardian_status_t (*ioctl_handler)(guardian_ioctl_request_t* req,
                                     guardian_ioctl_response_t* resp);
    
    /* Security operations */
    guardian_status_t (*security_handler)(guardian_security_context_t* sec_ctx,
                                        uint32_t operation,
                                        void* data,
                                        size_t size);
    
    /* Audit operations */
    guardian_status_t (*audit_handler)(guardian_audit_context_t* audit_ctx,
                                     const char* message,
                                     size_t size);
    
    /* Device operations */
    guardian_status_t (*device_handler)(guardian_device_info_t* dev_info,
                                      uint32_t operation);
    
    /* Reserved for future expansion */
    void* reserved[2];
} guardian_module_ops_t;

/*
 * Module initialization function
 * Initializes the Guardian kernel module with enhanced security
 */
GUARDIAN_EXPORT guardian_status_t
guardian_module_init(void* arg, guardian_security_context_t* sec_ctx);

/*
 * Module cleanup function
 * Safely cleans up and unloads the Guardian kernel module
 */
GUARDIAN_EXPORT guardian_status_t
guardian_module_cleanup(guardian_security_context_t* sec_ctx);

/*
 * Module information retrieval
 * Gets current module information with security context
 */
GUARDIAN_EXPORT guardian_status_t
guardian_module_get_info(guardian_module_info_t* info);

/*
 * Module operation registration
 * Registers operation handlers with security validation
 */
GUARDIAN_EXPORT guardian_status_t
guardian_module_register_ops(guardian_module_ops_t* ops,
                           guardian_security_context_t* sec_ctx);

/*
 * Module state management
 * Controls module state with security validation
 */
GUARDIAN_EXPORT guardian_status_t
guardian_module_set_state(uint32_t state_flags,
                         guardian_security_context_t* sec_ctx);

/*
 * Module capability management
 * Manages module capabilities with security validation
 */
GUARDIAN_EXPORT guardian_status_t
guardian_module_set_capabilities(uint32_t capabilities,
                               guardian_security_context_t* sec_ctx);

/*
 * Module device management
 * Manages device registration with security validation
 */
GUARDIAN_EXPORT guardian_status_t
guardian_module_register_device(guardian_device_info_t* dev_info,
                              guardian_security_context_t* sec_ctx);

/*
 * Module security context management
 * Manages security contexts with validation
 */
GUARDIAN_EXPORT guardian_status_t
guardian_module_set_security_context(guardian_security_context_t* new_ctx,
                                   guardian_security_context_t* current_ctx);

#ifdef __cplusplus
}
#endif

#endif /* _GUARDIAN_MODULE_H_ */