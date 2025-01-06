/*
 * Guardian System - Sysctl Handlers and Interfaces
 * 
 * This header defines secure sysctl handlers and interfaces for the Guardian system's
 * FreeBSD kernel module, providing system control and monitoring capabilities with
 * enhanced security features, thread-safe operations, and audit logging.
 *
 * Version: 1.0.0
 * FreeBSD Version: 13.0
 */

#ifndef _GUARDIAN_SYSCTL_HANDLERS_H_
#define _GUARDIAN_SYSCTL_HANDLERS_H_

#include <sys/sysctl.h>      /* FreeBSD 13.0 - System control interface */
#include <sys/kernel.h>      /* FreeBSD 13.0 - Kernel interface */
#include <sys/malloc.h>      /* FreeBSD 13.0 - Memory allocation */
#include "guardian_types.h"
#include "guardian_errors.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * System-wide constants
 */
#define GUARDIAN_SYSCTL_VERSION           "1.0.0"
#define GUARDIAN_SYSCTL_ROOT             "guardian"
#define GUARDIAN_SYSCTL_MAX_NAME         32
#define GUARDIAN_SYSCTL_MAX_SECURITY_LEVEL 4
#define GUARDIAN_SYSCTL_AUDIT_BUFFER_SIZE 4096

/*
 * Thread-safe mutex type for sysctl handlers
 */
typedef struct guardian_mutex {
    struct mtx mtx;
    uint32_t owner;
    uint32_t recursion;
} guardian_mutex_t;

/*
 * Enhanced sysctl node structure with security features
 */
typedef struct guardian_sysctl_node {
    char name[GUARDIAN_SYSCTL_MAX_NAME];          /* Node name */
    struct sysctl_oid *oid;                       /* FreeBSD sysctl OID */
    guardian_mutex_t thread_lock;                 /* Thread synchronization */
    uint8_t security_level;                       /* Required security level */
    uint32_t audit_mask;                          /* Audit event mask */
    void *data;                                   /* Node-specific data */
    size_t data_size;                            /* Size of node data */
    uint32_t flags;                              /* Node flags */
    guardian_security_context_t *security_ctx;    /* Security context */
} guardian_sysctl_node_t;

/*
 * Sysctl handler function type with security context
 */
typedef int (*guardian_sysctl_handler_t)(struct sysctl_oid *oidp,
                                       void *arg1,
                                       int arg2,
                                       struct sysctl_req *req,
                                       guardian_security_context_t *sec_ctx);

/*
 * Function declarations
 */

/*
 * Initialize the Guardian sysctl tree with security context
 */
__attribute__((warn_unused_result))
guardian_status_t guardian_sysctl_init(guardian_security_context_t *security_ctx);

/*
 * Cleanup and remove Guardian sysctl nodes
 */
void guardian_sysctl_cleanup(void);

/*
 * Create a new sysctl node with security attributes
 */
__attribute__((warn_unused_result))
guardian_status_t guardian_sysctl_create_node(
    const char *name,
    guardian_sysctl_handler_t handler,
    void *data,
    size_t data_size,
    uint8_t security_level,
    uint32_t audit_mask,
    guardian_security_context_t *sec_ctx);

/*
 * Remove a sysctl node securely
 */
guardian_status_t guardian_sysctl_remove_node(const char *name);

/*
 * Thread-safe sysctl value access functions
 */
guardian_status_t guardian_sysctl_read_value(
    guardian_sysctl_node_t *node,
    void *buffer,
    size_t *size,
    guardian_security_context_t *sec_ctx);

guardian_status_t guardian_sysctl_write_value(
    guardian_sysctl_node_t *node,
    const void *buffer,
    size_t size,
    guardian_security_context_t *sec_ctx);

/*
 * Audit logging for sysctl operations
 */
void guardian_sysctl_audit_log(
    const guardian_sysctl_node_t *node,
    const char *operation,
    guardian_status_t status,
    const guardian_security_context_t *sec_ctx);

/*
 * Security validation functions
 */
__attribute__((warn_unused_result))
guardian_status_t guardian_sysctl_validate_security(
    const guardian_sysctl_node_t *node,
    const guardian_security_context_t *sec_ctx);

/*
 * Thread synchronization functions
 */
void guardian_sysctl_lock_node(guardian_sysctl_node_t *node);
void guardian_sysctl_unlock_node(guardian_sysctl_node_t *node);

#ifdef __cplusplus
}
#endif

#endif /* _GUARDIAN_SYSCTL_HANDLERS_H_ */