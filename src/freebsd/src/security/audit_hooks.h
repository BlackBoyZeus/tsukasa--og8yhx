/*
 * Guardian System - Audit Hook Interfaces and Structures
 * 
 * This header defines the audit hook infrastructure for the Guardian system's
 * FreeBSD kernel module, providing comprehensive auditing capabilities with
 * enhanced buffer management and extended event types.
 *
 * Version: 1.0.0
 * FreeBSD Version: 13.0
 */

#ifndef _GUARDIAN_AUDIT_HOOKS_H_
#define _GUARDIAN_AUDIT_HOOKS_H_

#include <sys/types.h>              /* FreeBSD 13.0 - System type definitions */
#include <sys/audit.h>             /* FreeBSD 13.0 - Audit subsystem interfaces */
#include <security/audit/audit.h>   /* FreeBSD 13.0 - Security audit interfaces */
#include "guardian_types.h"         /* Guardian core type definitions */
#include "guardian_errors.h"        /* Guardian error handling definitions */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Audit system configuration constants
 */
#define GUARDIAN_AUDIT_MAX_EVENTS    1024    /* Maximum events in buffer */
#define GUARDIAN_AUDIT_BUFFER_SIZE   4096    /* Size of audit data buffer */
#define GUARDIAN_AUDIT_MAX_HANDLERS  16      /* Maximum audit handlers */
#define GUARDIAN_AUDIT_MIN_SEVERITY  0       /* Minimum severity level */
#define GUARDIAN_AUDIT_MAX_SEVERITY  5       /* Maximum severity level */

/*
 * Audit event types enumeration
 */
typedef enum guardian_audit_event_types {
    GUARDIAN_AUDIT_SECURITY  = 0x0001,   /* Security-related events */
    GUARDIAN_AUDIT_SYSTEM    = 0x0002,   /* System operation events */
    GUARDIAN_AUDIT_HARDWARE  = 0x0004,   /* Hardware-related events */
    GUARDIAN_AUDIT_PROCESS   = 0x0008    /* Process-related events */
} guardian_audit_event_type_t;

/*
 * Enhanced audit event structure with context tracking
 */
typedef struct guardian_audit_event {
    uint32_t event_id;                              /* Unique event identifier */
    time_t timestamp;                               /* Event timestamp */
    uint32_t type;                                  /* Event type */
    uint32_t severity;                              /* Event severity */
    char data[GUARDIAN_AUDIT_BUFFER_SIZE];          /* Event data buffer */
    uint64_t context_id;                           /* Security context ID */
    guardian_security_context_t* security_context;   /* Security context */
    guardian_error_info_t* error_info;              /* Associated error info */
} guardian_audit_event_t;

/*
 * Audit handler callback type definition
 */
typedef guardian_status_t (*guardian_audit_handler_callback_t)(
    const guardian_audit_event_t* event,
    void* context
);

/*
 * Audit handler structure with context support
 */
typedef struct guardian_audit_handler {
    guardian_audit_handler_callback_t callback;     /* Handler callback */
    void* context;                                 /* Handler context */
    uint32_t event_mask;                          /* Event type mask */
    uint32_t min_severity;                        /* Minimum severity */
    guardian_security_context_t* security_context; /* Handler security context */
} guardian_audit_handler_t;

/*
 * Function declarations
 */

/*
 * Initialize the Guardian audit subsystem
 * Returns: Status code indicating initialization success or failure
 */
guardian_status_t guardian_audit_init(void) __must_check;

/*
 * Record a security audit event
 * Parameters:
 *   event   - Pointer to audit event structure
 *   context - Security context for the event
 * Returns: Status code indicating audit recording success or failure
 */
guardian_status_t guardian_audit_event(
    guardian_audit_event_t* event,
    guardian_security_context_t* context
) __must_check __non_null(1,2);

/*
 * Register an audit event handler
 * Parameters:
 *   handler - Audit handler structure
 *   context - Handler-specific context
 * Returns: Status code indicating registration success or failure
 */
guardian_status_t guardian_register_audit_handler(
    guardian_audit_handler_t handler,
    void* context
) __must_check __non_null(1);

/*
 * Unregister an audit event handler
 * Parameters:
 *   handler - Handler to unregister
 * Returns: Status code indicating unregistration success or failure
 */
guardian_status_t guardian_unregister_audit_handler(
    guardian_audit_handler_t handler
) __must_check __non_null(1);

/*
 * Get current audit statistics
 * Parameters:
 *   stats - Pointer to stats structure to fill
 * Returns: Status code indicating operation success or failure
 */
guardian_status_t guardian_audit_get_stats(
    guardian_audit_stats_t* stats
) __must_check __non_null(1);

/*
 * Flush audit buffer
 * Returns: Status code indicating flush operation success or failure
 */
guardian_status_t guardian_audit_flush(void) __must_check;

/*
 * Set audit event filter
 * Parameters:
 *   type_mask - Event types to filter
 *   min_severity - Minimum severity to record
 * Returns: Status code indicating filter setup success or failure
 */
guardian_status_t guardian_audit_set_filter(
    uint32_t type_mask,
    uint32_t min_severity
) __must_check;

#ifdef __cplusplus
}
#endif

#endif /* _GUARDIAN_AUDIT_HOOKS_H_ */