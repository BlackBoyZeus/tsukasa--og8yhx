/*
 * Guardian System - Mandatory Access Control (MAC) Policy Framework
 * FreeBSD Kernel Module Implementation
 *
 * This header defines the MAC policy interface and data structures for the
 * Guardian system's FreeBSD kernel module, providing comprehensive MAC
 * functionality for enforcing security policies with enhanced validation
 * and auditing capabilities.
 *
 * Copyright (c) 2024. All rights reserved.
 */

#ifndef _GUARDIAN_MAC_POLICY_H_
#define _GUARDIAN_MAC_POLICY_H_

#include <sys/mac.h>      /* FreeBSD 13.0 - MAC framework interfaces */
#include <sys/param.h>    /* FreeBSD 13.0 - System parameters */
#include <sys/kernel.h>   /* FreeBSD 13.0 - Kernel interfaces */

#include "../include/guardian_types.h"
#include "../include/guardian_errors.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Version and configuration constants
 */
#define GUARDIAN_MAC_VERSION        "1"
#define GUARDIAN_MAC_NAME          "guardian_mac"
#define GUARDIAN_MAC_MAX_LABELS    256
#define GUARDIAN_MAC_MAX_POLICIES  32
#define GUARDIAN_MAC_LOCK_TYPE     "guardian_mac_lock"
#define GUARDIAN_MAC_AUDIT_ENABLED 1

/*
 * MAC label validation flags
 */
#define GUARDIAN_MAC_LABEL_VALID    0x00000001
#define GUARDIAN_MAC_LABEL_SYSTEM   0x00000002
#define GUARDIAN_MAC_LABEL_TRUSTED  0x00000004
#define GUARDIAN_MAC_LABEL_CRITICAL 0x00000008

/*
 * Enhanced MAC label structure with validation support
 */
typedef struct guardian_mac_label {
    uint32_t id;                /* Unique label identifier */
    uint32_t type;             /* Label type classification */
    uint32_t flags;            /* Label status flags */
    uint32_t validation_mask;  /* Validation requirements mask */
    char name[GUARDIAN_MAX_NAME_LENGTH];  /* Human-readable label name */
    void *private_data;        /* Policy-specific private data */
} guardian_mac_label_t;

/*
 * MAC policy initialization configuration
 */
typedef struct guardian_mac_init_params {
    uint32_t version;          /* Policy module version */
    uint32_t flags;           /* Initialization flags */
    uint32_t max_labels;      /* Maximum number of labels */
    uint32_t audit_flags;     /* Audit configuration flags */
} guardian_mac_init_params_t;

/*
 * Enhanced audit context for MAC operations
 */
typedef struct guardian_mac_audit_context {
    uint32_t event_id;        /* Unique audit event identifier */
    uint32_t severity;        /* Event severity level */
    uint64_t timestamp;       /* Event timestamp */
    char description[256];    /* Event description */
    void *context_data;       /* Additional context information */
} guardian_mac_audit_context_t;

/*
 * MAC policy operation handlers with enhanced safety checks
 */
struct guardian_mac_policy_ops {
    /* Policy initialization with validation */
    guardian_error_t (*init)(guardian_mac_init_params_t *params);
    
    /* Access control check with comprehensive validation */
    guardian_error_t (*check_access)(
        guardian_security_policy_t *policy,
        uint32_t requested_access,
        guardian_mac_audit_context_t *audit_ctx
    ) __attribute__((warn_unused_result));
    
    /* Policy state transition validation */
    guardian_error_t (*validate_transition)(
        guardian_mac_label_t *old_label,
        guardian_mac_label_t *new_label,
        guardian_mac_audit_context_t *audit_ctx
    );
    
    /* Enhanced audit event handling */
    void (*audit_event)(
        guardian_mac_audit_context_t *audit_ctx,
        const char *event_type,
        uint32_t result
    );
};

/*
 * Core MAC policy interface functions
 */

/*
 * Initialize the MAC policy module with enhanced validation and thread-safety
 *
 * @param flags: Initialization flags
 * @param audit_config: Audit subsystem configuration
 * @return: Success or detailed error code with context
 */
guardian_error_t guardian_mac_init(
    guardian_init_flags_t flags,
    guardian_audit_config_t *audit_config
) __attribute__((warn_unused_result));

/*
 * Perform comprehensive access control check with enhanced validation
 *
 * @param policy: Security policy to evaluate
 * @param requested_access: Requested access rights
 * @param audit_ctx: Audit context for logging
 * @return: Detailed access control decision or error
 */
guardian_error_t guardian_mac_check_access(
    guardian_security_policy_t *policy,
    uint32_t requested_access,
    guardian_mac_audit_context_t *audit_ctx
) __attribute__((warn_unused_result)) __attribute__((hot));

/*
 * Register a new MAC policy with the framework
 *
 * @param policy_ops: Policy operation handlers
 * @param policy_name: Unique policy name
 * @param flags: Registration flags
 * @return: Success or error code
 */
guardian_error_t guardian_mac_register_policy(
    struct guardian_mac_policy_ops *policy_ops,
    const char *policy_name,
    uint32_t flags
) __attribute__((warn_unused_result));

/*
 * Create a new MAC label with validation
 *
 * @param label_type: Type of label to create
 * @param flags: Label creation flags
 * @param out_label: Pointer to store created label
 * @return: Success or error code
 */
guardian_error_t guardian_mac_create_label(
    uint32_t label_type,
    uint32_t flags,
    guardian_mac_label_t **out_label
) __attribute__((warn_unused_result));

#ifdef __cplusplus
}
#endif

#endif /* _GUARDIAN_MAC_POLICY_H_ */