/*
 * Guardian System - Sysctl Handlers Implementation
 * 
 * Implements sysctl handlers for the Guardian system's FreeBSD kernel module,
 * providing secure interfaces for runtime configuration, monitoring, and control.
 *
 * Version: 1.0.0
 * FreeBSD Version: 13.0
 */

#include <sys/sysctl.h>    /* FreeBSD 13.0 - System control interface */
#include <sys/kernel.h>    /* FreeBSD 13.0 - Kernel interfaces */
#include <sys/malloc.h>    /* FreeBSD 13.0 - Memory allocation */
#include <sys/mac.h>       /* FreeBSD 13.0 - MAC framework integration */
#include <sys/tpm.h>       /* FreeBSD 13.0 - TPM interface */

#include "guardian_types.h"
#include "guardian_errors.h"
#include "guardian_syscalls.h"

/* Sysctl tree root node */
#define GUARDIAN_SYSCTL_ROOT "security.guardian"
#define GUARDIAN_SYSCTL_VERSION "1"
#define GUARDIAN_SYSCTL_MAX_NAME 256

/* Security level definitions */
static const struct {
    const char* name;
    int level;
} GUARDIAN_SYSCTL_SECURITY_LEVELS[] = {
    {"LOW", 0},
    {"MEDIUM", 1},
    {"HIGH", 2},
    {"CRITICAL", 3}
};

/* Forward declarations for static functions */
static int guardian_sysctl_stats_handler(SYSCTL_HANDLER_ARGS);
static int guardian_sysctl_security_handler(SYSCTL_HANDLER_ARGS);
static guardian_status_t verify_tpm_state(void);
static guardian_status_t initialize_mac_context(void);

/* Sysctl declaration macros with security attributes */
SYSCTL_NODE(_security, OID_AUTO, guardian, CTLFLAG_RW | CTLFLAG_SECURE,
            0, "Guardian Security System");

SYSCTL_STRING(_security_guardian, OID_AUTO, version, CTLFLAG_RD,
              GUARDIAN_SYSCTL_VERSION, 0, "Guardian system version");

/* System statistics node */
SYSCTL_PROC(_security_guardian, OID_AUTO, stats,
            CTLTYPE_STRUCT | CTLFLAG_RD | CTLFLAG_SECURE,
            NULL, 0, guardian_sysctl_stats_handler, "S",
            "Guardian system statistics");

/* Security parameters node */
SYSCTL_PROC(_security_guardian, OID_AUTO, security,
            CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_SECURE,
            NULL, 0, guardian_sysctl_security_handler, "I",
            "Guardian security parameters");

/*
 * Initialize the Guardian sysctl interface with security features
 */
guardian_status_t
guardian_sysctl_init(void)
{
    guardian_status_t status;
    guardian_error_info_t error;

    /* Verify TPM state and system integrity */
    status = verify_tpm_state();
    if (status != GUARDIAN_STATUS_SUCCESS) {
        GUARDIAN_ERROR_PUSH(status, "TPM verification failed during sysctl init");
        return status;
    }

    /* Initialize MAC framework context */
    status = initialize_mac_context();
    if (status != GUARDIAN_STATUS_SUCCESS) {
        GUARDIAN_ERROR_PUSH(status, "MAC framework initialization failed");
        return status;
    }

    /* Register sysctl nodes with security attributes */
    sysctl_ctx_init(&guardian_sysctl_ctx);

    /* Create root node with security context */
    guardian_security_context_t sec_ctx = {0};
    sec_ctx.security_flags = GUARDIAN_CAP_MASK;
    sec_ctx.audit_mask = 0xFFFFFFFF;

    /* Initialize system statistics nodes */
    struct sysctl_oid *stats_oid = SYSCTL_ADD_PROC(&guardian_sysctl_ctx,
        SYSCTL_STATIC_CHILDREN(_security_guardian),
        OID_AUTO, "stats",
        CTLTYPE_STRUCT | CTLFLAG_RD | CTLFLAG_SECURE,
        NULL, 0, guardian_sysctl_stats_handler,
        "S", "Guardian system statistics");

    if (stats_oid == NULL) {
        GUARDIAN_ERROR_PUSH(GUARDIAN_STATUS_ERROR, "Failed to create stats sysctl node");
        guardian_sysctl_cleanup();
        return GUARDIAN_STATUS_ERROR;
    }

    /* Initialize security parameter nodes */
    struct sysctl_oid *security_oid = SYSCTL_ADD_PROC(&guardian_sysctl_ctx,
        SYSCTL_STATIC_CHILDREN(_security_guardian),
        OID_AUTO, "security",
        CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_SECURE,
        NULL, 0, guardian_sysctl_security_handler,
        "I", "Guardian security parameters");

    if (security_oid == NULL) {
        GUARDIAN_ERROR_PUSH(GUARDIAN_STATUS_ERROR, "Failed to create security sysctl node");
        guardian_sysctl_cleanup();
        return GUARDIAN_STATUS_ERROR;
    }

    /* Verify initialization with TPM measurement */
    status = guardian_sys_tpm_validate(NULL, 0, &sec_ctx, NULL);
    if (status != GUARDIAN_STATUS_SUCCESS) {
        GUARDIAN_ERROR_PUSH(status, "TPM validation failed after sysctl init");
        guardian_sysctl_cleanup();
        return status;
    }

    return GUARDIAN_STATUS_SUCCESS;
}

/*
 * Clean up the Guardian sysctl interface
 */
void
guardian_sysctl_cleanup(void)
{
    guardian_security_context_t sec_ctx = {0};
    guardian_audit_context_t audit_ctx = {0};

    /* Log cleanup initiation */
    audit_ctx.timestamp = time_second;
    audit_ctx.syscall_number = SYS_GUARDIAN_SECURITY_CONTEXT;
    strlcpy(audit_ctx.audit_data, "Sysctl cleanup initiated",
            GUARDIAN_ERROR_AUDIT_BUFFER);

    /* Verify security context for cleanup */
    guardian_sys_security_context_validate(&sec_ctx, 0xFFFFFFFF, &audit_ctx);

    /* Unregister sysctl handlers */
    sysctl_ctx_free(&guardian_sysctl_ctx);

    /* Clean up MAC framework context */
    mac_policy_remove(&guardian_mac_policy);

    /* Verify cleanup with TPM */
    guardian_sys_tpm_validate(NULL, 0, &sec_ctx, &audit_ctx);
}

/*
 * Handler for system statistics sysctl requests
 */
static int
guardian_sysctl_stats_handler(SYSCTL_HANDLER_ARGS)
{
    guardian_memory_stats_t stats;
    guardian_security_context_t sec_ctx = {0};
    guardian_audit_context_t audit_ctx = {0};
    int error;

    /* Validate request parameters */
    if (req == NULL) {
        return EINVAL;
    }

    /* Verify security context and capabilities */
    sec_ctx.security_flags = GUARDIAN_CAP_MASK;
    error = guardian_sys_security_context_validate(&sec_ctx, 0xFFFFFFFF, &audit_ctx);
    if (error != 0) {
        return error;
    }

    /* Check MAC framework access permissions */
    error = mac_system_check_sysctl(&req->td->td_ucred->cr_label,
                                  req->td, oidp, arg1, arg2,
                                  req->newptr, req->newlen);
    if (error != 0) {
        return error;
    }

    /* Collect system statistics securely */
    memset(&stats, 0, sizeof(stats));
    stats.total = vm_cnt.v_page_count * PAGE_SIZE;
    stats.used = vm_cnt.v_active_count * PAGE_SIZE;
    stats.free = vm_cnt.v_free_count * PAGE_SIZE;
    stats.shared = vm_cnt.v_wire_count * PAGE_SIZE;

    /* Return formatted statistics */
    error = SYSCTL_OUT(req, &stats, sizeof(stats));
    if (error != 0) {
        return error;
    }

    /* Log access to audit system */
    audit_ctx.timestamp = time_second;
    audit_ctx.syscall_number = SYS_GUARDIAN_PROCESS_MONITOR;
    strlcpy(audit_ctx.audit_data, "Statistics accessed via sysctl",
            GUARDIAN_ERROR_AUDIT_BUFFER);
    guardian_sys_process_monitor(NULL, &sec_ctx, &audit_ctx);

    return 0;
}

/*
 * Handler for security parameter sysctl requests
 */
static int
guardian_sysctl_security_handler(SYSCTL_HANDLER_ARGS)
{
    int error, value;
    guardian_security_context_t sec_ctx = {0};
    guardian_audit_context_t audit_ctx = {0};

    /* Verify TPM state for secure operation */
    error = verify_tpm_state();
    if (error != 0) {
        return error;
    }

    /* Validate security context */
    sec_ctx.security_flags = GUARDIAN_CAP_MASK;
    error = guardian_sys_security_context_validate(&sec_ctx, 0xFFFFFFFF, &audit_ctx);
    if (error != 0) {
        return error;
    }

    /* Handle read request */
    if (req->newptr == NULL) {
        error = SYSCTL_OUT(req, arg1, sizeof(int));
        return error;
    }

    /* Handle write request with validation */
    error = SYSCTL_IN(req, &value, sizeof(value));
    if (error != 0) {
        return error;
    }

    /* Validate security parameter bounds */
    if (value < 0 || value > GUARDIAN_SYSCTL_SECURITY_LEVELS[3].level) {
        return EINVAL;
    }

    /* Update security settings atomically */
    atomic_store_int((int *)arg1, value);

    /* Log security parameter change */
    audit_ctx.timestamp = time_second;
    audit_ctx.syscall_number = SYS_GUARDIAN_SECURITY_CONTEXT;
    snprintf(audit_ctx.audit_data, GUARDIAN_ERROR_AUDIT_BUFFER,
             "Security parameter updated: %d", value);
    guardian_sys_security_context_validate(&sec_ctx, 0xFFFFFFFF, &audit_ctx);

    return 0;
}

/*
 * Verify TPM state and system integrity
 */
static guardian_status_t
verify_tpm_state(void)
{
    int error;
    struct tpm_readpublic_params params;
    guardian_security_context_t sec_ctx = {0};

    /* Initialize TPM parameters */
    memset(&params, 0, sizeof(params));
    params.algorithm_id = TPM_ALG_RSA;

    /* Verify TPM state */
    error = tpm2_readpublic(&params);
    if (error != 0) {
        GUARDIAN_ERROR_PUSH(GUARDIAN_STATUS_ERROR, "TPM verification failed");
        return GUARDIAN_STATUS_ERROR;
    }

    return GUARDIAN_STATUS_SUCCESS;
}

/*
 * Initialize MAC framework context
 */
static guardian_status_t
initialize_mac_context(void)
{
    int error;
    struct mac_policy_conf policy_conf;
    guardian_security_context_t sec_ctx = {0};

    /* Initialize MAC policy configuration */
    memset(&policy_conf, 0, sizeof(policy_conf));
    policy_conf.mpc_name = "guardian";
    policy_conf.mpc_fullname = "Guardian Security System";
    policy_conf.mpc_labelname = "guardian_label";
    policy_conf.mpc_ops = &guardian_mac_ops;

    /* Register MAC policy */
    error = mac_policy_register(&policy_conf, &guardian_mac_handle);
    if (error != 0) {
        GUARDIAN_ERROR_PUSH(GUARDIAN_STATUS_ERROR, "MAC policy registration failed");
        return GUARDIAN_STATUS_ERROR;
    }

    return GUARDIAN_STATUS_SUCCESS;
}