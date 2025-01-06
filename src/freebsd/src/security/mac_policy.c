/*
 * Guardian System - Mandatory Access Control (MAC) Policy Framework
 * FreeBSD Kernel Module Implementation
 *
 * This file implements the MAC policy framework for the Guardian system's
 * FreeBSD kernel module, providing thread-safe MAC functionality with 
 * enhanced audit logging for enforcing security policies.
 *
 * Copyright (c) 2024. All rights reserved.
 */

#include <sys/param.h>     /* FreeBSD 13.0 - System parameters */
#include <sys/kernel.h>    /* FreeBSD 13.0 - Kernel interfaces */
#include <sys/mac.h>       /* FreeBSD 13.0 - MAC framework interfaces */
#include <sys/malloc.h>    /* FreeBSD 13.0 - Kernel memory allocation */
#include <sys/proc.h>      /* FreeBSD 13.0 - Process management */
#include <sys/lock.h>      /* FreeBSD 13.0 - Kernel locking primitives */
#include <sys/mutex.h>     /* FreeBSD 13.0 - Mutex synchronization */

#include "mac_policy.h"
#include "../include/guardian_types.h"
#include "../include/guardian_errors.h"

/* Memory allocation type for MAC policy */
MALLOC_DEFINE(M_GUARDIAN_MAC, "guardian_mac", "Guardian MAC Policy Framework");

/* Global state with alignment for cache efficiency */
static struct mac_policy_ops g_guardian_mac_policy __aligned(16);
static guardian_mac_policy_state g_guardian_mac_state __aligned(16);
static guardian_mac_label g_guardian_mac_label_cache[GUARDIAN_MAC_MAX_LABELS] __aligned(16);
static struct mtx g_guardian_mac_mutex;
static guardian_audit_context_t g_audit_ctx;

/* Forward declarations for internal functions */
static guardian_error_t guardian_mac_validate_policy(const guardian_security_policy_t *policy);
static void guardian_mac_audit_log(const guardian_audit_context_t *ctx, const char *event, uint32_t result);
static guardian_error_t guardian_mac_cache_label(guardian_mac_label_t *label);

/*
 * Initialize the MAC policy module with enhanced thread-safety and audit logging
 */
guardian_error_t
guardian_mac_init(guardian_audit_context_t *audit_ctx)
{
    guardian_error_t error = GUARDIAN_SUCCESS;

    /* Initialize mutex with adaptive spin */
    mtx_init(&g_guardian_mac_mutex, "guardian_mac_mutex", GUARDIAN_MAC_LOCK_TYPE, 
             MTX_DEF | MTX_DUPOK);

    /* Set up audit context with memory barrier */
    memcpy(&g_audit_ctx, audit_ctx, sizeof(guardian_audit_context_t));
    atomic_thread_fence(memory_order_release);

    /* Initialize MAC policy data structures */
    memset(&g_guardian_mac_policy, 0, sizeof(g_guardian_mac_policy));
    memset(&g_guardian_mac_state, 0, sizeof(g_guardian_mac_state));
    memset(g_guardian_mac_label_cache, 0, sizeof(g_guardian_mac_label_cache));

    /* Set up MAC policy operations */
    g_guardian_mac_policy.mpo_init = guardian_mac_init;
    g_guardian_mac_policy.mpo_check_access = guardian_mac_check_access;
    g_guardian_mac_policy.mpo_audit_event = guardian_mac_audit_log;

    /* Register MAC policy with kernel */
    struct mac_policy_conf policy_conf = {
        .mpc_name = GUARDIAN_MAC_NAME,
        .mpc_fullname = "Guardian MAC Policy",
        .mpc_labelname = "guardian_mac",
        .mpc_ops = &g_guardian_mac_policy,
        .mpc_loadtime_flags = MPC_LOADTIME_FLAG_UNLOADOK,
        .mpc_field_flags = MPC_FIELD_FLAG_NONE
    };

    error = mac_policy_register(&policy_conf, &g_guardian_mac_state.policy_handle);
    if (error != GUARDIAN_SUCCESS) {
        guardian_mac_audit_log(&g_audit_ctx, "mac_init_failed", error);
        goto cleanup;
    }

    /* Initialize label cache with memory barriers */
    for (int i = 0; i < GUARDIAN_MAC_MAX_LABELS; i++) {
        g_guardian_mac_label_cache[i].flags = GUARDIAN_MAC_LABEL_VALID;
        atomic_thread_fence(memory_order_release);
    }

    guardian_mac_audit_log(&g_audit_ctx, "mac_init_success", GUARDIAN_SUCCESS);
    return GUARDIAN_SUCCESS;

cleanup:
    mtx_destroy(&g_guardian_mac_mutex);
    return error;
}

/*
 * Thread-safe access permission check with audit logging
 */
guardian_error_t
guardian_mac_check_access(guardian_security_policy_t *policy,
                         uint32_t requested_access,
                         guardian_audit_context_t *audit_ctx)
{
    guardian_error_t error;

    /* Parameter validation */
    if (policy == NULL || audit_ctx == NULL) {
        return GUARDIAN_E_INVALID_PARAM;
    }

    /* Acquire mutex with deadlock prevention */
    if (mtx_trylock(&g_guardian_mac_mutex) != 0) {
        if (mtx_lock(&g_guardian_mac_mutex, 100) != 0) {
            guardian_mac_audit_log(audit_ctx, "mac_lock_failed", GUARDIAN_E_THREAD_SAFETY);
            return GUARDIAN_E_THREAD_SAFETY;
        }
    }

    /* Validate policy with memory barrier */
    atomic_thread_fence(memory_order_acquire);
    error = guardian_mac_validate_policy(policy);
    if (error != GUARDIAN_SUCCESS) {
        guardian_mac_audit_log(audit_ctx, "mac_policy_invalid", error);
        goto cleanup;
    }

    /* Check access permissions */
    if ((policy->flags & GUARDIAN_POLICY_ENFORCING) == 0) {
        error = GUARDIAN_E_PERMISSION;
        guardian_mac_audit_log(audit_ctx, "mac_policy_not_enforcing", error);
        goto cleanup;
    }

    /* Evaluate access request against policy */
    if ((requested_access & policy->flags) != requested_access) {
        error = GUARDIAN_E_PERMISSION;
        guardian_mac_audit_log(audit_ctx, "mac_access_denied", error);
        goto cleanup;
    }

    /* Log successful access */
    guardian_mac_audit_log(audit_ctx, "mac_access_granted", GUARDIAN_SUCCESS);
    error = GUARDIAN_SUCCESS;

cleanup:
    /* Release mutex with memory barrier */
    atomic_thread_fence(memory_order_release);
    mtx_unlock(&g_guardian_mac_mutex);
    return error;
}

/*
 * Internal helper to validate MAC policy
 */
static guardian_error_t
guardian_mac_validate_policy(const guardian_security_policy_t *policy)
{
    if (policy->id >= GUARDIAN_MAC_MAX_POLICIES) {
        return GUARDIAN_E_INVALID_PARAM;
    }

    if ((policy->flags & GUARDIAN_POLICY_ENABLED) == 0) {
        return GUARDIAN_E_PERMISSION;
    }

    return GUARDIAN_SUCCESS;
}

/*
 * Internal helper for audit logging with thread safety
 */
static void
guardian_mac_audit_log(const guardian_audit_context_t *ctx,
                      const char *event,
                      uint32_t result)
{
    if (ctx == NULL || event == NULL) {
        return;
    }

    /* Acquire mutex for audit logging */
    mtx_lock(&g_guardian_mac_mutex);

    /* Log audit event with memory barrier */
    atomic_thread_fence(memory_order_acquire);
    g_guardian_mac_policy.mpo_audit_event(ctx, event, result);
    atomic_thread_fence(memory_order_release);

    mtx_unlock(&g_guardian_mac_mutex);
}

/*
 * Internal helper to cache MAC label with thread safety
 */
static guardian_error_t
guardian_mac_cache_label(guardian_mac_label_t *label)
{
    if (label == NULL) {
        return GUARDIAN_E_INVALID_PARAM;
    }

    mtx_lock(&g_guardian_mac_mutex);

    /* Find empty cache slot with memory barrier */
    atomic_thread_fence(memory_order_acquire);
    for (int i = 0; i < GUARDIAN_MAC_MAX_LABELS; i++) {
        if ((g_guardian_mac_label_cache[i].flags & GUARDIAN_MAC_LABEL_VALID) == 0) {
            memcpy(&g_guardian_mac_label_cache[i], label, sizeof(guardian_mac_label_t));
            atomic_thread_fence(memory_order_release);
            mtx_unlock(&g_guardian_mac_mutex);
            return GUARDIAN_SUCCESS;
        }
    }

    mtx_unlock(&g_guardian_mac_mutex);
    return GUARDIAN_E_BUSY;
}