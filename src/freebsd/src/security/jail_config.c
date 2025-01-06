/*
 * Guardian System - FreeBSD Jail Configuration Implementation
 * FreeBSD Kernel Module Implementation
 *
 * This module implements secure jail-based isolation for the Guardian system
 * using FreeBSD's jail subsystem with comprehensive resource controls and
 * security policy enforcement.
 */

#include <sys/jail.h>
#include <sys/param.h>
#include <sys/mount.h>
#include <sys/rctl.h>
#include <sys/procdesc.h>
#include "jail_config.h"
#include "guardian_errors.h"

/* Default configuration values */
#define JAIL_DEVFS_RULESET 4
#define DEFAULT_JAIL_PATH "/guardian/jails"
#define MAX_JAIL_PROCESSES 1000
#define DEFAULT_JAIL_MEMORY_LIMIT 4294967296UL /* 4GB */

/* Internal helper functions */
static guardian_error_t validate_jail_path(const char *path);
static guardian_error_t setup_devfs_rules(int jid, uint32_t ruleset);
static guardian_error_t apply_resource_limits(int jid, const struct jail_limits *limits);
static guardian_error_t mount_jail_filesystems(const guardian_jail_config_t *config);

guardian_error_t guardian_jail_init(guardian_jail_config_t *config) {
    if (config == NULL) {
        return GUARDIAN_E_INVALID_PARAM;
    }

    /* Initialize with secure defaults */
    memset(config, 0, sizeof(guardian_jail_config_t));
    
    /* Set default path with proper permissions */
    strlcpy(config->path, DEFAULT_JAIL_PATH, GUARDIAN_JAIL_PATH_MAX);
    
    /* Configure default security policy */
    config->security_policy.flags = GUARDIAN_POLICY_ENABLED | 
                                  GUARDIAN_POLICY_ENFORCING |
                                  GUARDIAN_POLICY_AUDITING;
    config->security_policy.priority = 100;
    
    /* Set conservative resource limits */
    config->resource_limits.maxproc = MAX_JAIL_PROCESSES;
    config->resource_limits.maxmem = DEFAULT_JAIL_MEMORY_LIMIT;
    config->resource_limits.maxcpu = 100; /* 100% of one CPU */
    config->resource_limits.maxfiles = 1024;
    config->resource_limits.maxswap = DEFAULT_JAIL_MEMORY_LIMIT;
    
    /* Configure default flags */
    config->flags = GUARDIAN_JAIL_FLAG_SECURE | 
                   GUARDIAN_JAIL_FLAG_DEVFS;
    
    config->devfs_ruleset = JAIL_DEVFS_RULESET;
    
    return GUARDIAN_SUCCESS;
}

guardian_error_t guardian_jail_create(guardian_jail_config_t *config, int *jid) {
    struct jail j;
    guardian_error_t error;
    
    if (config == NULL || jid == NULL) {
        return GUARDIAN_E_INVALID_PARAM;
    }

    /* Validate configuration */
    error = guardian_jail_validate_config(config);
    if (error != GUARDIAN_SUCCESS) {
        return error;
    }

    /* Create jail directory structure */
    if (mkdir(config->path, 0700) != 0 && errno != EEXIST) {
        return GUARDIAN_E_RESOURCE_LIMIT;
    }

    /* Initialize jail parameters */
    memset(&j, 0, sizeof(j));
    j.version = JAIL_API_VERSION;
    j.path = config->path;
    j.hostname = config->hostname;
    j.jailname = config->name;
    
    /* Set security flags */
    if (config->flags & GUARDIAN_JAIL_FLAG_SECURE) {
        j.flags |= JAIL_SECURITY_LEVEL_3;
    }
    
    /* Create the jail */
    *jid = jail_set(&j, JAIL_CREATE | JAIL_ATTACH, 
                    JAIL_SECURITY_LEVEL_3,
                    JAIL_UPDATE);
    if (*jid < 0) {
        return GUARDIAN_E_RESOURCE_LIMIT;
    }

    /* Setup devfs rules if enabled */
    if (config->flags & GUARDIAN_JAIL_FLAG_DEVFS) {
        error = setup_devfs_rules(*jid, config->devfs_ruleset);
        if (error != GUARDIAN_SUCCESS) {
            guardian_jail_destroy(*jid);
            return error;
        }
    }

    /* Mount required filesystems */
    error = mount_jail_filesystems(config);
    if (error != GUARDIAN_SUCCESS) {
        guardian_jail_destroy(*jid);
        return error;
    }

    /* Apply resource limits */
    error = apply_resource_limits(*jid, &config->resource_limits);
    if (error != GUARDIAN_SUCCESS) {
        guardian_jail_destroy(*jid);
        return error;
    }

    return GUARDIAN_SUCCESS;
}

guardian_error_t guardian_jail_destroy(int jid) {
    if (jid <= 0) {
        return GUARDIAN_E_INVALID_PARAM;
    }

    /* Stop all processes in jail */
    if (jail_remove(jid) != 0) {
        return GUARDIAN_E_RESOURCE_LIMIT;
    }

    /* Clean up devfs rules */
    if (devfs_rule_delete(jid, 0) != 0) {
        /* Continue cleanup despite error */
    }

    /* Remove resource limits */
    rctl_remove_rule_from_jail(jid);

    return GUARDIAN_SUCCESS;
}

guardian_error_t guardian_jail_set_limits(int jid, const struct jail_limits *limits) {
    char rule_str[128];
    
    if (jid <= 0 || limits == NULL) {
        return GUARDIAN_E_INVALID_PARAM;
    }

    /* Set process limit */
    snprintf(rule_str, sizeof(rule_str), 
             "jail:%d:maxproc:%lu", jid, limits->maxproc);
    if (rctl_add_rule(rule_str, 0, 0) != 0) {
        return GUARDIAN_E_RESOURCE_LIMIT;
    }

    /* Set memory limit */
    snprintf(rule_str, sizeof(rule_str),
             "jail:%d:vmemoryuse:%lu", jid, limits->maxmem);
    if (rctl_add_rule(rule_str, 0, 0) != 0) {
        return GUARDIAN_E_RESOURCE_LIMIT;
    }

    /* Set CPU limit */
    snprintf(rule_str, sizeof(rule_str),
             "jail:%d:pcpu:%lu", jid, limits->maxcpu);
    if (rctl_add_rule(rule_str, 0, 0) != 0) {
        return GUARDIAN_E_RESOURCE_LIMIT;
    }

    /* Set file descriptor limit */
    snprintf(rule_str, sizeof(rule_str),
             "jail:%d:openfiles:%lu", jid, limits->maxfiles);
    if (rctl_add_rule(rule_str, 0, 0) != 0) {
        return GUARDIAN_E_RESOURCE_LIMIT;
    }

    return GUARDIAN_SUCCESS;
}

/* Internal helper function implementations */

static guardian_error_t validate_jail_path(const char *path) {
    struct stat st;
    
    if (path == NULL || strlen(path) >= GUARDIAN_JAIL_PATH_MAX) {
        return GUARDIAN_E_INVALID_PARAM;
    }

    if (stat(path, &st) == 0) {
        if (!S_ISDIR(st.st_mode) || (st.st_mode & 0777) != 0700) {
            return GUARDIAN_E_INVALID_PARAM;
        }
    }

    return GUARDIAN_SUCCESS;
}

static guardian_error_t setup_devfs_rules(int jid, uint32_t ruleset) {
    if (devfs_rule_path(ruleset, "path", "hide") != 0) {
        return GUARDIAN_E_RESOURCE_LIMIT;
    }

    /* Allow only essential devices */
    devfs_rule_path(ruleset, "path", "null", "unhide");
    devfs_rule_path(ruleset, "path", "zero", "unhide");
    devfs_rule_path(ruleset, "path", "random", "unhide");
    devfs_rule_path(ruleset, "path", "urandom", "unhide");

    return GUARDIAN_SUCCESS;
}

static guardian_error_t apply_resource_limits(int jid, const struct jail_limits *limits) {
    if (limits == NULL) {
        return GUARDIAN_E_INVALID_PARAM;
    }

    /* Validate limits */
    if (limits->maxproc > MAX_JAIL_PROCESSES ||
        limits->maxmem > DEFAULT_JAIL_MEMORY_LIMIT * 2) {
        return GUARDIAN_E_RESOURCE_LIMIT;
    }

    return guardian_jail_set_limits(jid, limits);
}

static guardian_error_t mount_jail_filesystems(const guardian_jail_config_t *config) {
    if (config == NULL) {
        return GUARDIAN_E_INVALID_PARAM;
    }

    /* Mount devfs if enabled */
    if (config->flags & GUARDIAN_JAIL_FLAG_DEVFS) {
        char devfs_path[GUARDIAN_JAIL_PATH_MAX];
        snprintf(devfs_path, sizeof(devfs_path), "%s/dev", config->path);
        
        if (mount("devfs", devfs_path, 0, NULL) != 0) {
            return GUARDIAN_E_MOUNT_FAILED;
        }
    }

    return GUARDIAN_SUCCESS;
}