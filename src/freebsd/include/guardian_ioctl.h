/*
 * guardian_ioctl.h - IOCTL interface definitions for Guardian security system
 *
 * Copyright (c) 2024. All rights reserved.
 *
 * This header defines the IOCTL command interface for the Guardian FreeBSD kernel module,
 * providing secure userspace-kernel communication with version control, type safety,
 * and hardware management capabilities.
 */

#ifndef _GUARDIAN_IOCTL_H_
#define _GUARDIAN_IOCTL_H_

#include <sys/ioccom.h>
#include <sys/types.h>
#include "guardian_types.h"
#include "guardian_errors.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * IOCTL interface version information
 */
#define GUARDIAN_IOC_MAGIC          0xAF
#define GUARDIAN_IOC_VERSION_MAJOR  1
#define GUARDIAN_IOC_VERSION_MINOR  0
#define GUARDIAN_IOC_VERSION_PATCH  0

/*
 * Version and capability information structure
 */
typedef struct guardian_ioctl_version {
    uint32_t major;                  /* Major version number */
    uint32_t minor;                  /* Minor version number */
    uint32_t patch;                  /* Patch level */
    guardian_capability_mask_t capabilities; /* Supported capabilities */
} guardian_ioctl_version_t;

/*
 * IOCTL command metadata structure for validation
 */
typedef struct guardian_ioctl_cmd_info {
    uint32_t cmd;                    /* IOCTL command code */
    guardian_capability_mask_t required_capabilities; /* Required capabilities */
    guardian_ioctl_version_t min_version; /* Minimum required version */
} guardian_ioctl_cmd_info_t;

/*
 * IOCTL command definitions
 * Note: All commands use type-safe _IOR/_IOW/_IOWR macros
 */
#define GUARDIAN_IOC_GET_VERSION     _IOR(GUARDIAN_IOC_MAGIC, 0, guardian_ioctl_version_t)
#define GUARDIAN_IOC_GET_STATE       _IOR(GUARDIAN_IOC_MAGIC, 1, guardian_system_state_t)
#define GUARDIAN_IOC_SET_POLICY      _IOW(GUARDIAN_IOC_MAGIC, 2, guardian_security_policy_t)
#define GUARDIAN_IOC_GET_POLICY      _IOR(GUARDIAN_IOC_MAGIC, 3, guardian_security_policy_t)
#define GUARDIAN_IOC_MAP_REGION      _IOWR(GUARDIAN_IOC_MAGIC, 4, guardian_memory_region_t)
#define GUARDIAN_IOC_UNMAP_REGION    _IOW(GUARDIAN_IOC_MAGIC, 5, guardian_handle_t)
#define GUARDIAN_IOC_GET_HARDWARE_INFO _IOR(GUARDIAN_IOC_MAGIC, 6, guardian_hardware_info_t)
#define GUARDIAN_IOC_SET_CAPABILITIES _IOW(GUARDIAN_IOC_MAGIC, 7, guardian_capability_mask_t)
#define GUARDIAN_IOC_GET_CAPABILITIES _IOR(GUARDIAN_IOC_MAGIC, 8, guardian_capability_mask_t)

/*
 * Command metadata array for runtime validation
 */
static const guardian_ioctl_cmd_info_t GUARDIAN_IOC_COMMANDS[] = {
    {
        .cmd = GUARDIAN_IOC_GET_VERSION,
        .required_capabilities = 0, /* No special capabilities required */
        .min_version = {0, 0, 0, 0}
    },
    {
        .cmd = GUARDIAN_IOC_GET_STATE,
        .required_capabilities = GUARDIAN_CAP_TPM,
        .min_version = {1, 0, 0, GUARDIAN_CAP_TPM}
    },
    {
        .cmd = GUARDIAN_IOC_SET_POLICY,
        .required_capabilities = GUARDIAN_CAP_SECURE_BOOT | GUARDIAN_CAP_TPM,
        .min_version = {1, 0, 0, GUARDIAN_CAP_SECURE_BOOT | GUARDIAN_CAP_TPM}
    },
    {
        .cmd = GUARDIAN_IOC_GET_POLICY,
        .required_capabilities = GUARDIAN_CAP_TPM,
        .min_version = {1, 0, 0, GUARDIAN_CAP_TPM}
    },
    {
        .cmd = GUARDIAN_IOC_MAP_REGION,
        .required_capabilities = GUARDIAN_CAP_IOMMU | GUARDIAN_CAP_ENCRYPTION,
        .min_version = {1, 0, 0, GUARDIAN_CAP_IOMMU | GUARDIAN_CAP_ENCRYPTION}
    },
    {
        .cmd = GUARDIAN_IOC_UNMAP_REGION,
        .required_capabilities = GUARDIAN_CAP_IOMMU,
        .min_version = {1, 0, 0, GUARDIAN_CAP_IOMMU}
    },
    {
        .cmd = GUARDIAN_IOC_GET_HARDWARE_INFO,
        .required_capabilities = 0, /* No special capabilities required */
        .min_version = {1, 0, 0, 0}
    },
    {
        .cmd = GUARDIAN_IOC_SET_CAPABILITIES,
        .required_capabilities = GUARDIAN_CAP_TPM | GUARDIAN_CAP_SECURE_BOOT,
        .min_version = {1, 0, 0, GUARDIAN_CAP_TPM | GUARDIAN_CAP_SECURE_BOOT}
    },
    {
        .cmd = GUARDIAN_IOC_GET_CAPABILITIES,
        .required_capabilities = 0, /* No special capabilities required */
        .min_version = {1, 0, 0, 0}
    }
};

#ifdef __cplusplus
}
#endif

#endif /* _GUARDIAN_IOCTL_H_ */