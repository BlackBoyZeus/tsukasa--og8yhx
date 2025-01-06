# Core Terraform functionality for variable definitions and validation
terraform {
  required_version = "~> 1.0"
}

# HSM cluster identifier variable
variable "hsm_cluster_id" {
  description = "Unique identifier for the CloudHSM cluster used for gaming console key management"
  type        = string
  validation {
    condition     = can(regex("^[a-zA-Z0-9-]+$", var.hsm_cluster_id))
    error_message = "HSM cluster ID must contain only alphanumeric characters and hyphens for security tracking"
  }
}

# Subnet configuration for HSM deployment
variable "hsm_subnet_ids" {
  description = "List of subnet IDs where HSM instances will be deployed for high availability"
  type        = list(string)
  validation {
    condition     = length(var.hsm_subnet_ids) >= 2
    error_message = "At least two subnet IDs must be provided for high availability requirements"
  }
}

# HSM instance type configuration
variable "hsm_type" {
  description = "Type of HSM instance to deploy - currently limited to hsm1.medium for gaming console requirements"
  type        = string
  default     = "hsm1.medium"
  validation {
    condition     = contains(["hsm1.medium"], var.hsm_type)
    error_message = "Only hsm1.medium type is supported for gaming console HSM infrastructure"
  }
}

# Backup retention configuration
variable "backup_retention_days" {
  description = "Number of days to retain HSM backups for compliance and recovery"
  type        = number
  default     = 90
  validation {
    condition     = var.backup_retention_days >= 7 && var.backup_retention_days <= 379
    error_message = "Backup retention must be between 7 and 379 days per security policy"
  }
}

# Cryptographic algorithm configuration
variable "key_algorithm" {
  description = "Cryptographic algorithm for key generation in HSM, supporting RSA 2048/4096"
  type        = string
  default     = "RSA_4096"
  validation {
    condition     = contains(["RSA_2048", "RSA_4096"], var.key_algorithm)
    error_message = "Key algorithm must be either RSA_2048 or RSA_4096 for secure key operations"
  }
}

# Automatic backup configuration
variable "enable_auto_backup" {
  description = "Enable automatic backup of HSM cluster for disaster recovery"
  type        = bool
  default     = true
}

# Resource tagging configuration
variable "tags" {
  description = "Tags to apply to HSM resources for resource tracking and compliance"
  type        = map(string)
  default = {
    Project       = "AI Guardian"
    ManagedBy     = "Terraform"
    SecurityLevel = "Critical"
    Environment   = "Production"
  }
}

# Local variable definitions for HSM configuration defaults
locals {
  hsm_defaults = {
    backup_schedule = "cron(0 5 ? * * *)"
    key_specs = {
      rsa_2048 = {
        type   = "RSA"
        length = 2048
        usage  = "SIGN_VERIFY"
      }
      rsa_4096 = {
        type   = "RSA"
        length = 4096
        usage  = "ENCRYPT_DECRYPT"
      }
    }
    tpm_integration = {
      mode           = "secure_boot"
      key_hierarchy = "endorsement"
    }
  }
}