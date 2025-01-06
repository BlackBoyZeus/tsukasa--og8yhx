# Environment configuration
variable "environment" {
  type        = string
  description = "Deployment environment identifier for the AI Guardian system"
  
  validation {
    condition     = can(regex("^(production|staging)$", lower(var.environment)))
    error_message = "Environment must be either 'production' or 'staging' in lowercase."
  }
}

# Region configuration
variable "region" {
  type        = string
  description = "AWS region for infrastructure deployment with data residency compliance"
  default     = "us-west-2"
  
  validation {
    condition     = can(regex("^(us-west-2|us-east-1|eu-west-1|ap-northeast-1)$", var.region))
    error_message = "Region must be one of: us-west-2, us-east-1, eu-west-1, ap-northeast-1."
  }
}

# VPC CIDR configuration
variable "vpc_cidr" {
  type        = string
  description = "CIDR block for the VPC hosting AI Guardian components"
  default     = "10.0.0.0/16"
  
  validation {
    condition     = can(cidrhost(var.vpc_cidr, 0))
    error_message = "VPC CIDR must be a valid IPv4 CIDR block."
  }
}

# KMS key configuration
variable "kms_key_config" {
  type = object({
    deletion_window_in_days = number
    enable_key_rotation    = bool
    key_usage             = string
    multi_region          = bool
    key_spec             = string
    alias_prefix         = string
    admin_principals     = list(string)
    user_principals      = list(string)
  })
  description = "Enhanced KMS key configuration for data encryption and security"
  sensitive   = true
  
  validation {
    condition     = var.kms_key_config.deletion_window_in_days >= 7 && var.kms_key_config.deletion_window_in_days <= 30
    error_message = "KMS key deletion window must be between 7 and 30 days."
  }
}

# Temporal.io configuration
variable "temporal_config" {
  type = object({
    version              = string
    replica_count        = number
    persistence_size     = string
    monitoring_enabled   = bool
    history_ttl_days    = number
    worker_count        = number
    namespace           = string
    retention_period_days = number
    backup_enabled      = bool
  })
  description = "Temporal.io workflow engine configuration for AI Guardian"
  
  validation {
    condition     = var.temporal_config.replica_count >= 2
    error_message = "Temporal replica count must be at least 2 for high availability."
  }
}

# Monitoring configuration
variable "monitoring_config" {
  type = object({
    prometheus_retention    = string
    grafana_version        = string
    alertmanager_enabled   = bool
    metrics_retention_days = number
    log_level             = string
    alert_channels        = list(string)
    dashboard_enabled     = bool
    custom_metrics_enabled = bool
  })
  description = "Comprehensive monitoring stack configuration"
  
  validation {
    condition     = contains(["debug", "info", "warn", "error"], var.monitoring_config.log_level)
    error_message = "Log level must be one of: debug, info, warn, error."
  }
}

# Resource tagging configuration
variable "tags" {
  type        = map(string)
  description = "Common tags to be applied to all AI Guardian infrastructure resources"
  default = {
    Project          = "AI-Guardian"
    ManagedBy        = "Terraform"
    Environment      = "${var.environment}"
    SecurityLevel    = "High"
    ComplianceLevel  = "Critical"
  }
  
  validation {
    condition     = length(var.tags) > 0
    error_message = "At least one tag must be specified."
  }
}