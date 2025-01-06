# Terraform variables configuration for Temporal.io workflow engine module
# Version: 1.0
# Last Updated: 2024-01

# Environment configuration with strict validation
variable "environment" {
  description = "Deployment environment identifier with strict validation"
  type        = string
  validation {
    condition     = can(regex("^(production|staging|development)$", var.environment))
    error_message = "Environment must be one of: production, staging, development"
  }
}

# Namespace configuration
variable "namespace" {
  description = "Kubernetes namespace for isolated Temporal.io deployment"
  type        = string
  default     = "temporal-system"
}

# High availability configuration
variable "instance_count" {
  description = "Number of Temporal.io server replicas for high availability"
  type        = number
  default     = 3
  validation {
    condition     = var.instance_count >= 3 && var.instance_count <= 10
    error_message = "Instance count must be between 3 and 10 for HA"
  }
}

# Storage configuration
variable "storage_config" {
  description = "Enhanced storage configuration for Temporal.io persistence"
  type = object({
    size            = string
    storage_class   = string
    backup_enabled  = bool
    retention_days  = number
  })
  default = {
    size            = "100Gi"
    storage_class   = "premium-rwo"
    backup_enabled  = true
    retention_days  = 30
  }
}

# Security configuration
variable "security_config" {
  description = "Comprehensive security configuration"
  type = object({
    encryption_enabled        = bool
    tls_enabled              = bool
    mtls_required            = bool
    min_tls_version          = string
    certificate_rotation_days = number
  })
  default = {
    encryption_enabled        = true
    tls_enabled              = true
    mtls_required            = true
    min_tls_version          = "1.3"
    certificate_rotation_days = 30
  }
}

# HSM integration configuration
variable "hsm_integration" {
  description = "Enhanced HSM integration configuration"
  type = object({
    enabled              = bool
    key_identifier       = string
    region              = string
    rotation_period_days = number
    backup_key_enabled   = bool
  })
  default = {
    enabled              = true
    key_identifier       = ""
    region              = "us-west-2"
    rotation_period_days = 90
    backup_key_enabled   = true
  }
}

# Monitoring configuration
variable "monitoring_config" {
  description = "Comprehensive monitoring configuration"
  type = object({
    prometheus_enabled     = bool
    grafana_integration   = bool
    metrics_retention_days = number
    alert_config = object({
      cpu_threshold_percent    = number
      memory_threshold_percent = number
      latency_threshold_ms     = number
    })
  })
  default = {
    prometheus_enabled     = true
    grafana_integration   = true
    metrics_retention_days = 30
    alert_config = {
      cpu_threshold_percent    = 80
      memory_threshold_percent = 85
      latency_threshold_ms     = 100
    }
  }
}

# Resource limits configuration
variable "resource_limits" {
  description = "Detailed resource limits configuration"
  type = object({
    cpu_request           = string
    cpu_limit            = string
    memory_request       = string
    memory_limit         = string
    enable_vertical_scaling = bool
  })
  default = {
    cpu_request           = "1"
    cpu_limit            = "2"
    memory_request       = "2Gi"
    memory_limit         = "4Gi"
    enable_vertical_scaling = true
  }
}