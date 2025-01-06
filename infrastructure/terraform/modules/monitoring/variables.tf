# Core Terraform functionality for variable definitions and validation rules
terraform {
  required_version = "~> 1.0"
}

# Kubernetes namespace for monitoring components with strict isolation
variable "namespace" {
  description = "Kubernetes namespace for monitoring components with strict isolation"
  type        = string
  default     = "guardian-monitoring"

  validation {
    condition     = can(regex("^[a-z0-9-]+$", var.namespace))
    error_message = "Namespace must consist of lowercase alphanumeric characters or '-'"
  }
}

# Comprehensive Prometheus server configuration for metrics collection and alerting
variable "prometheus_config" {
  description = "Comprehensive Prometheus server configuration for metrics collection and alerting"
  type = object({
    retention_days      = number
    storage_size       = string
    scrape_interval    = string
    evaluation_interval = string
    high_availability  = object({
      enabled  = bool
      replicas = number
    })
    resource_limits = object({
      cpu    = string
      memory = string
    })
    security_rules = object({
      network_policy_enabled = bool
      pod_security_policy   = string
    })
  })

  default = {
    retention_days      = 90
    storage_size       = "50Gi"
    scrape_interval    = "15s"
    evaluation_interval = "15s"
    high_availability  = {
      enabled  = true
      replicas = 2
    }
    resource_limits = {
      cpu    = "2000m"
      memory = "4Gi"
    }
    security_rules = {
      network_policy_enabled = true
      pod_security_policy   = "restricted"
    }
  }

  validation {
    condition     = var.prometheus_config.retention_days >= 30 && can(regex("^[0-9]+s$", var.prometheus_config.scrape_interval)) && tonumber(replace(var.prometheus_config.scrape_interval, "s", "")) <= 30
    error_message = "Retention must be >= 30 days and scrape interval <= 30s for SLA compliance"
  }
}

# Enhanced Grafana configuration for visualization and alerting
variable "grafana_config" {
  description = "Enhanced Grafana configuration for visualization and alerting"
  type = object({
    instance_count = number
    storage_size  = string
    admin_password = string
    high_availability = object({
      enabled              = bool
      load_balancer_enabled = bool
    })
    security = object({
      oauth_enabled     = bool
      session_timeout  = string
      audit_logging    = bool
    })
    dashboards = object({
      auto_provision   = bool
      update_interval = string
    })
  })

  default = {
    instance_count = 2
    storage_size  = "20Gi"
    admin_password = null
    high_availability = {
      enabled              = true
      load_balancer_enabled = true
    }
    security = {
      oauth_enabled     = true
      session_timeout  = "8h"
      audit_logging    = true
    }
    dashboards = {
      auto_provision   = true
      update_interval = "1h"
    }
  }

  validation {
    condition     = var.grafana_config.instance_count > 0
    error_message = "At least one Grafana instance is required for monitoring"
  }
}

# AlertManager configuration for comprehensive notification routing
variable "alert_manager_config" {
  description = "AlertManager configuration for comprehensive notification routing"
  type = object({
    notification_endpoints = list(string)
    slack_webhook         = string
    pagerduty_key        = string
    email_config         = object({
      smtp_host     = string
      smtp_port     = number
      from_address  = string
      to_addresses  = list(string)
    })
    grouping_rules = object({
      security_alerts    = string
      performance_alerts = string
      system_alerts     = string
    })
    inhibition_rules = object({
      enabled        = bool
      max_duplicates = number
    })
  })

  default = {
    notification_endpoints = []
    slack_webhook         = null
    pagerduty_key        = null
    email_config         = null
    grouping_rules = {
      security_alerts    = "5m"
      performance_alerts = "10m"
      system_alerts     = "15m"
    }
    inhibition_rules = {
      enabled        = true
      max_duplicates = 3
    }
  }

  sensitive = true
}

# Detailed metrics retention configuration by type
variable "metrics_retention" {
  description = "Detailed metrics retention configuration by type"
  type = object({
    system_metrics      = string
    security_metrics    = string
    performance_metrics = string
    audit_metrics      = string
    ml_model_metrics   = string
  })

  default = {
    system_metrics      = "30d"
    security_metrics    = "90d"
    performance_metrics = "60d"
    audit_metrics      = "365d"
    ml_model_metrics   = "180d"
  }

  validation {
    condition     = can(regex("^[0-9]+d$", var.metrics_retention.system_metrics)) && can(regex("^[0-9]+d$", var.metrics_retention.security_metrics))
    error_message = "Metrics retention periods must be specified in days with format '<number>d'"
  }
}

# Comprehensive labels for monitoring resource identification
variable "monitoring_labels" {
  description = "Comprehensive labels for monitoring resource identification"
  type        = map(string)
  default = {
    app              = "guardian-monitoring"
    component        = "observability"
    managed-by       = "terraform"
    security-tier    = "critical"
    compliance-level = "high"
  }

  validation {
    condition     = length(var.monitoring_labels) > 0
    error_message = "At least one monitoring label must be specified"
  }
}