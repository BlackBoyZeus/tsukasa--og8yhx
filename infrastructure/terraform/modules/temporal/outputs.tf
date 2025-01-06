# Terraform outputs configuration for Temporal.io workflow engine module
# Version: 1.0
# Last Updated: 2024-01

# Namespace output for service discovery and integration
output "temporal_namespace" {
  description = "Kubernetes namespace where Temporal.io is deployed"
  value       = kubernetes_namespace.temporal.metadata[0].name
  sensitive   = false
}

# Service endpoint for internal system integration
output "temporal_endpoint" {
  description = "Internal service endpoint for Temporal.io frontend"
  value       = "temporal-frontend.${kubernetes_namespace.temporal.metadata[0].name}.svc.cluster.local:7233"
  sensitive   = false
}

# Web UI endpoint for administrative access
output "temporal_ui_endpoint" {
  description = "Web UI endpoint for Temporal.io administration"
  value       = "temporal-web.${kubernetes_namespace.temporal.metadata[0].name}.svc.cluster.local:8080"
  sensitive   = false
}

# Encryption status and configuration details
output "temporal_encryption_status" {
  description = "Encryption configuration status for Temporal.io"
  value = {
    enabled         = var.security_config.encryption_enabled
    tls_enabled     = var.security_config.tls_enabled
    mtls_required   = var.security_config.mtls_required
    min_tls_version = var.security_config.min_tls_version
    hsm_integrated  = var.hsm_integration.enabled
    key_identifier  = var.hsm_integration.enabled ? var.hsm_integration.key_identifier : ""
  }
  sensitive = true
}

# Monitoring configuration and endpoints
output "temporal_monitoring" {
  description = "Monitoring configuration details"
  value = {
    prometheus_enabled = var.monitoring_config.prometheus_enabled
    grafana_enabled   = var.monitoring_config.grafana_integration
    metrics_endpoint  = "temporal-metrics.${kubernetes_namespace.temporal.metadata[0].name}.svc.cluster.local:9090"
    retention_days    = var.monitoring_config.metrics_retention_days
    alert_thresholds = {
      cpu_percent    = var.monitoring_config.alert_config.cpu_threshold_percent
      memory_percent = var.monitoring_config.alert_config.memory_threshold_percent
      latency_ms     = var.monitoring_config.alert_config.latency_threshold_ms
    }
  }
  sensitive = false
}

# Deployment status and configuration
output "deployment_status" {
  description = "Current status of the Temporal.io deployment"
  value = {
    version         = helm_release.temporal.version
    status          = helm_release.temporal.status
    instance_count  = var.instance_count
    environment     = var.environment
    resource_limits = {
      cpu_request    = var.resource_limits.cpu_request
      cpu_limit      = var.resource_limits.cpu_limit
      memory_request = var.resource_limits.memory_request
      memory_limit   = var.resource_limits.memory_limit
    }
    storage_config = {
      size           = var.storage_config.size
      storage_class  = var.storage_config.storage_class
      backup_enabled = var.storage_config.backup_enabled
      retention_days = var.storage_config.retention_days
    }
  }
  sensitive = false
}