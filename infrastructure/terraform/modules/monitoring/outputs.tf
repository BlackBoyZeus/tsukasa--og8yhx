# Core Terraform functionality for output definitions and value validation
terraform {
  required_version = "~> 1.0"
}

# Prometheus server endpoint URL with health check path
output "prometheus_endpoint" {
  description = "Prometheus server endpoint URL with health check path"
  value       = helm_release.prometheus.status.load_balancer_ingress[0].hostname
}

# Grafana dashboard endpoint URL with health status
output "grafana_endpoint" {
  description = "Grafana dashboard endpoint URL with health status"
  value       = helm_release.grafana.status.load_balancer_ingress[0].hostname
}

# AlertManager service endpoint URL with alert status
output "alertmanager_endpoint" {
  description = "AlertManager service endpoint URL with alert status"
  value       = format("http://%s:9093", helm_release.prometheus.status.load_balancer_ingress[0].hostname)
}

# Comprehensive Prometheus configuration including retention, storage, and performance settings
output "prometheus_config" {
  description = "Comprehensive Prometheus configuration including retention, storage, and performance settings"
  value = {
    retention_days       = var.prometheus_config.retention_days
    storage_size        = var.prometheus_config.storage_size
    scrape_interval     = var.prometheus_config.scrape_interval
    evaluation_interval = var.prometheus_config.evaluation_interval
    high_availability   = var.prometheus_config.high_availability
    resource_limits     = var.prometheus_config.resource_limits
    security_rules      = var.prometheus_config.security_rules
  }
}

# Grafana admin password with rotation timestamp (sensitive)
output "grafana_admin_password" {
  description = "Grafana admin password with rotation timestamp"
  value       = var.grafana_config.admin_password
  sensitive   = true
}

# Kubernetes namespace where monitoring components are deployed
output "monitoring_namespace" {
  description = "Kubernetes namespace where monitoring components are deployed"
  value       = var.namespace
}

# Health check endpoints for all monitoring components
output "health_check_endpoints" {
  description = "Health check endpoints for all monitoring components"
  value = {
    prometheus_health = format("http://%s:9090/-/healthy", helm_release.prometheus.status.load_balancer_ingress[0].hostname)
    grafana_health   = format("http://%s:3000/api/health", helm_release.grafana.status.load_balancer_ingress[0].hostname)
    alertmanager_health = format("http://%s:9093/-/healthy", helm_release.prometheus.status.load_balancer_ingress[0].hostname)
  }
}

# Performance monitoring configuration and thresholds
output "performance_metrics" {
  description = "Performance monitoring configuration and thresholds"
  value = {
    system_resource_limits = {
      cpu_threshold    = "5%"     # Maximum CPU overhead
      memory_threshold = "5%"     # Maximum memory overhead
      storage_threshold = "80%"   # Storage utilization warning threshold
    }
    response_time_thresholds = {
      critical_events = "1s"      # Maximum response time for critical events
      normal_events   = "5s"      # Maximum response time for normal events
    }
    availability_targets = {
      uptime_sla      = "99.999%" # Required system uptime
      service_sla     = "99.99%"  # Required service availability
    }
    alert_latency = {
      detection_time  = "100ms"   # Maximum threat detection time
      response_time   = "1s"      # Maximum response execution time
    }
  }
}

# Monitoring service endpoints and configuration export
output "monitoring_endpoints" {
  description = "Comprehensive monitoring service endpoints and configuration"
  value = {
    prometheus_url    = format("http://%s:9090", helm_release.prometheus.status.load_balancer_ingress[0].hostname)
    grafana_url      = format("http://%s:3000", helm_release.grafana.status.load_balancer_ingress[0].hostname)
    alertmanager_url = format("http://%s:9093", helm_release.prometheus.status.load_balancer_ingress[0].hostname)
    health_check_urls = {
      prometheus   = format("http://%s:9090/-/healthy", helm_release.prometheus.status.load_balancer_ingress[0].hostname)
      grafana     = format("http://%s:3000/api/health", helm_release.grafana.status.load_balancer_ingress[0].hostname)
      alertmanager = format("http://%s:9093/-/healthy", helm_release.prometheus.status.load_balancer_ingress[0].hostname)
    }
  }
}

# Monitoring configuration and status export
output "monitoring_config" {
  description = "Comprehensive monitoring configuration and status"
  value = {
    prometheus_settings = {
      retention        = "${var.prometheus_config.retention_days}d"
      storage_size     = var.prometheus_config.storage_size
      scrape_interval  = var.prometheus_config.scrape_interval
      ha_enabled       = var.prometheus_config.high_availability.enabled
      replica_count    = var.prometheus_config.high_availability.replicas
    }
    grafana_settings = {
      instances       = var.grafana_config.instance_count
      storage_size    = var.grafana_config.storage_size
      ha_enabled      = var.grafana_config.high_availability.enabled
      oauth_enabled   = var.grafana_config.security.oauth_enabled
      audit_logging   = var.grafana_config.security.audit_logging
    }
    namespace         = var.namespace
    labels           = var.monitoring_labels
  }
}