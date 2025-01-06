# Terraform outputs configuration for AI Guardian system
# Exposes critical infrastructure endpoints and configurations
# Version: 1.0

# Monitoring service endpoints for system observability
output "monitoring_endpoints" {
  description = "Monitoring service endpoints"
  value = {
    prometheus    = module.monitoring.prometheus_endpoint
    grafana      = module.monitoring.grafana_endpoint
    alertmanager = module.monitoring.alertmanager_endpoint
  }
}

# HSM cluster configuration and access details
# Marked as sensitive to prevent exposure of security-critical information
output "hsm_cluster" {
  description = "HSM cluster configuration and access details"
  sensitive   = true
  value = {
    cluster_id          = aws_cloudhsm_v2_cluster.guardian_hsm.id
    cluster_endpoint    = aws_cloudhsm_v2_cluster.guardian_hsm.cluster_endpoint
    cluster_certificates = aws_cloudhsm_v2_cluster.guardian_hsm.cluster_certificates
  }
}

# Temporal.io service endpoints for workflow orchestration
output "temporal_endpoints" {
  description = "Temporal.io service endpoints for workflow orchestration"
  value = {
    frontend_endpoint = module.temporal.frontend_endpoint
    worker_endpoint  = module.temporal.worker_endpoint
    namespace       = module.temporal.namespace
  }
}

# Additional observability endpoints for comprehensive monitoring
output "observability_endpoints" {
  description = "Additional observability endpoints for comprehensive monitoring"
  value = {
    metrics_endpoint = module.monitoring.metrics_endpoint
    logs_endpoint    = module.monitoring.logs_endpoint
    traces_endpoint  = module.monitoring.traces_endpoint
  }
}