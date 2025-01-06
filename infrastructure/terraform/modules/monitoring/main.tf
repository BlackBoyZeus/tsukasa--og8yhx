# Core Terraform configuration with required providers
terraform {
  required_version = "~> 1.0"
  required_providers {
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.0"
    }
    helm = {
      source  = "hashicorp/helm"
      version = "~> 2.0"
    }
  }
}

# Local variables for common configurations
locals {
  monitoring_labels = {
    app         = "guardian-monitoring"
    component   = "observability"
    managed-by  = "terraform"
    environment = "production"
    criticality = "high"
  }

  common_annotations = {
    "prometheus.io/scrape"        = "true"
    "prometheus.io/port"          = "9090"
    "security.guardian.io/encrypted" = "true"
    "backup.guardian.io/enabled"  = "true"
  }
}

# Prometheus deployment using Helm
resource "helm_release" "prometheus" {
  name       = "prometheus"
  repository = "https://prometheus-community.github.io/helm-charts"
  chart      = "prometheus"
  namespace  = var.namespace
  version    = "15.0.0"  # Specify exact version for production stability

  values = [
    yamlencode({
      server = {
        retention           = "${var.prometheus_config.retention_days}d"
        persistentVolume = {
          size = var.prometheus_config.storage_size
        }
        global = {
          scrape_interval     = var.prometheus_config.scrape_interval
          evaluation_interval = var.prometheus_config.evaluation_interval
        }
        replicaCount = var.prometheus_config.high_availability.enabled ? var.prometheus_config.high_availability.replicas : 1
        resources = {
          limits = var.prometheus_config.resource_limits
        }
        securityContext = {
          runAsNonRoot = true
          runAsUser    = 65534  # nobody user
        }
        podSecurityPolicy = {
          enabled = true
        }
      }
      networkPolicy = {
        enabled = var.prometheus_config.security_rules.network_policy_enabled
      }
      alertmanager = {
        enabled = true
        config  = {
          global = {
            resolve_timeout = "5m"
          }
          route = {
            group_by    = ["alertname", "cluster", "service"]
            group_wait  = "30s"
            group_interval = "5m"
            repeat_interval = "12h"
          }
        }
      }
    })
  ]

  set {
    name  = "server.extraLabels"
    value = jsonencode(local.monitoring_labels)
  }
}

# Grafana deployment using Helm
resource "helm_release" "grafana" {
  name       = "grafana"
  repository = "https://grafana.github.io/helm-charts"
  chart      = "grafana"
  namespace  = var.namespace
  version    = "6.32.0"  # Specify exact version for production stability

  values = [
    yamlencode({
      replicas = var.grafana_config.instance_count
      persistence = {
        enabled = true
        size    = var.grafana_config.storage_size
      }
      adminPassword = var.grafana_config.admin_password
      
      security = {
        oauth = {
          enabled = var.grafana_config.security.oauth_enabled
        }
        sessionTimeout = var.grafana_config.security.session_timeout
        auditLogging   = var.grafana_config.security.audit_logging
      }

      dashboardProviders = {
        "dashboardproviders.yaml" = {
          apiVersion = 1
          providers = [{
            name = "default"
            orgId = 1
            folder = ""
            type = "file"
            disableDeletion = true
            editable = false
            options = {
              path = "/var/lib/grafana/dashboards"
            }
          }]
        }
      }

      resources = {
        limits = {
          cpu    = "1000m"
          memory = "1Gi"
        }
        requests = {
          cpu    = "500m"
          memory = "512Mi"
        }
      }

      securityContext = {
        runAsUser    = 472  # grafana user
        runAsNonRoot = true
        fsGroup      = 472
      }
    })
  ]

  set {
    name  = "extraLabels"
    value = jsonencode(local.monitoring_labels)
  }
}

# Export monitoring endpoints
output "prometheus_endpoint" {
  description = "Prometheus service endpoint details"
  value = {
    url           = "http://prometheus-server.${var.namespace}.svc.cluster.local:9090"
    health_status = "http://prometheus-server.${var.namespace}.svc.cluster.local:9090/-/healthy"
    metrics_port  = 9090
  }
}

output "grafana_endpoint" {
  description = "Grafana service endpoint details"
  value = {
    url           = "http://grafana.${var.namespace}.svc.cluster.local:3000"
    health_status = "http://grafana.${var.namespace}.svc.cluster.local:3000/api/health"
    admin_port    = 3000
  }
  sensitive = true
}

# Network policies for secure communication
resource "kubernetes_network_policy" "monitoring" {
  metadata {
    name      = "monitoring-network-policy"
    namespace = var.namespace
    labels    = local.monitoring_labels
  }

  spec {
    pod_selector {
      match_labels = local.monitoring_labels
    }

    ingress {
      from {
        namespace_selector {
          match_labels = {
            name = var.namespace
          }
        }
      }
      ports {
        port     = "9090"
        protocol = "TCP"
      }
      ports {
        port     = "3000"
        protocol = "TCP"
      }
    }

    policy_types = ["Ingress"]
  }
}