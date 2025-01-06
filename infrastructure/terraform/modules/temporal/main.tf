# Temporal.io Workflow Engine Infrastructure Configuration
# Version: 1.0
# Last Updated: 2024-01

# Required providers with strict version constraints
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
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

# Local variables for resource naming and tagging
locals {
  resource_prefix = "${var.environment}-temporal"
  common_tags = {
    Project         = "AI Guardian"
    Component       = "Temporal"
    Environment     = var.environment
    ManagedBy       = "Terraform"
    SecurityTier    = "Critical"
    Compliance      = "Required"
    LastUpdated     = timestamp()
  }
}

# Create dedicated namespace for Temporal.io with enhanced security
resource "kubernetes_namespace" "temporal" {
  metadata {
    name = var.namespace
    labels = {
      environment     = var.environment
      managed-by      = "terraform"
      security-tier   = "critical"
      encryption      = "required"
    }
    annotations = {
      "security.kubernetes.io/enforce-mtls"           = "true"
      "monitoring.kubernetes.io/prometheus-enabled"   = "true"
      "vault.hashicorp.com/auto-auth"                = "true"
      "vault.hashicorp.com/tls-secret"               = "temporal-tls"
    }
  }
}

# Deploy Temporal.io using Helm with comprehensive configuration
resource "helm_release" "temporal" {
  name       = "temporal"
  repository = "https://helm.temporal.io"
  chart      = "temporal"
  namespace  = kubernetes_namespace.temporal.metadata[0].name
  version    = "0.20.0"

  values = [
    yamlencode({
      server = {
        replicaCount = var.instance_count
        resources = {
          requests = {
            cpu    = var.resource_limits.cpu_request
            memory = var.resource_limits.memory_request
          }
          limits = {
            cpu    = var.resource_limits.cpu_limit
            memory = var.resource_limits.memory_limit
          }
        }
        security = {
          mtls = {
            enabled  = var.security_config.mtls_required
            provider = "cert-manager"
            minVersion = var.security_config.min_tls_version
          }
          authentication = {
            enabled  = true
            provider = "oidc"
            oidc = {
              issuer     = "https://guardian-auth.example.com"
              clientID   = "temporal-server"
              secretName = "temporal-oidc-secret"
            }
          }
        }
      }
      persistence = {
        enabled      = true
        storageClass = var.storage_config.storage_class
        size         = var.storage_config.size
        backup = {
          enabled        = var.storage_config.backup_enabled
          schedule      = "0 0 * * *"
          retentionDays = var.storage_config.retention_days
        }
      }
      encryption = {
        enabled   = var.security_config.encryption_enabled
        provider  = "aws-kms"
        kmsKeyId  = var.hsm_integration.enabled ? var.hsm_integration.key_identifier : ""
        keyRotation = {
          enabled  = true
          schedule = "${var.hsm_integration.rotation_period_days * 24}h"
        }
      }
      monitoring = {
        enabled = true
        prometheus = {
          enabled = var.monitoring_config.prometheus_enabled
          serviceMonitor = {
            enabled  = true
            interval = "30s"
            labels = {
              release = "prometheus"
            }
          }
          alerting = {
            enabled = true
            rules = [
              {
                name      = "HighCPUUsage"
                threshold = var.monitoring_config.alert_config.cpu_threshold_percent
              },
              {
                name      = "HighMemoryUsage"
                threshold = var.monitoring_config.alert_config.memory_threshold_percent
              },
              {
                name      = "HighLatency"
                threshold = "${var.monitoring_config.alert_config.latency_threshold_ms}ms"
              }
            ]
          }
        }
        grafana = {
          enabled = var.monitoring_config.grafana_integration
          dashboards = {
            enabled = true
          }
        }
      }
    })
  ]

  set_sensitive {
    name  = "server.security.encryption.kmsKeyId"
    value = var.hsm_integration.key_identifier
  }
}

# Export Temporal deployment information
output "temporal_deployment" {
  description = "Temporal.io deployment details"
  value = {
    namespace = kubernetes_namespace.temporal.metadata[0].name
    endpoint  = "temporal.${kubernetes_namespace.temporal.metadata[0].name}.svc.cluster.local:7233"
    security_config = {
      mtls_enabled     = var.security_config.mtls_required
      encryption       = var.security_config.encryption_enabled
      min_tls_version = var.security_config.min_tls_version
    }
    monitoring_endpoints = {
      prometheus = "http://temporal-prometheus:9090"
      grafana    = "http://temporal-grafana:3000"
    }
  }
  sensitive = true
}