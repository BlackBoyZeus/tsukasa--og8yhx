# Configure Terraform version and required providers
terraform {
  required_version = ">= 1.0.0"
  
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

# AWS Provider configuration with enhanced security tags
provider "aws" {
  region = var.region
  
  default_tags {
    tags = {
      Environment         = var.environment
      Project            = "AI-Guardian"
      ManagedBy          = "Terraform"
      SecurityLevel      = "High"
      DataClassification = "Sensitive"
      ComplianceRequired = "True"
    }
  }
}

# Data sources for EKS cluster information
data "aws_eks_cluster" "guardian" {
  name = "guardian-${var.environment}"
  
  tags = {
    SecurityLevel      = "High"
    DataClassification = "Sensitive"
  }
}

data "aws_eks_cluster_auth" "guardian" {
  name = "guardian-${var.environment}"
}

# Kubernetes provider configuration with enhanced security settings
provider "kubernetes" {
  host                               = data.aws_eks_cluster.guardian.endpoint
  cluster_ca_certificate             = base64decode(data.aws_eks_cluster.guardian.certificate_authority[0].data)
  token                             = data.aws_eks_cluster_auth.guardian.token
  client_certificate_rotation_enabled = true
  client_key_rotation_enabled        = true
  tls_server_name                    = "guardian-${var.environment}.eks.amazonaws.com"
  
  exec {
    api_version = "client.authentication.k8s.io/v1beta1"
    command     = "aws"
    args        = ["eks", "get-token", "--cluster-name", "guardian-${var.environment}"]
  }
}

# Helm provider configuration with secure repository management
provider "helm" {
  kubernetes {
    host                   = data.aws_eks_cluster.guardian.endpoint
    cluster_ca_certificate = base64decode(data.aws_eks_cluster.guardian.certificate_authority[0].data)
    token                 = data.aws_eks_cluster_auth.guardian.token
    
    exec {
      api_version = "client.authentication.k8s.io/v1beta1"
      command     = "aws"
      args        = ["eks", "get-token", "--cluster-name", "guardian-${var.environment}"]
    }
  }
  
  repository_config_path = "${path.module}/helm/repositories.yaml"
  repository_cache      = "${path.module}/helm/cache"
  debug                 = true
  verify               = true
}