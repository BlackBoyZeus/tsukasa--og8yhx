# AI Guardian System Infrastructure Configuration
# Version: 1.0.0
# Terraform Version: >= 1.0.0

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

  backend "s3" {
    bucket         = "guardian-terraform-state"
    key            = "guardian/terraform.tfstate"
    region         = var.region
    encrypt        = true
    dynamodb_table = "guardian-terraform-locks"
    kms_key_id     = aws_kms_key.terraform_state_key.id
  }
}

# Provider configurations
provider "aws" {
  region = var.region
  
  default_tags {
    tags = local.common_tags
  }
}

# Local variables for resource naming and tagging
locals {
  resource_prefix = "${var.environment}-guardian"
  common_tags = {
    Project             = "AI Guardian"
    Environment         = var.environment
    ManagedBy          = "Terraform"
    SecurityLevel      = "High"
    ComplianceRequired = "True"
    BackupRequired     = "True"
    MonitoringRequired = "True"
    LastUpdated        = timestamp()
  }
}

# KMS key for Terraform state encryption
resource "aws_kms_key" "terraform_state_key" {
  description             = "KMS key for Terraform state encryption"
  deletion_window_in_days = 30
  enable_key_rotation    = true
  
  tags = merge(local.common_tags, {
    Name = "${local.resource_prefix}-terraform-state-key"
  })
}

# HSM Module for secure key management
module "hsm" {
  source = "./modules/hsm"
  
  environment        = var.environment
  region            = var.region
  hsm_config        = var.hsm_config
  backup_retention  = 30
  key_rotation_period = 90
  monitoring_enabled = true
  
  tags = local.common_tags
}

# Temporal.io workflow engine deployment
module "temporal" {
  source = "./modules/temporal"
  
  environment       = var.environment
  region           = var.region
  temporal_config  = var.temporal_config
  hsm_id           = module.hsm.hsm_id
  high_availability = true
  encryption_enabled = true
  backup_enabled    = true
  
  depends_on = [module.hsm]
  
  tags = local.common_tags
}

# Monitoring infrastructure deployment
module "monitoring" {
  source = "./modules/monitoring"
  
  environment        = var.environment
  region            = var.region
  monitoring_config = var.monitoring_config
  retention_period  = 90
  alert_integration = true
  dashboard_enabled = true
  
  temporal_endpoint = module.temporal.endpoint
  hsm_metrics_enabled = true
  
  tags = local.common_tags
}

# Security group for infrastructure components
resource "aws_security_group" "guardian_infrastructure" {
  name        = "${local.resource_prefix}-infrastructure-sg"
  description = "Security group for AI Guardian infrastructure components"
  vpc_id      = var.hsm_config.vpc_id
  
  tags = merge(local.common_tags, {
    Name = "${local.resource_prefix}-infrastructure-sg"
  })

  lifecycle {
    create_before_destroy = true
  }
}

# VPC endpoints for secure service access
resource "aws_vpc_endpoint" "guardian_endpoints" {
  for_each = toset([
    "hsm",
    "monitoring",
    "temporal"
  ])
  
  vpc_id             = var.hsm_config.vpc_id
  service_name       = "com.amazonaws.${var.region}.${each.key}"
  vpc_endpoint_type  = "Interface"
  security_group_ids = [aws_security_group.guardian_infrastructure.id]
  subnet_ids         = var.hsm_config.subnet_ids
  
  private_dns_enabled = true
  
  tags = merge(local.common_tags, {
    Name = "${local.resource_prefix}-${each.key}-endpoint"
  })
}

# CloudWatch log group for infrastructure logging
resource "aws_cloudwatch_log_group" "infrastructure_logs" {
  name              = "/guardian/${var.environment}/infrastructure"
  retention_in_days = 90
  kms_key_id        = aws_kms_key.terraform_state_key.id
  
  tags = merge(local.common_tags, {
    Name = "${local.resource_prefix}-infrastructure-logs"
  })
}

# S3 bucket for infrastructure artifacts
resource "aws_s3_bucket" "artifacts" {
  bucket = "${local.resource_prefix}-artifacts"
  
  versioning {
    enabled = true
  }
  
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        kms_master_key_id = aws_kms_key.terraform_state_key.id
        sse_algorithm     = "aws:kms"
      }
    }
  }
  
  tags = merge(local.common_tags, {
    Name = "${local.resource_prefix}-artifacts"
  })
}

# DynamoDB table for infrastructure locks
resource "aws_dynamodb_table" "terraform_locks" {
  name         = "guardian-terraform-locks"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "LockID"
  
  attribute {
    name = "LockID"
    type = "S"
  }
  
  point_in_time_recovery {
    enabled = true
  }
  
  tags = merge(local.common_tags, {
    Name = "${local.resource_prefix}-terraform-locks"
  })
}