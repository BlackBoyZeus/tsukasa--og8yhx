# Backend configuration for AI Guardian infrastructure state management
# Version: 1.0
# Terraform Version: ~> 1.5

terraform {
  # S3 backend configuration with encryption and state locking
  backend "s3" {
    # State file storage configuration
    bucket = "${local.state_bucket_name}"
    key    = "guardian/terraform.tfstate"
    region = "${var.region}"
    
    # Security configuration
    encrypt        = true
    kms_key_id     = "${local.kms_key_id}"
    acl            = "private"
    
    # State locking configuration
    dynamodb_table = "${local.lock_table_name}"
    
    # Versioning and backup
    versioning = true
    
    # Server-side encryption configuration
    server_side_encryption_configuration {
      rule {
        apply_server_side_encryption_by_default {
          sse_algorithm = "aws:kms"
        }
      }
    }
  }
}

# Local variables for resource naming and configuration
locals {
  # S3 bucket name for state storage following naming convention
  state_bucket_name = "${var.environment}-${var.project_name}-terraform-state"
  
  # DynamoDB table name for state locking
  lock_table_name = "${var.environment}-${var.project_name}-terraform-locks"
  
  # KMS key ARN for state encryption
  kms_key_id = "arn:aws:kms:${var.region}:${data.aws_caller_identity.current.account_id}:key/${var.environment}-${var.project_name}-terraform-key"
}

# Data source to get current AWS account information
data "aws_caller_identity" "current" {}