# AWS Provider configuration for CloudHSM resources
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 4.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.0"
    }
  }
}

# Random identifier for unique resource naming
resource "random_id" "suffix" {
  byte_length = 4
}

# Data source to fetch subnet information
data "aws_subnet" "selected" {
  id = var.hsm_subnet_ids[0]
}

# Local configuration for HSM setup
locals {
  hsm_config = {
    cluster_name = "guardian-hsm-${random_id.suffix.hex}"
    backup_identifier = "guardian-hsm-backup-${formatdate("YYYY-MM-DD", timestamp())}"
    key_specs = {
      algorithm = var.key_algorithm
      length    = var.key_algorithm == "RSA_4096" ? 4096 : 2048
      purpose   = "TPM_ATTESTATION"
    }
    tpm_integration = {
      enabled                 = var.tpm_integration_enabled
      attestation_key_type   = "RSA_4096"
      secure_boot_verification = true
      key_rotation_period    = "90d"
    }
    tpm_cidr_blocks = [data.aws_subnet.selected.cidr_block]
    tpm_tags = {
      TPMIntegration = "enabled"
      SecurityLevel  = "critical"
      KeyRotation    = "90days"
    }
    ip_address = cidrhost(data.aws_subnet.selected.cidr_block, 10)
  }
}

# CloudHSM cluster resource
resource "aws_cloudhsm_v2_cluster" "guardian" {
  hsm_type   = var.hsm_type
  subnet_ids = var.hsm_subnet_ids
  
  tags = merge(var.tags, local.hsm_config.tpm_tags)

  backup_retention_days = var.backup_retention_days
  source_backup_identifier = local.hsm_config.backup_identifier

  logging_config {
    log_group_name = "/aws/cloudhsm/${local.hsm_config.cluster_name}"
    audit_logging_enabled = true
  }
}

# CloudHSM instance resource
resource "aws_cloudhsm_v2_hsm" "guardian" {
  cluster_id        = aws_cloudhsm_v2_cluster.guardian.cluster_id
  subnet_id         = var.hsm_subnet_ids[0]
  availability_zone = data.aws_subnet.selected.availability_zone
  ip_address        = local.hsm_config.ip_address

  depends_on = [aws_cloudhsm_v2_cluster.guardian]
}

# Security group rule for HSM cluster communication
resource "aws_security_group_rule" "hsm_cluster_communication" {
  security_group_id = aws_cloudhsm_v2_cluster.guardian.security_group_id
  type             = "ingress"
  from_port        = 2223
  to_port          = 2225
  protocol         = "tcp"
  cidr_blocks      = [data.aws_subnet.selected.cidr_block]
  description      = "HSM cluster communication"
}

# Security group rule for HSM-TPM communication
resource "aws_security_group_rule" "hsm_tpm_communication" {
  security_group_id = aws_cloudhsm_v2_cluster.guardian.security_group_id
  type             = "ingress"
  from_port        = 1789
  to_port          = 1790
  protocol         = "tcp"
  cidr_blocks      = local.hsm_config.tpm_cidr_blocks
  description      = "HSM-TPM secure communication"
}

# CloudWatch Log Group for HSM audit logs
resource "aws_cloudwatch_log_group" "hsm_audit" {
  name              = "/aws/cloudhsm/${local.hsm_config.cluster_name}"
  retention_in_days = var.backup_retention_days
  
  tags = merge(var.tags, {
    Purpose = "HSM Audit Logging"
  })
}

# KMS key for HSM backup encryption
resource "aws_kms_key" "hsm_backup" {
  description             = "KMS key for HSM backup encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  
  tags = merge(var.tags, {
    Purpose = "HSM Backup Encryption"
  })
}

# Output values for use in other modules
output "cluster_id" {
  value       = aws_cloudhsm_v2_cluster.guardian.cluster_id
  description = "ID of the CloudHSM cluster"
}

output "hsm_eni_id" {
  value       = aws_cloudhsm_v2_cluster.guardian.hsm_eni_id
  description = "ID of the HSM elastic network interface"
}

output "security_group_id" {
  value       = aws_cloudhsm_v2_cluster.guardian.security_group_id
  description = "ID of the HSM security group"
}

output "hsm_ip_address" {
  value       = aws_cloudhsm_v2_hsm.guardian.ip_address
  description = "IP address of the HSM instance"
}