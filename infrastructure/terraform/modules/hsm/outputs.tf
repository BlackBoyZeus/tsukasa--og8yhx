# Output definitions for HSM module exposing critical configuration values
# for secure key management and cryptographic operations

output "hsm_cluster_id" {
  description = "ID of the CloudHSM cluster for secure key management and TPM integration"
  value       = aws_cloudhsm_v2_cluster.guardian.cluster_id
  sensitive   = false
}

output "hsm_vpc_id" {
  description = "VPC ID where the HSM cluster is deployed for network isolation and security"
  value       = aws_cloudhsm_v2_cluster.guardian.vpc_id
  sensitive   = false
}

output "hsm_security_group_id" {
  description = "Security group ID controlling network access to HSM cluster for cryptographic operations"
  value       = aws_cloudhsm_v2_cluster.guardian.security_group_id
  sensitive   = false
}

output "hsm_instance_id" {
  description = "ID of the HSM instance providing hardware-backed key storage and AES-256-GCM encryption"
  value       = aws_cloudhsm_v2_hsm.guardian.hsm_id
  sensitive   = false
}

output "hsm_ip_address" {
  description = "IP address of the HSM instance for secure client configuration and TPM integration"
  value       = aws_cloudhsm_v2_hsm.guardian.ip_address
  sensitive   = true
}

output "hsm_availability_zone" {
  description = "Availability zone of the HSM instance for high availability and disaster recovery"
  value       = aws_cloudhsm_v2_hsm.guardian.availability_zone
  sensitive   = false
}

output "hsm_cluster_state" {
  description = "Current state of the HSM cluster for monitoring and health checks"
  value       = aws_cloudhsm_v2_cluster.guardian.cluster_state
  sensitive   = false
}