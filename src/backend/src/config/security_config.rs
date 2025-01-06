use serde::{Deserialize, Serialize};
use config::{Config, ConfigError, Environment, File};
use tracing::{debug, error, info, instrument};
use std::path::Path;
use std::time::Duration;

use crate::utils::error::GuardianError;
use crate::utils::validation::{validate_input, ValidationRules};

// Security configuration constants
const DEFAULT_KEY_SIZE: u32 = 4096;
const MIN_PASSWORD_LENGTH: usize = 16;
const DEFAULT_TLS_VERSION: &str = "1.3";
const DEFAULT_CIPHER_SUITE: &str = "TLS_AES_256_GCM_SHA384";
const MIN_MFA_TOKEN_LENGTH: usize = 6;
const CERT_ROTATION_DAYS: u32 = 90;

/// Authentication configuration settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthConfig {
    pub x509_enabled: bool,
    pub x509_cert_path: String,
    pub x509_key_path: String,
    pub mfa_required: bool,
    pub mfa_issuer: String,
    pub api_key_enabled: bool,
    pub api_key_length: usize,
    pub min_password_length: usize,
    pub password_complexity: bool,
    pub session_timeout: Duration,
}

/// Encryption configuration settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptionConfig {
    pub aes_key_size: u32,
    pub rsa_key_size: u32,
    pub key_rotation_interval: Duration,
    pub encryption_at_rest: bool,
    pub encryption_in_transit: bool,
    pub cipher_suite: String,
}

/// TLS configuration settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TLSConfig {
    pub version: String,
    pub cipher_suites: Vec<String>,
    pub cert_path: String,
    pub key_path: String,
    pub ca_path: String,
    pub verify_peer: bool,
    pub cert_rotation_days: u32,
}

/// System hardening configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardeningConfig {
    pub secure_boot_enabled: bool,
    pub kernel_hardening: bool,
    pub memory_protection: bool,
    pub stack_protection: bool,
    pub aslr_enabled: bool,
    pub strict_permissions: bool,
}

/// Hardware security module configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareSecurityConfig {
    pub hsm_enabled: bool,
    pub hsm_provider: String,
    pub hsm_token_label: String,
    pub tpm_enabled: bool,
    pub secure_enclave_enabled: bool,
}

/// Audit logging configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditConfig {
    pub audit_enabled: bool,
    pub log_level: String,
    pub log_retention_days: u32,
    pub secure_logging: bool,
    pub log_encryption: bool,
}

/// Security monitoring configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitoringConfig {
    pub intrusion_detection: bool,
    pub threat_monitoring: bool,
    pub anomaly_detection: bool,
    pub monitoring_interval: Duration,
    pub alert_threshold: u32,
}

/// Comprehensive security configuration for the Guardian system
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    pub auth_config: AuthConfig,
    pub encryption_config: EncryptionConfig,
    pub tls_config: TLSConfig,
    pub hardening_config: HardeningConfig,
    pub hw_security_config: HardwareSecurityConfig,
    pub audit_config: AuditConfig,
    pub monitoring_config: MonitoringConfig,
}

impl SecurityConfig {
    /// Creates a new SecurityConfig with secure default settings
    pub fn new() -> Self {
        Self {
            auth_config: AuthConfig {
                x509_enabled: true,
                x509_cert_path: "/etc/guardian/certs/client.crt".to_string(),
                x509_key_path: "/etc/guardian/certs/client.key".to_string(),
                mfa_required: true,
                mfa_issuer: "AI Guardian".to_string(),
                api_key_enabled: true,
                api_key_length: 32,
                min_password_length: MIN_PASSWORD_LENGTH,
                password_complexity: true,
                session_timeout: Duration::from_secs(900), // 15 minutes
            },
            encryption_config: EncryptionConfig {
                aes_key_size: 256,
                rsa_key_size: DEFAULT_KEY_SIZE,
                key_rotation_interval: Duration::from_secs(7 * 24 * 3600), // 7 days
                encryption_at_rest: true,
                encryption_in_transit: true,
                cipher_suite: DEFAULT_CIPHER_SUITE.to_string(),
            },
            tls_config: TLSConfig {
                version: DEFAULT_TLS_VERSION.to_string(),
                cipher_suites: vec![DEFAULT_CIPHER_SUITE.to_string()],
                cert_path: "/etc/guardian/certs/server.crt".to_string(),
                key_path: "/etc/guardian/certs/server.key".to_string(),
                ca_path: "/etc/guardian/certs/ca.crt".to_string(),
                verify_peer: true,
                cert_rotation_days: CERT_ROTATION_DAYS,
            },
            hardening_config: HardeningConfig {
                secure_boot_enabled: true,
                kernel_hardening: true,
                memory_protection: true,
                stack_protection: true,
                aslr_enabled: true,
                strict_permissions: true,
            },
            hw_security_config: HardwareSecurityConfig {
                hsm_enabled: true,
                hsm_provider: "SoftHSM".to_string(),
                hsm_token_label: "guardian_hsm".to_string(),
                tpm_enabled: true,
                secure_enclave_enabled: true,
            },
            audit_config: AuditConfig {
                audit_enabled: true,
                log_level: "INFO".to_string(),
                log_retention_days: 90,
                secure_logging: true,
                log_encryption: true,
            },
            monitoring_config: MonitoringConfig {
                intrusion_detection: true,
                threat_monitoring: true,
                anomaly_detection: true,
                monitoring_interval: Duration::from_secs(60),
                alert_threshold: 3,
            },
        }
    }

    /// Loads and validates security configuration from specified path
    #[instrument(skip(config_path, env))]
    pub fn load_config<P: AsRef<Path>>(
        config_path: P,
        env: Option<Environment>,
    ) -> Result<Self, GuardianError> {
        let mut builder = Config::builder()
            .add_source(File::from(config_path.as_ref()))
            .add_source(env.unwrap_or_else(|| Environment::with_prefix("guardian")));

        let config = builder
            .build()
            .map_err(|e| GuardianError::ConfigError(format!("Failed to load config: {}", e)))?;

        let security_config: SecurityConfig = config
            .try_deserialize()
            .map_err(|e| GuardianError::ConfigError(format!("Failed to parse config: {}", e)))?;

        security_config.validate()?;
        
        info!("Security configuration loaded successfully");
        Ok(security_config)
    }

    /// Validates all security configuration settings
    pub fn validate(&self) -> Result<(), GuardianError> {
        // Validate authentication settings
        let auth_rules = ValidationRules {
            required: true,
            min_length: Some(MIN_PASSWORD_LENGTH),
            ..Default::default()
        };

        validate_input(&self.auth_config.x509_cert_path, &auth_rules)?;
        validate_input(&self.auth_config.x509_key_path, &auth_rules)?;

        if self.auth_config.min_password_length < MIN_PASSWORD_LENGTH {
            return Err(GuardianError::ValidationError(
                "Password length below minimum requirement".to_string(),
            ));
        }

        // Validate encryption settings
        if self.encryption_config.aes_key_size != 256 {
            return Err(GuardianError::ValidationError(
                "AES key size must be 256 bits".to_string(),
            ));
        }

        if self.encryption_config.rsa_key_size < DEFAULT_KEY_SIZE {
            return Err(GuardianError::ValidationError(
                "RSA key size below minimum requirement".to_string(),
            ));
        }

        // Validate TLS settings
        if self.tls_config.version != DEFAULT_TLS_VERSION {
            return Err(GuardianError::ValidationError(
                "TLS version must be 1.3".to_string(),
            ));
        }

        if !self.tls_config.cipher_suites.contains(&DEFAULT_CIPHER_SUITE.to_string()) {
            return Err(GuardianError::ValidationError(
                "Required cipher suite missing".to_string(),
            ));
        }

        debug!("Security configuration validation successful");
        Ok(())
    }

    /// Safely reloads security configuration with zero downtime
    #[instrument(skip(self))]
    pub fn reload_config(&self) -> Result<Self, GuardianError> {
        info!("Initiating security configuration reload");
        
        // Load new configuration while keeping current one active
        let new_config = Self::load_config(
            "/etc/guardian/config/security.toml",
            Some(Environment::with_prefix("guardian")),
        )?;

        // Validate new configuration before applying
        new_config.validate()?;

        info!("Security configuration reloaded successfully");
        Ok(new_config)
    }
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_security_config_validation() {
        let config = SecurityConfig::new();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_invalid_password_length() {
        let mut config = SecurityConfig::new();
        config.auth_config.min_password_length = 8;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_invalid_tls_version() {
        let mut config = SecurityConfig::new();
        config.tls_config.version = "1.2".to_string();
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_invalid_encryption_settings() {
        let mut config = SecurityConfig::new();
        config.encryption_config.aes_key_size = 128;
        assert!(config.validate().is_err());
    }
}