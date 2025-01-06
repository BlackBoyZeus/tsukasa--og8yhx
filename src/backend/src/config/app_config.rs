use config::{Config, ConfigError, Environment, File};
use serde::{Deserialize, Serialize};
use std::{path::PathBuf, time::Duration};
use tracing::{debug, error, info, instrument};

use crate::utils::error::{GuardianError, ValidationError, ConfigurationError};
use crate::utils::validation::{ValidationContext, validate, validate_performance};

// Core configuration constants
const CONFIG_VERSION: &str = "1.0.0";
const DEFAULT_APP_NAME: &str = "AI Guardian";
const MIN_THREADS: usize = 2;
const MAX_THREADS: usize = 32;
const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const SYSTEM_OVERHEAD_LIMIT: f64 = 0.05; // 5% max system overhead
const CRITICAL_RESPONSE_LIMIT: Duration = Duration::from_millis(1000);
const MIN_UPTIME_PERCENTAGE: f64 = 99.999;

/// Environment types for configuration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Environment {
    Development,
    Staging,
    Production,
}

/// Log level configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LogLevel {
    Debug,
    Info,
    Warn,
    Error,
}

/// Performance mode settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PerformanceMode {
    HighPerformance,
    Balanced,
    PowerSaving,
}

/// Resource limits configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceLimits {
    pub max_memory_mb: usize,
    pub max_cpu_percent: f64,
    pub max_gpu_percent: f64,
    pub io_priority: u8,
}

/// Security settings configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecuritySettings {
    pub enable_secure_boot: bool,
    pub tpm_required: bool,
    pub encryption_level: String,
    pub auth_timeout_seconds: u64,
    pub max_auth_retries: u32,
}

/// Monitoring configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitoringConfig {
    pub metrics_interval: Duration,
    pub health_check_interval: Duration,
    pub enable_tracing: bool,
    pub log_retention_days: u32,
}

/// Main application configuration structure
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppConfig {
    pub app_name: String,
    pub version: String,
    pub environment: Environment,
    pub log_level: LogLevel,
    pub max_threads: usize,
    pub request_timeout: Duration,
    pub max_memory: usize,
    pub performance_mode: PerformanceMode,
    pub resource_limits: ResourceLimits,
    pub security_settings: SecuritySettings,
    pub monitoring_config: MonitoringConfig,
}

impl AppConfig {
    /// Creates a new AppConfig instance with environment-specific defaults
    pub fn new(environment: Option<Environment>) -> Self {
        let env = environment.unwrap_or(Environment::Production);
        
        let resource_limits = match env {
            Environment::Production => ResourceLimits {
                max_memory_mb: 4096,
                max_cpu_percent: 80.0,
                max_gpu_percent: 70.0,
                io_priority: 1,
            },
            _ => ResourceLimits {
                max_memory_mb: 2048,
                max_cpu_percent: 60.0,
                max_gpu_percent: 50.0,
                io_priority: 2,
            },
        };

        let security_settings = SecuritySettings {
            enable_secure_boot: env == Environment::Production,
            tpm_required: env == Environment::Production,
            encryption_level: "AES-256-GCM".to_string(),
            auth_timeout_seconds: 1800,
            max_auth_retries: 3,
        };

        let monitoring_config = MonitoringConfig {
            metrics_interval: Duration::from_secs(60),
            health_check_interval: Duration::from_secs(30),
            enable_tracing: true,
            log_retention_days: 90,
        };

        Self {
            app_name: DEFAULT_APP_NAME.to_string(),
            version: CONFIG_VERSION.to_string(),
            environment: env,
            log_level: LogLevel::Info,
            max_threads: MAX_THREADS,
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
            max_memory: resource_limits.max_memory_mb,
            performance_mode: PerformanceMode::Balanced,
            resource_limits,
            security_settings,
            monitoring_config,
        }
    }

    /// Loads and validates configuration from file with environment overlays
    #[instrument(skip(config_path))]
    pub fn load(config_path: PathBuf) -> Result<Self, GuardianError> {
        let config_file = File::from(config_path).required(true);
        
        let config = Config::builder()
            .add_source(config_file)
            .add_source(Environment::with_prefix("GUARDIAN"))
            .build()
            .map_err(|e| GuardianError::ConfigurationError {
                context: "Failed to load configuration".into(),
                source: Some(Box::new(e)),
                severity: crate::utils::error::ErrorSeverity::Critical,
                timestamp: time::OffsetDateTime::now_utc(),
                correlation_id: uuid::Uuid::new_v4(),
                category: crate::utils::error::ErrorCategory::System,
                retry_count: 0,
            })?;

        let mut app_config: AppConfig = config.try_deserialize().map_err(|e| {
            GuardianError::ConfigurationError {
                context: "Failed to deserialize configuration".into(),
                source: Some(Box::new(e)),
                severity: crate::utils::error::ErrorSeverity::Critical,
                timestamp: time::OffsetDateTime::now_utc(),
                correlation_id: uuid::Uuid::new_v4(),
                category: crate::utils::error::ErrorCategory::System,
                retry_count: 0,
            }
        })?;

        app_config.validate()?;
        info!("Configuration loaded successfully");
        Ok(app_config)
    }

    /// Validates configuration against performance and security requirements
    #[instrument(skip(self))]
    pub fn validate(&self) -> Result<(), GuardianError> {
        // Validate thread configuration
        if self.max_threads < MIN_THREADS || self.max_threads > MAX_THREADS {
            return Err(GuardianError::ValidationError {
                context: format!("Invalid thread count: {}", self.max_threads),
                source: None,
                severity: crate::utils::error::ErrorSeverity::High,
                timestamp: time::OffsetDateTime::now_utc(),
                correlation_id: uuid::Uuid::new_v4(),
                category: crate::utils::error::ErrorCategory::Validation,
                retry_count: 0,
            });
        }

        // Validate resource limits
        if self.resource_limits.max_cpu_percent > 95.0 {
            return Err(GuardianError::ValidationError {
                context: "CPU limit exceeds safe threshold".into(),
                source: None,
                severity: crate::utils::error::ErrorSeverity::High,
                timestamp: time::OffsetDateTime::now_utc(),
                correlation_id: uuid::Uuid::new_v4(),
                category: crate::utils::error::ErrorCategory::Validation,
                retry_count: 0,
            });
        }

        // Validate security settings for production
        if self.environment == Environment::Production {
            if !self.security_settings.enable_secure_boot || !self.security_settings.tpm_required {
                return Err(GuardianError::ValidationError {
                    context: "Production requires secure boot and TPM".into(),
                    source: None,
                    severity: crate::utils::error::ErrorSeverity::Critical,
                    timestamp: time::OffsetDateTime::now_utc(),
                    correlation_id: uuid::Uuid::new_v4(),
                    category: crate::utils::error::ErrorCategory::Validation,
                    retry_count: 0,
                });
            }
        }

        // Validate monitoring configuration
        if self.monitoring_config.metrics_interval < Duration::from_secs(10) {
            return Err(GuardianError::ValidationError {
                context: "Metrics interval too short".into(),
                source: None,
                severity: crate::utils::error::ErrorSeverity::Medium,
                timestamp: time::OffsetDateTime::now_utc(),
                correlation_id: uuid::Uuid::new_v4(),
                category: crate::utils::error::ErrorCategory::Validation,
                retry_count: 0,
            });
        }

        debug!("Configuration validation successful");
        Ok(())
    }

    /// Reloads configuration from disk with validation
    #[instrument(skip(self))]
    pub fn reload(&self, config_path: PathBuf) -> Result<Self, GuardianError> {
        info!("Reloading configuration");
        Self::load(config_path)
    }

    /// Returns current configuration metrics
    pub fn get_metrics(&self) -> HashMap<String, f64> {
        let mut metrics = HashMap::new();
        metrics.insert("max_threads".to_string(), self.max_threads as f64);
        metrics.insert("max_memory_mb".to_string(), self.max_memory as f64);
        metrics.insert("max_cpu_percent".to_string(), self.resource_limits.max_cpu_percent);
        metrics.insert("max_gpu_percent".to_string(), self.resource_limits.max_gpu_percent);
        metrics
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn test_config_validation() {
        let config = AppConfig::new(Some(Environment::Production));
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_invalid_thread_count() {
        let mut config = AppConfig::new(None);
        config.max_threads = MAX_THREADS + 1;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_production_security_requirements() {
        let mut config = AppConfig::new(Some(Environment::Production));
        config.security_settings.enable_secure_boot = false;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_config_reload() {
        let dir = tempdir().unwrap();
        let config_path = dir.path().join("config.yaml");
        
        let config = AppConfig::new(None);
        let yaml = serde_yaml::to_string(&config).unwrap();
        fs::write(&config_path, yaml).unwrap();
        
        assert!(config.reload(config_path).is_ok());
    }
}