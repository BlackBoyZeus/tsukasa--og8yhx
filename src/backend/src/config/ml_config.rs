use serde::{Deserialize, Serialize};
use config::{Config, ConfigError, Environment, File};
use burn::config as burn_config;
use num_cpus;
use crate::utils::error::GuardianError;

// Default configuration constants
const DEFAULT_MODEL_REGISTRY_PATH: &str = "/var/lib/guardian/models";
const DEFAULT_INFERENCE_THREADS: usize = (num_cpus::get() * 3) / 4;
const DEFAULT_MODEL_TIMEOUT_MS: u64 = 1000;
const DEFAULT_MAX_BATCH_SIZE: usize = 32;
const DEFAULT_FEATURE_CACHE_SIZE: usize = 10000;
const DEFAULT_MODEL_VERSION_RETENTION: u32 = 3;
const CONFIG_VERSION: &str = "1.0.0";

/// Resource limits for ML training and inference
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceLimits {
    pub max_memory_mb: usize,
    pub max_cpu_percent: u8,
    pub max_gpu_memory_mb: usize,
    pub max_training_time_hours: u8,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            max_memory_mb: 4096,      // 4GB default memory limit
            max_cpu_percent: 75,      // 75% CPU utilization limit
            max_gpu_memory_mb: 2048,  // 2GB GPU memory limit
            max_training_time_hours: 24, // 24 hour training time limit
        }
    }
}

/// Configuration structure for the ML subsystem
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MLConfig {
    pub model_registry_path: String,
    pub inference_threads: usize,
    pub model_timeout_ms: u64,
    pub max_batch_size: usize,
    pub feature_cache_size: usize,
    pub training_enabled: bool,
    pub model_version_retention: u32,
    pub inference_gpu_enabled: bool,
    pub config_version: String,
    pub training_resource_limits: ResourceLimits,
}

impl Default for MLConfig {
    fn default() -> Self {
        Self {
            model_registry_path: DEFAULT_MODEL_REGISTRY_PATH.to_string(),
            inference_threads: DEFAULT_INFERENCE_THREADS,
            model_timeout_ms: DEFAULT_MODEL_TIMEOUT_MS,
            max_batch_size: DEFAULT_MAX_BATCH_SIZE,
            feature_cache_size: DEFAULT_FEATURE_CACHE_SIZE,
            training_enabled: false,
            model_version_retention: DEFAULT_MODEL_VERSION_RETENTION,
            inference_gpu_enabled: false,
            config_version: CONFIG_VERSION.to_string(),
            training_resource_limits: ResourceLimits::default(),
        }
    }
}

impl MLConfig {
    /// Creates a new MLConfig instance with security-conscious default values
    pub fn new() -> Self {
        Self::default()
    }

    /// Loads and validates ML configuration from specified path with environment overrides
    pub fn load(path: String) -> Result<Self, GuardianError> {
        let builder = Config::builder()
            .add_source(File::with_name(&path).required(true))
            .add_source(Environment::with_prefix("GUARDIAN_ML"));

        let config = builder.build().map_err(|e| GuardianError::ConfigError {
            context: format!("Failed to load ML config from {}: {}", path, e),
            source: Some(Box::new(e)),
            severity: ErrorSeverity::High,
            timestamp: OffsetDateTime::now_utc(),
            correlation_id: Uuid::new_v4(),
            category: ErrorCategory::Validation,
            retry_count: 0,
        })?;

        let mut ml_config: MLConfig = config.try_deserialize().map_err(|e| GuardianError::ConfigError {
            context: format!("Failed to deserialize ML config: {}", e),
            source: Some(Box::new(e)),
            severity: ErrorSeverity::High,
            timestamp: OffsetDateTime::now_utc(),
            correlation_id: Uuid::new_v4(),
            category: ErrorCategory::Validation,
            retry_count: 0,
        })?;

        // Validate the loaded configuration
        ml_config.validate()?;

        Ok(ml_config)
    }

    /// Performs comprehensive validation of ML configuration settings
    pub fn validate(&self) -> Result<(), GuardianError> {
        use std::path::Path;

        // Validate model registry path
        if !Path::new(&self.model_registry_path).exists() {
            return Err(GuardianError::ConfigError {
                context: format!("Model registry path does not exist: {}", self.model_registry_path),
                source: None,
                severity: ErrorSeverity::High,
                timestamp: OffsetDateTime::now_utc(),
                correlation_id: Uuid::new_v4(),
                category: ErrorCategory::Validation,
                retry_count: 0,
            });
        }

        // Validate inference threads
        if self.inference_threads == 0 || self.inference_threads > num_cpus::get() {
            return Err(GuardianError::ConfigError {
                context: format!("Invalid inference thread count: {}", self.inference_threads),
                source: None,
                severity: ErrorSeverity::High,
                timestamp: OffsetDateTime::now_utc(),
                correlation_id: Uuid::new_v4(),
                category: ErrorCategory::Validation,
                retry_count: 0,
            });
        }

        // Validate model timeout
        if self.model_timeout_ms < 100 || self.model_timeout_ms > 5000 {
            return Err(GuardianError::ConfigError {
                context: format!("Model timeout must be between 100ms and 5000ms: {}", self.model_timeout_ms),
                source: None,
                severity: ErrorSeverity::High,
                timestamp: OffsetDateTime::now_utc(),
                correlation_id: Uuid::new_v4(),
                category: ErrorCategory::Validation,
                retry_count: 0,
            });
        }

        // Validate batch size
        if self.max_batch_size == 0 || self.max_batch_size > 128 {
            return Err(GuardianError::ConfigError {
                context: format!("Invalid batch size: {}", self.max_batch_size),
                source: None,
                severity: ErrorSeverity::High,
                timestamp: OffsetDateTime::now_utc(),
                correlation_id: Uuid::new_v4(),
                category: ErrorCategory::Validation,
                retry_count: 0,
            });
        }

        // Validate resource limits
        if self.training_resource_limits.max_cpu_percent > 90 {
            return Err(GuardianError::ConfigError {
                context: "CPU usage limit cannot exceed 90%".to_string(),
                source: None,
                severity: ErrorSeverity::High,
                timestamp: OffsetDateTime::now_utc(),
                correlation_id: Uuid::new_v4(),
                category: ErrorCategory::Validation,
                retry_count: 0,
            });
        }

        // Validate config version
        if self.config_version != CONFIG_VERSION {
            return Err(GuardianError::ConfigError {
                context: format!("Config version mismatch. Expected {}, got {}", CONFIG_VERSION, self.config_version),
                source: None,
                severity: ErrorSeverity::High,
                timestamp: OffsetDateTime::now_utc(),
                correlation_id: Uuid::new_v4(),
                category: ErrorCategory::Validation,
                retry_count: 0,
            });
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = MLConfig::new();
        assert_eq!(config.model_registry_path, DEFAULT_MODEL_REGISTRY_PATH);
        assert_eq!(config.inference_threads, DEFAULT_INFERENCE_THREADS);
        assert_eq!(config.model_timeout_ms, DEFAULT_MODEL_TIMEOUT_MS);
    }

    #[test]
    fn test_validate_invalid_timeout() {
        let mut config = MLConfig::new();
        config.model_timeout_ms = 50; // Too low
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validate_invalid_threads() {
        let mut config = MLConfig::new();
        config.inference_threads = num_cpus::get() + 1; // Too high
        assert!(config.validate().is_err());
    }
}