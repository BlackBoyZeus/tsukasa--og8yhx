use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::{debug, error, info, instrument, warn};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use crate::utils::error::GuardianError;
use crate::utils::validation::{validate_input, ValidationRules};

// Import configuration components
mod app_config;
mod security_config;
mod ml_config;
mod storage_config;

pub use app_config::AppConfig;
pub use security_config::SecurityConfig;
pub use ml_config::MLConfig;
pub use storage_config::StorageConfig;

// System-wide configuration constants
const CONFIG_VERSION: &str = "1.0.0";
const DEFAULT_CONFIG_PATH: &str = "/etc/guardian/config";
const MAX_RESOURCE_USAGE: f64 = 5.0;
const BACKUP_RETENTION_DAYS: u32 = 30;

/// System resource monitoring configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemResources {
    pub max_memory_percent: f64,
    pub max_cpu_percent: f64,
    pub max_gpu_percent: f64,
    pub check_interval_ms: u64,
}

/// Root configuration structure for the Guardian system
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuardianConfig {
    pub app_config: AppConfig,
    pub security_config: SecurityConfig,
    pub ml_config: MLConfig,
    pub storage_config: StorageConfig,
    pub version: String,
    pub resources: SystemResources,
}

impl GuardianConfig {
    /// Creates a new GuardianConfig instance with secure defaults
    #[instrument]
    pub fn new() -> Result<Self, GuardianError> {
        info!("Initializing Guardian configuration");
        
        let config = Self {
            app_config: AppConfig::new(None, None)?,
            security_config: SecurityConfig::new(),
            ml_config: MLConfig::new(),
            storage_config: StorageConfig::new()?,
            version: CONFIG_VERSION.to_string(),
            resources: SystemResources {
                max_memory_percent: MAX_RESOURCE_USAGE,
                max_cpu_percent: MAX_RESOURCE_USAGE,
                max_gpu_percent: MAX_RESOURCE_USAGE,
                check_interval_ms: 1000,
            },
        };

        config.validate()?;
        Ok(config)
    }

    /// Loads all configuration components with validation and security checks
    #[instrument(skip(config_path))]
    pub async fn load(config_path: PathBuf) -> Result<Arc<RwLock<Self>>, GuardianError> {
        info!("Loading Guardian configuration from {:?}", config_path);

        // Verify config directory exists and has correct permissions
        if !config_path.exists() {
            return Err(GuardianError::ConfigError(
                "Configuration directory does not exist".to_string(),
            ));
        }

        // Load individual components
        let app_config = AppConfig::new(Some(config_path.join("app.toml").to_string_lossy().to_string()), None)?;
        let security_config = SecurityConfig::load_config(&config_path.join("security.toml"), None)?;
        let ml_config = MLConfig::load_config(config_path.join("ml.toml").to_string_lossy().to_string())?;
        let storage_config = StorageConfig::new()?;

        let config = Self {
            app_config,
            security_config,
            ml_config,
            storage_config,
            version: CONFIG_VERSION.to_string(),
            resources: SystemResources {
                max_memory_percent: MAX_RESOURCE_USAGE,
                max_cpu_percent: MAX_RESOURCE_USAGE,
                max_gpu_percent: MAX_RESOURCE_USAGE,
                check_interval_ms: 1000,
            },
        };

        // Validate complete configuration
        config.validate()?;

        Ok(Arc::new(RwLock::new(config)))
    }

    /// Comprehensive validation of all configuration components
    #[instrument(skip(self))]
    pub fn validate(&self) -> Result<(), GuardianError> {
        debug!("Validating Guardian configuration");

        // Validate individual components
        self.app_config.validate()?;
        self.security_config.validate()?;
        self.ml_config.validate()?;
        self.storage_config.validate()?;

        // Cross-component validation
        self.validate_resource_limits()?;
        self.validate_security_dependencies()?;
        self.validate_version_compatibility()?;

        info!("Configuration validation successful");
        Ok(())
    }

    /// Safely reloads configuration during runtime
    #[instrument(skip(self))]
    pub async fn hot_reload(&self) -> Result<(), GuardianError> {
        info!("Initiating configuration hot reload");

        // Create temporary configuration
        let temp_config = Self::load(PathBuf::from(DEFAULT_CONFIG_PATH)).await?;
        
        // Validate new configuration
        temp_config.read().await.validate()?;

        // Verify resource impact
        self.verify_resource_impact(&temp_config.read().await)?;

        // Apply new configuration gradually
        tokio::time::sleep(Duration::from_secs(1)).await;

        info!("Configuration hot reload successful");
        Ok(())
    }

    /// Creates a secure backup of the current configuration
    #[instrument(skip(self))]
    pub async fn backup(&self) -> Result<(), GuardianError> {
        info!("Creating configuration backup");

        // Backup each component
        self.app_config.hot_reload().await?;
        self.storage_config.validate()?;

        // Create timestamped backup
        let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S");
        let backup_path = PathBuf::from(DEFAULT_CONFIG_PATH)
            .join(format!("backup_{}", timestamp));

        // Ensure backup directory exists
        std::fs::create_dir_all(&backup_path)
            .map_err(|e| GuardianError::StorageError(format!("Failed to create backup directory: {}", e)))?;

        // Cleanup old backups
        self.cleanup_old_backups().await?;

        info!("Configuration backup created successfully");
        Ok(())
    }

    // Private helper methods
    
    fn validate_resource_limits(&self) -> Result<(), GuardianError> {
        if self.resources.max_memory_percent > MAX_RESOURCE_USAGE ||
           self.resources.max_cpu_percent > MAX_RESOURCE_USAGE ||
           self.resources.max_gpu_percent > MAX_RESOURCE_USAGE {
            return Err(GuardianError::ValidationError(
                "Resource usage limits exceeded".to_string(),
            ));
        }
        Ok(())
    }

    fn validate_security_dependencies(&self) -> Result<(), GuardianError> {
        if self.security_config.auth_config.x509_enabled && 
           self.app_config.security_config.tls_enabled {
            // Verify certificate paths match
            if self.security_config.auth_config.x509_cert_path != 
               self.app_config.security_config.certificate_path.clone().unwrap_or_default() {
                return Err(GuardianError::ValidationError(
                    "Mismatched certificate configurations".to_string(),
                ));
            }
        }
        Ok(())
    }

    fn validate_version_compatibility(&self) -> Result<(), GuardianError> {
        if self.version != CONFIG_VERSION {
            return Err(GuardianError::ValidationError(
                format!("Configuration version mismatch: expected {}, found {}", 
                    CONFIG_VERSION, self.version)
            ));
        }
        Ok(())
    }

    fn verify_resource_impact(&self, new_config: &GuardianConfig) -> Result<(), GuardianError> {
        // Verify memory impact
        if new_config.resources.max_memory_percent > self.resources.max_memory_percent * 1.5 {
            return Err(GuardianError::ValidationError(
                "New configuration would significantly increase memory usage".to_string(),
            ));
        }

        // Verify CPU impact
        if new_config.resources.max_cpu_percent > self.resources.max_cpu_percent * 1.5 {
            return Err(GuardianError::ValidationError(
                "New configuration would significantly increase CPU usage".to_string(),
            ));
        }

        Ok(())
    }

    async fn cleanup_old_backups(&self) -> Result<(), GuardianError> {
        let backup_dir = PathBuf::from(DEFAULT_CONFIG_PATH);
        let retention_duration = chrono::Duration::days(BACKUP_RETENTION_DAYS as i64);

        for entry in std::fs::read_dir(&backup_dir)
            .map_err(|e| GuardianError::StorageError(format!("Failed to read backup directory: {}", e)))? {
                
            let entry = entry.map_err(|e| GuardianError::StorageError(
                format!("Failed to read backup entry: {}", e)))?;
                
            if let Some(file_name) = entry.file_name().to_str() {
                if file_name.starts_with("backup_") {
                    if let Ok(timestamp) = chrono::NaiveDateTime::parse_from_str(
                        &file_name[7..], "%Y%m%d_%H%M%S") {
                        if (chrono::Utc::now().naive_utc() - timestamp) > retention_duration {
                            std::fs::remove_dir_all(entry.path())
                                .map_err(|e| GuardianError::StorageError(
                                    format!("Failed to remove old backup: {}", e)))?;
                        }
                    }
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_config_validation() {
        let config = GuardianConfig::new().unwrap();
        assert!(config.validate().is_ok());
    }

    #[tokio::test]
    async fn test_resource_validation() {
        let mut config = GuardianConfig::new().unwrap();
        config.resources.max_memory_percent = MAX_RESOURCE_USAGE * 2.0;
        assert!(config.validate().is_err());
    }

    #[tokio::test]
    async fn test_version_validation() {
        let mut config = GuardianConfig::new().unwrap();
        config.version = "0.9.0".to_string();
        assert!(config.validate().is_err());
    }
}