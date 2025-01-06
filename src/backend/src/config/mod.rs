use std::{
    sync::{Arc, RwLock},
    time::{Duration, Instant},
    path::PathBuf,
};
use serde::{Deserialize, Serialize};
use metrics::{counter, gauge, histogram};
use tokio::time;
use tracing::{debug, error, info, instrument};

// Re-export configuration components
pub use app_config::AppConfig;
pub use security_config::SecurityConfig;
pub use ml_config::MLConfig;
pub use storage_config::StorageConfig;

// Core configuration constants
const CONFIG_VERSION: &str = "1.0.0";
const DEFAULT_CONFIG_DIR: &str = "/etc/guardian/config";
const CONFIG_RELOAD_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_CONFIG_SIZE: usize = 1024 * 1024; // 1MB

/// Configuration metrics tracking
#[derive(Debug, Clone)]
struct ConfigMetrics {
    last_reload: Instant,
    reload_count: u64,
    validation_failures: u64,
    load_duration_ms: u64,
}

/// Thread-safe configuration coordinator with comprehensive validation
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuardianConfig {
    app_config: Arc<RwLock<AppConfig>>,
    security_config: Arc<RwLock<SecurityConfig>>,
    ml_config: Arc<RwLock<MLConfig>>,
    storage_config: Arc<RwLock<StorageConfig>>,
    #[serde(skip)]
    metrics: ConfigMetrics,
    version: String,
}

impl GuardianConfig {
    /// Creates a new thread-safe GuardianConfig instance
    pub fn new() -> Self {
        Self {
            app_config: Arc::new(RwLock::new(AppConfig::new(None))),
            security_config: Arc::new(RwLock::new(SecurityConfig::new())),
            ml_config: Arc::new(RwLock::new(MLConfig::new())),
            storage_config: Arc::new(RwLock::new(StorageConfig::new())),
            metrics: ConfigMetrics {
                last_reload: Instant::now(),
                reload_count: 0,
                validation_failures: 0,
                load_duration_ms: 0,
            },
            version: CONFIG_VERSION.to_string(),
        }
    }

    /// Asynchronously loads configurations with performance tracking
    #[instrument(skip(config_dir))]
    pub async fn load<P: Into<PathBuf>>(config_dir: P) -> Result<Self, GuardianError> {
        let start_time = Instant::now();
        let config_dir = config_dir.into();

        info!("Loading Guardian configuration from {:?}", config_dir);
        
        // Load individual configurations
        let app_config = AppConfig::load(config_dir.join("app.yaml"))?;
        let security_config = SecurityConfig::load(&config_dir.join("security.yaml").to_string_lossy())?;
        let ml_config = MLConfig::load(config_dir.join("ml.yaml").to_string_lossy().to_string())?;
        let storage_config = StorageConfig::load(config_dir.join("storage.yaml").to_string_lossy().to_string())?;

        let config = Self {
            app_config: Arc::new(RwLock::new(app_config)),
            security_config: Arc::new(RwLock::new(security_config)),
            ml_config: Arc::new(RwLock::new(ml_config)),
            storage_config: Arc::new(RwLock::new(storage_config)),
            metrics: ConfigMetrics {
                last_reload: Instant::now(),
                reload_count: 0,
                validation_failures: 0,
                load_duration_ms: start_time.elapsed().as_millis() as u64,
            },
            version: CONFIG_VERSION.to_string(),
        };

        // Validate complete configuration
        config.validate()?;

        // Record metrics
        histogram!("guardian.config.load_duration_ms", config.metrics.load_duration_ms as f64);
        counter!("guardian.config.loads_total", 1);

        info!("Configuration loaded successfully in {}ms", config.metrics.load_duration_ms);
        Ok(config)
    }

    /// Comprehensive validation with security checks
    #[instrument(skip(self))]
    pub fn validate(&self) -> Result<(), GuardianError> {
        let start_time = Instant::now();

        // Validate individual components
        {
            let app_config = self.app_config.read().map_err(|_| GuardianError::ConfigurationError {
                context: "Failed to acquire app config lock".into(),
                source: None,
                severity: ErrorSeverity::High,
                timestamp: time::OffsetDateTime::now_utc(),
                correlation_id: uuid::Uuid::new_v4(),
                category: ErrorCategory::System,
                retry_count: 0,
            })?;
            app_config.validate()?;
        }

        {
            let security_config = self.security_config.read().map_err(|_| GuardianError::ConfigurationError {
                context: "Failed to acquire security config lock".into(),
                source: None,
                severity: ErrorSeverity::Critical,
                timestamp: time::OffsetDateTime::now_utc(),
                correlation_id: uuid::Uuid::new_v4(),
                category: ErrorCategory::Security,
                retry_count: 0,
            })?;
            security_config.validate()?;
        }

        {
            let ml_config = self.ml_config.read().map_err(|_| GuardianError::ConfigurationError {
                context: "Failed to acquire ML config lock".into(),
                source: None,
                severity: ErrorSeverity::High,
                timestamp: time::OffsetDateTime::now_utc(),
                correlation_id: uuid::Uuid::new_v4(),
                category: ErrorCategory::ML,
                retry_count: 0,
            })?;
            ml_config.validate()?;
        }

        {
            let storage_config = self.storage_config.read().map_err(|_| GuardianError::ConfigurationError {
                context: "Failed to acquire storage config lock".into(),
                source: None,
                severity: ErrorSeverity::High,
                timestamp: time::OffsetDateTime::now_utc(),
                correlation_id: uuid::Uuid::new_v4(),
                category: ErrorCategory::Storage,
                retry_count: 0,
            })?;
            storage_config.validate()?;
        }

        // Cross-component validation
        self.validate_cross_component_dependencies()?;

        let validation_time = start_time.elapsed();
        histogram!("guardian.config.validation_duration_ms", validation_time.as_millis() as f64);
        
        debug!("Configuration validation successful");
        Ok(())
    }

    /// Hot reload configuration with rollback capability
    #[instrument(skip(self))]
    pub async fn reload(&self) -> Result<(), GuardianError> {
        let start_time = Instant::now();
        info!("Initiating configuration reload");

        // Create configuration snapshot for rollback
        let app_snapshot = self.app_config.read().unwrap().clone();
        let security_snapshot = self.security_config.read().unwrap().clone();
        let ml_snapshot = self.ml_config.read().unwrap().clone();
        let storage_snapshot = self.storage_config.read().unwrap().clone();

        // Attempt reload
        let reload_result = async {
            let new_config = Self::load(DEFAULT_CONFIG_DIR).await?;
            
            // Update configurations atomically
            *self.app_config.write().unwrap() = new_config.app_config.read().unwrap().clone();
            *self.security_config.write().unwrap() = new_config.security_config.read().unwrap().clone();
            *self.ml_config.write().unwrap() = new_config.ml_config.read().unwrap().clone();
            *self.storage_config.write().unwrap() = new_config.storage_config.read().unwrap().clone();

            Ok::<(), GuardianError>(())
        }.await;

        match reload_result {
            Ok(()) => {
                let reload_time = start_time.elapsed();
                histogram!("guardian.config.reload_duration_ms", reload_time.as_millis() as f64);
                counter!("guardian.config.reloads_successful", 1);
                info!("Configuration reload successful");
                Ok(())
            }
            Err(e) => {
                error!("Configuration reload failed, rolling back: {:?}", e);
                counter!("guardian.config.reload_failures", 1);
                
                // Rollback to snapshots
                *self.app_config.write().unwrap() = app_snapshot;
                *self.security_config.write().unwrap() = security_snapshot;
                *self.ml_config.write().unwrap() = ml_snapshot;
                *self.storage_config.write().unwrap() = storage_snapshot;

                Err(e)
            }
        }
    }

    /// Returns current configuration metrics
    pub fn get_metrics(&self) -> HashMap<String, f64> {
        let mut metrics = HashMap::new();
        metrics.insert("reload_count".to_string(), self.metrics.reload_count as f64);
        metrics.insert("validation_failures".to_string(), self.metrics.validation_failures as f64);
        metrics.insert("load_duration_ms".to_string(), self.metrics.load_duration_ms as f64);
        metrics.insert("last_reload_age_secs".to_string(), self.metrics.last_reload.elapsed().as_secs() as f64);
        metrics
    }

    // Private helper methods
    fn validate_cross_component_dependencies(&self) -> Result<(), GuardianError> {
        let app_config = self.app_config.read().unwrap();
        let security_config = self.security_config.read().unwrap();
        let ml_config = self.ml_config.read().unwrap();
        let storage_config = self.storage_config.read().unwrap();

        // Validate ML resource limits against app limits
        if ml_config.training_resource_limits.max_memory_mb > app_config.resource_limits.max_memory_mb {
            return Err(GuardianError::ValidationError {
                context: "ML memory limit exceeds system limit".into(),
                source: None,
                severity: ErrorSeverity::High,
                timestamp: time::OffsetDateTime::now_utc(),
                correlation_id: uuid::Uuid::new_v4(),
                category: ErrorCategory::Validation,
                retry_count: 0,
            });
        }

        // Validate storage encryption against security requirements
        if app_config.environment == Environment::Production && !storage_config.encryption_enabled {
            return Err(GuardianError::ValidationError {
                context: "Production environment requires storage encryption".into(),
                source: None,
                severity: ErrorSeverity::Critical,
                timestamp: time::OffsetDateTime::now_utc(),
                correlation_id: uuid::Uuid::new_v4(),
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
    use tempfile::tempdir;
    use std::fs;

    #[tokio::test]
    async fn test_config_load_and_validate() {
        let dir = tempdir().unwrap();
        
        // Create test config files
        fs::write(dir.path().join("app.yaml"), "environment: Production").unwrap();
        fs::write(dir.path().join("security.yaml"), "tls_version: \"1.3\"").unwrap();
        fs::write(dir.path().join("ml.yaml"), "inference_threads: 4").unwrap();
        fs::write(dir.path().join("storage.yaml"), "encryption_enabled: true").unwrap();

        let config = GuardianConfig::load(dir.path()).await;
        assert!(config.is_ok());
    }

    #[test]
    fn test_cross_component_validation() {
        let config = GuardianConfig::new();
        assert!(config.validate_cross_component_dependencies().is_ok());
    }

    #[tokio::test]
    async fn test_config_reload() {
        let config = GuardianConfig::new();
        let reload_result = config.reload().await;
        assert!(reload_result.is_ok());
    }
}