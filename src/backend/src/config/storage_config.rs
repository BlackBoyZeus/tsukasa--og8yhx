use serde::{Deserialize, Serialize};
use config::{Config, ConfigError, File};
use crate::utils::error::GuardianError;

// Constants for storage configuration
const DEFAULT_ZFS_POOL: &str = "guardian_pool";
const DEFAULT_COMPRESSION: &str = "lz4";
const MIN_RETENTION_DAYS: u32 = 30;
const DEFAULT_COMPRESSION_LEVEL: u32 = 6;
const MAX_COMPRESSION_LEVEL: u32 = 9;
const MIN_COMPRESSION_LEVEL: u32 = 1;

/// Storage I/O priority levels
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StorageIOPriority {
    High,
    Normal,
    Low,
}

/// Data retention policy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetentionPolicy {
    pub system_events_days: u32,
    pub security_alerts_days: u32,
    pub ml_model_versions: u32,
    pub audit_logs_days: u32,
}

/// Storage quota settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuotaSettings {
    pub max_pool_size_gb: u64,
    pub alert_threshold_percent: u8,
    pub reserve_space_percent: u8,
}

/// ZFS snapshot configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotConfig {
    pub enabled: bool,
    pub interval_hours: u32,
    pub retention_count: u32,
    pub auto_cleanup: bool,
}

/// Resource usage estimate
#[derive(Debug, Clone)]
pub struct ResourceEstimate {
    pub cpu_percent: f32,
    pub memory_mb: u64,
    pub io_ops_per_sec: u32,
}

/// Resource limits for optimization
#[derive(Debug, Clone)]
pub struct ResourceLimit {
    pub max_cpu_percent: f32,
    pub max_memory_mb: u64,
    pub max_io_ops_per_sec: u32,
}

/// Enhanced storage configuration for the ZFS-based storage subsystem
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    pub zfs_pool_name: String,
    pub encryption_enabled: bool,
    pub compression_algorithm: String,
    pub compression_level: u32,
    pub io_priority: StorageIOPriority,
    pub retention_policy: RetentionPolicy,
    pub quota_settings: QuotaSettings,
    pub backup_enabled: bool,
    pub snapshot_schedule: SnapshotConfig,
}

impl StorageConfig {
    /// Creates a new StorageConfig instance with optimized default settings
    pub fn new() -> Self {
        Self {
            zfs_pool_name: DEFAULT_ZFS_POOL.to_string(),
            encryption_enabled: true,
            compression_algorithm: DEFAULT_COMPRESSION.to_string(),
            compression_level: DEFAULT_COMPRESSION_LEVEL,
            io_priority: StorageIOPriority::Normal,
            retention_policy: RetentionPolicy {
                system_events_days: 90,
                security_alerts_days: 180,
                ml_model_versions: 5,
                audit_logs_days: 365,
            },
            quota_settings: QuotaSettings {
                max_pool_size_gb: 1024,
                alert_threshold_percent: 85,
                reserve_space_percent: 10,
            },
            backup_enabled: true,
            snapshot_schedule: SnapshotConfig {
                enabled: true,
                interval_hours: 24,
                retention_count: 30,
                auto_cleanup: true,
            },
        }
    }

    /// Loads and validates storage configuration from specified path
    pub fn load(config_path: String) -> Result<Self, GuardianError> {
        let config = Config::builder()
            .add_source(File::with_name(&config_path))
            .build()
            .map_err(|e| GuardianError::ConfigError {
                context: format!("Failed to load storage config: {}", e),
                source: Some(Box::new(e)),
                severity: ErrorSeverity::High,
                timestamp: time::OffsetDateTime::now_utc(),
                correlation_id: uuid::Uuid::new_v4(),
                category: ErrorCategory::Storage,
                retry_count: 0,
            })?;

        let storage_config: StorageConfig = config.try_deserialize()
            .map_err(|e| GuardianError::ConfigError {
                context: format!("Failed to parse storage config: {}", e),
                source: Some(Box::new(e)),
                severity: ErrorSeverity::High,
                timestamp: time::OffsetDateTime::now_utc(),
                correlation_id: uuid::Uuid::new_v4(),
                category: ErrorCategory::Storage,
                retry_count: 0,
            })?;

        storage_config.validate()?;
        Ok(storage_config)
    }

    /// Comprehensive validation of storage configuration settings
    pub fn validate(&self) -> Result<(), GuardianError> {
        // Validate compression level
        if self.compression_level < MIN_COMPRESSION_LEVEL || self.compression_level > MAX_COMPRESSION_LEVEL {
            return Err(GuardianError::ConfigError {
                context: format!("Invalid compression level: {}", self.compression_level),
                source: None,
                severity: ErrorSeverity::High,
                timestamp: time::OffsetDateTime::now_utc(),
                correlation_id: uuid::Uuid::new_v4(),
                category: ErrorCategory::Validation,
                retry_count: 0,
            });
        }

        // Validate retention policy
        if self.retention_policy.system_events_days < MIN_RETENTION_DAYS {
            return Err(GuardianError::ConfigError {
                context: "System events retention period too short".to_string(),
                source: None,
                severity: ErrorSeverity::High,
                timestamp: time::OffsetDateTime::now_utc(),
                correlation_id: uuid::Uuid::new_v4(),
                category: ErrorCategory::Validation,
                retry_count: 0,
            });
        }

        // Validate quota settings
        if self.quota_settings.alert_threshold_percent >= 100 
            || self.quota_settings.reserve_space_percent >= 100 {
            return Err(GuardianError::ConfigError {
                context: "Invalid quota percentage settings".to_string(),
                source: None,
                severity: ErrorSeverity::High,
                timestamp: time::OffsetDateTime::now_utc(),
                correlation_id: uuid::Uuid::new_v4(),
                category: ErrorCategory::Validation,
                retry_count: 0,
            });
        }

        Ok(())
    }

    /// Estimates system resource usage based on current configuration
    pub fn estimate_resource_usage(&self) -> ResourceEstimate {
        let base_cpu = 2.0;
        let compression_cpu = match self.compression_level {
            1..=3 => 0.5,
            4..=6 => 1.0,
            7..=9 => 2.0,
            _ => 1.0,
        };

        let memory_overhead = if self.encryption_enabled { 512 } else { 256 };
        let snapshot_memory = if self.snapshot_schedule.enabled { 256 } else { 0 };

        ResourceEstimate {
            cpu_percent: base_cpu + compression_cpu,
            memory_mb: memory_overhead + snapshot_memory,
            io_ops_per_sec: 1000,
        }
    }

    /// Optimizes storage settings for maximum performance within resource constraints
    pub fn optimize_for_performance(&mut self, resource_limit: ResourceLimit) -> Result<(), GuardianError> {
        let current_usage = self.estimate_resource_usage();

        // Adjust compression level based on CPU availability
        if current_usage.cpu_percent > resource_limit.max_cpu_percent {
            self.compression_level = self.compression_level.saturating_sub(1);
        }

        // Optimize snapshot schedule based on IO capacity
        if current_usage.io_ops_per_sec > resource_limit.max_io_ops_per_sec {
            self.snapshot_schedule.interval_hours = 
                (self.snapshot_schedule.interval_hours as f32 * 1.5) as u32;
        }

        // Verify optimizations meet requirements
        self.validate()?;
        
        Ok(())
    }
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = StorageConfig::new();
        assert_eq!(config.zfs_pool_name, DEFAULT_ZFS_POOL);
        assert!(config.encryption_enabled);
        assert_eq!(config.compression_algorithm, DEFAULT_COMPRESSION);
    }

    #[test]
    fn test_validate_compression_level() {
        let mut config = StorageConfig::new();
        config.compression_level = MAX_COMPRESSION_LEVEL + 1;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_resource_estimation() {
        let config = StorageConfig::new();
        let estimate = config.estimate_resource_usage();
        assert!(estimate.cpu_percent > 0.0);
        assert!(estimate.memory_mb > 0);
    }

    #[test]
    fn test_performance_optimization() {
        let mut config = StorageConfig::new();
        let resource_limit = ResourceLimit {
            max_cpu_percent: 5.0,
            max_memory_mb: 1024,
            max_io_ops_per_sec: 500,
        };
        assert!(config.optimize_for_performance(resource_limit).is_ok());
    }
}