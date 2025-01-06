//! AI Guardian System - Root Library Crate
//! Version: 1.0.0
//! 
//! This is the root library crate for the AI Guardian system that coordinates
//! all major subsystems including core functionality, security, ML operations,
//! and utilities. It implements thread-safe initialization, comprehensive telemetry,
//! and resource optimization.

use once_cell::sync::OnceCell;
use std::sync::Arc;
use tokio::runtime::Runtime;
use tracing::{debug, error, info, instrument, warn};
use metrics::{counter, gauge};

// Internal module imports
use crate::utils::{GuardianError, Result, metrics};
use crate::core::{Guardian, GuardianConfig, HealthCheck};
use crate::security::{SecurityManager, SecurityBoundary};

// Version and configuration constants
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
const METRICS_PREFIX: &str = "guardian";
const INIT_TIMEOUT_SECS: u64 = 30;
const MAX_RETRY_ATTEMPTS: u32 = 3;

// Module declarations
pub mod core;
pub mod security;
pub mod utils;

// Global singleton instance
static GUARDIAN_INSTANCE: OnceCell<Arc<Guardian>> = OnceCell::new();

/// Feature flags for optional functionality
#[derive(Debug, Clone)]
pub struct FeatureFlags {
    pub ml_enabled: bool,
    pub audit_logging: bool,
    pub performance_metrics: bool,
    pub secure_boot: bool,
}

impl Default for FeatureFlags {
    fn default() -> Self {
        Self {
            ml_enabled: true,
            audit_logging: true,
            performance_metrics: true,
            secure_boot: true,
        }
    }
}

/// System initialization options
#[derive(Debug, Clone)]
pub struct InitOptions {
    pub features: FeatureFlags,
    pub runtime_threads: Option<usize>,
    pub metrics_interval: std::time::Duration,
}

impl Default for InitOptions {
    fn default() -> Self {
        Self {
            features: FeatureFlags::default(),
            runtime_threads: None,
            metrics_interval: std::time::Duration::from_secs(60),
        }
    }
}

/// Initializes the Guardian system with the provided configuration
#[instrument(skip(config), fields(features = ?config.features))]
pub async fn init_guardian(config: GuardianConfig) -> Result<Arc<Guardian>> {
    info!("Initializing AI Guardian system v{}", VERSION);
    
    // Initialize metrics collection
    metrics::init_metrics(METRICS_PREFIX)?;
    counter!("guardian.initialization", 1);

    // Create optimized runtime
    let runtime = Runtime::builder()
        .threaded_scheduler()
        .enable_all()
        .build()
        .map_err(|e| GuardianError::SystemError {
            context: "Failed to create runtime".into(),
            source: Some(Box::new(e)),
            severity: utils::error::ErrorSeverity::Critical,
            timestamp: time::OffsetDateTime::now_utc(),
            correlation_id: uuid::Uuid::new_v4(),
            category: utils::error::ErrorCategory::System,
            retry_count: 0,
        })?;

    // Initialize core system
    let guardian = core::init_core(config.clone()).await?;
    
    // Initialize security subsystem
    let security_manager = SecurityManager::new(
        config.security_config,
        Arc::new(metrics::MetricsCollector::new(Default::default())?),
    )?;
    security_manager.initialize().await?;

    // Store singleton instance
    GUARDIAN_INSTANCE.set(Arc::clone(&guardian))
        .map_err(|_| GuardianError::SystemError {
            context: "Failed to set global instance".into(),
            source: None,
            severity: utils::error::ErrorSeverity::Critical,
            timestamp: time::OffsetDateTime::now_utc(),
            correlation_id: uuid::Uuid::new_v4(),
            category: utils::error::ErrorCategory::System,
            retry_count: 0,
        })?;

    // Start health monitoring
    monitor_system_health(Arc::clone(&guardian));

    info!("Guardian system initialization complete");
    Ok(guardian)
}

/// Performs graceful system shutdown
#[instrument]
pub async fn shutdown_guardian() -> Result<()> {
    info!("Initiating Guardian system shutdown");

    if let Some(guardian) = GUARDIAN_INSTANCE.get() {
        // Stop accepting new operations
        guardian.pause_operations().await?;

        // Wait for pending operations to complete
        guardian.wait_for_pending().await?;

        // Flush metrics and traces
        metrics::flush_metrics().await?;

        // Perform subsystem shutdown
        guardian.shutdown().await?;

        info!("Guardian system shutdown complete");
        Ok(())
    } else {
        warn!("Guardian system not initialized during shutdown");
        Ok(())
    }
}

/// Monitors system health and resource utilization
fn monitor_system_health(guardian: Arc<Guardian>) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
        
        loop {
            interval.tick().await;
            
            match guardian.health_check().await {
                Ok(health) => {
                    gauge!("guardian.health.status", health.score);
                    
                    if !health.is_healthy {
                        error!("System health check failed: {:?}", health);
                        counter!("guardian.health.failures", 1);
                    }
                }
                Err(e) => {
                    error!("Health check error: {:?}", e);
                    counter!("guardian.health.check_errors", 1);
                }
            }
        }
    });
}

// Re-exports for commonly used types
pub use core::Guardian;
pub use core::GuardianConfig;
pub use security::SecurityManager;
pub use utils::{GuardianError, Result};

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_guardian_initialization() {
        let config = GuardianConfig::default();
        let result = init_guardian(config).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_guardian_shutdown() {
        let config = GuardianConfig::default();
        let _ = init_guardian(config).await.unwrap();
        
        let result = shutdown_guardian().await;
        assert!(result.is_ok());
    }
}