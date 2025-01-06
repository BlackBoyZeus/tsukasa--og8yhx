//! Core module for the AI Guardian system that coordinates fundamental components
//! Version: 1.0.0
//! 
//! This module serves as the central coordination point for the Guardian system,
//! providing efficient resource utilization, real-time protection capabilities,
//! and autonomous response orchestration.

use tokio::runtime::{Builder, Runtime}; // v1.32
use tracing::{info, error, instrument}; // v0.1
use crate::utils::error::{GuardianError, Result};

// Core module version and name constants
pub const CORE_VERSION: &str = "1.0.0";
pub const CORE_MODULE_NAME: &str = "guardian_core";

// Export core submodules
pub mod metrics;
pub mod event_bus;
pub mod system_state;
pub mod guardian;

// Re-export commonly used types
pub use metrics::{CoreMetricsManager, SystemMetricType};
pub use event_bus::{EventBus, Event};
pub use system_state::{SystemState, SystemStatus};
pub use guardian::{Guardian, GuardianConfig};

/// Runtime configuration for the Guardian core system
#[derive(Debug)]
struct CoreRuntime {
    runtime: Runtime,
    metrics_manager: CoreMetricsManager,
    event_bus: EventBus,
    system_state: SystemState,
}

impl CoreRuntime {
    /// Creates a new optimized runtime instance for the Guardian core
    fn new() -> Result<Self> {
        let runtime = Builder::new_multi_thread()
            .thread_name("guardian-core")
            .enable_all()
            .build()
            .map_err(|e| GuardianError::SystemError {
                context: "Failed to initialize core runtime".into(),
                source: Some(Box::new(e)),
                severity: crate::utils::error::ErrorSeverity::Critical,
                timestamp: time::OffsetDateTime::now_utc(),
                correlation_id: uuid::Uuid::new_v4(),
                category: crate::utils::error::ErrorCategory::System,
                retry_count: 0,
            })?;

        let metrics_manager = CoreMetricsManager::new()?;
        let event_bus = EventBus::new()?;
        let system_state = SystemState::new()?;

        Ok(Self {
            runtime,
            metrics_manager,
            event_bus,
            system_state,
        })
    }
}

/// Initializes all core components of the Guardian system
#[instrument(skip(config), fields(version = %CORE_VERSION))]
pub async fn init_core(config: GuardianConfig) -> Result<Guardian> {
    info!("Initializing Guardian core system v{}", CORE_VERSION);

    // Initialize core runtime with optimized settings
    let core_runtime = CoreRuntime::new()?;

    // Validate configuration parameters
    config.validate().map_err(|e| GuardianError::ValidationError {
        context: "Invalid core configuration".into(),
        source: Some(Box::new(e)),
        severity: crate::utils::error::ErrorSeverity::Critical,
        timestamp: time::OffsetDateTime::now_utc(),
        correlation_id: uuid::Uuid::new_v4(),
        category: crate::utils::error::ErrorCategory::Validation,
        retry_count: 0,
    })?;

    // Initialize core Guardian instance with validated components
    let guardian = Guardian::new(
        config,
        core_runtime.metrics_manager,
        core_runtime.event_bus,
        core_runtime.system_state,
    )?;

    // Register shutdown handlers
    tokio::spawn(async move {
        handle_shutdown_signals(guardian.clone()).await;
    });

    info!("Guardian core system initialization complete");
    Ok(guardian)
}

/// Handles system shutdown signals gracefully
async fn handle_shutdown_signals(guardian: Guardian) {
    use tokio::signal::unix::{signal, SignalKind};
    
    let mut sigterm = signal(SignalKind::terminate())
        .expect("Failed to register SIGTERM handler");
    let mut sigint = signal(SignalKind::interrupt())
        .expect("Failed to register SIGINT handler");

    tokio::select! {
        _ = sigterm.recv() => {
            info!("Received SIGTERM signal");
        }
        _ = sigint.recv() => {
            info!("Received SIGINT signal");
        }
    }

    if let Err(e) = guardian.shutdown().await {
        error!("Error during shutdown: {:?}", e);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_core_initialization() {
        let config = GuardianConfig::default();
        let result = init_core(config).await;
        assert!(result.is_ok());
    }

    #[test]
    fn test_core_runtime_creation() {
        let runtime = CoreRuntime::new();
        assert!(runtime.is_ok());
    }
}