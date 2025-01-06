use std::{sync::Arc, time::Duration};
use tokio::signal;
use tracing::{debug, error, info, warn, instrument};
use metrics::{counter, gauge};
use uuid::Uuid;

use guardian_lib::{Guardian, GuardianConfig};
use config::app_config::AppConfig;
use cli::run_cli;
use security::{SecurityContext, SecurityConfig};

// Core system constants
const VERSION: &str = env!("CARGO_PKG_VERSION");
const APP_NAME: &str = "guardian";
const CONFIG_PATH: &str = "config/guardian.toml";
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_MEMORY_PERCENT: f64 = 5.0;

/// Main entry point for the Guardian system
#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
#[tracing::instrument(name = "guardian_main", err)]
async fn main() -> Result<(), GuardianError> {
    let correlation_id = Uuid::new_v4();
    info!(
        version = VERSION,
        correlation_id = %correlation_id,
        "Starting AI Guardian system"
    );

    // Initialize security context
    let security_ctx = SecurityContext::new().map_err(|e| GuardianError::SecurityError {
        context: "Failed to initialize security context".into(),
        source: Some(Box::new(e)),
        severity: crate::utils::error::ErrorSeverity::Critical,
        timestamp: time::OffsetDateTime::now_utc(),
        correlation_id,
        category: crate::utils::error::ErrorCategory::Security,
        retry_count: 0,
    })?;

    // Load and validate configuration
    let config = AppConfig::load(std::path::PathBuf::from(CONFIG_PATH))?;
    config.validate()?;

    // Initialize tracing with security context
    init_tracing(&config, &security_ctx)?;

    // Initialize core Guardian system
    let guardian_config = GuardianConfig {
        app_name: APP_NAME.to_string(),
        version: VERSION.to_string(),
        environment: config.environment,
        max_threads: config.max_threads,
        max_memory: config.max_memory,
        security_settings: config.security_settings,
        monitoring_config: config.monitoring_config,
    };

    let guardian = Guardian::new(guardian_config)?;
    guardian.start().await?;

    // Record startup metrics
    counter!("guardian.system.starts", 1);
    gauge!("guardian.system.max_memory_mb", config.max_memory as f64);

    // Handle CLI mode if specified
    if std::env::args().any(|arg| arg == "--cli") {
        run_cli().await?;
        return Ok(());
    }

    // Wait for shutdown signal
    shutdown_signal(guardian, security_ctx).await?;

    info!("Guardian system shutdown complete");
    Ok(())
}

/// Initializes the tracing system with security context
#[instrument(skip(config, security_ctx), err)]
fn init_tracing(config: &AppConfig, security_ctx: &SecurityContext) -> Result<(), GuardianError> {
    use tracing_subscriber::{
        fmt::{self, time::UtcTime},
        EnvFilter,
        layer::SubscriberExt,
        util::SubscriberInitExt,
    };

    // Validate security context before initializing tracing
    security_ctx.validate()?;

    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info"));

    let formatting_layer = fmt::layer()
        .with_target(true)
        .with_thread_ids(true)
        .with_line_number(true)
        .with_timer(UtcTime::rfc_3339())
        .with_file(true);

    tracing_subscriber::registry()
        .with(env_filter)
        .with(formatting_layer)
        .try_init()
        .map_err(|e| GuardianError::SystemError {
            context: "Failed to initialize tracing".into(),
            source: Some(Box::new(e)),
            severity: crate::utils::error::ErrorSeverity::Critical,
            timestamp: time::OffsetDateTime::now_utc(),
            correlation_id: Uuid::new_v4(),
            category: crate::utils::error::ErrorCategory::System,
            retry_count: 0,
        })?;

    Ok(())
}

/// Handles system shutdown signals with graceful cleanup
#[instrument(skip(guardian, security_ctx), err)]
async fn shutdown_signal(guardian: Guardian, security_ctx: SecurityContext) -> Result<(), GuardianError> {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("Failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    // Wait for shutdown signal
    tokio::select! {
        _ = ctrl_c => {
            info!("Received Ctrl+C signal");
        }
        _ = terminate => {
            info!("Received termination signal");
        }
    }

    // Initiate graceful shutdown
    info!("Initiating graceful shutdown");
    counter!("guardian.system.shutdowns", 1);

    // Verify security context before shutdown
    security_ctx.validate()?;

    // Perform health check before shutdown
    if let Err(e) = guardian.health_check().await {
        warn!(error = ?e, "Health check failed during shutdown");
    }

    // Shutdown with timeout
    match tokio::time::timeout(SHUTDOWN_TIMEOUT, guardian.shutdown()).await {
        Ok(result) => result?,
        Err(_) => {
            error!("Shutdown timed out after {:?}", SHUTDOWN_TIMEOUT);
            counter!("guardian.system.shutdown_timeouts", 1);
        }
    }

    Ok(())
}