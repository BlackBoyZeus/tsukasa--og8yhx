//! AI Guardian System - Main Entry Point
//! 
//! Initializes and coordinates the core runtime, logging, monitoring, and system services
//! for the AI Guardian security and management solution.
//! 
//! Version: 1.0.0
//! Dependencies:
//! - tokio v1.32
//! - tracing v0.1
//! - tracing-subscriber v0.3
//! - clap v4.0

use std::sync::Arc;
use std::time::Duration;
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};
use clap::{Command, Arg, ArgAction};

use guardian::{Guardian, Result};
use crate::config::app_config::AppConfig;
use crate::cli::run_cli;

// System version and metadata constants
const VERSION: &str = env!("CARGO_PKG_VERSION");
const AUTHOR: &str = "Guardian Security Team";
const DEFAULT_CONFIG_PATH: &str = "/etc/guardian/config.toml";

// Operational constants
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(30);
const HEALTH_CHECK_INTERVAL: Duration = Duration::from_secs(5);
const MAX_STARTUP_RETRIES: u32 = 3;

/// Initializes the logging and tracing system with security context
async fn setup_logging() -> Result<()> {
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_target(true)
        .with_thread_ids(true)
        .with_file(true)
        .with_line_number(true)
        .with_env_filter("guardian=debug,warn")
        .json()
        .with_current_span(true)
        .with_span_events(tracing_subscriber::fmt::format::FmtSpan::FULL)
        .try_init();

    match subscriber {
        Ok(_) => {
            info!("Logging system initialized successfully");
            Ok(())
        }
        Err(e) => {
            eprintln!("Failed to initialize logging: {}", e);
            Err(guardian::GuardianError::SystemError(
                "Logging initialization failed".to_string(),
            ))
        }
    }
}

/// Creates the command-line interface configuration
fn create_cli() -> Command {
    Command::new("guardian")
        .version(VERSION)
        .author(AUTHOR)
        .about("AI Guardian Security System")
        .arg(
            Arg::new("config")
                .short('c')
                .long("config")
                .value_name("FILE")
                .help("Path to configuration file")
                .default_value(DEFAULT_CONFIG_PATH),
        )
        .arg(
            Arg::new("verbose")
                .short('v')
                .long("verbose")
                .action(ArgAction::Count)
                .help("Increases logging verbosity"),
        )
}

/// Main entry point with comprehensive security and monitoring
#[tokio::main]
async fn main() -> Result<()> {
    // Parse command line arguments
    let matches = create_cli().get_matches();
    let config_path = matches.get_one::<String>("config").unwrap();
    
    // Initialize logging with security context
    setup_logging().await?;
    info!(version = VERSION, "Starting AI Guardian System");

    // Load and validate configuration
    let app_config = match AppConfig::new(Some(config_path.to_string()), None) {
        Ok(config) => {
            debug!("Configuration loaded successfully");
            config
        }
        Err(e) => {
            error!("Failed to load configuration: {}", e);
            return Err(e);
        }
    };

    // Initialize Guardian system
    let guardian = Arc::new(RwLock::new(
        Guardian::new(
            Arc::new(RwLock::new(
                app_config.security_config.clone()
            )),
            app_config.clone(),
        ).await?,
    ));
    
    // Start health monitoring
    let health_guardian = guardian.clone();
    tokio::spawn(async move {
        loop {
            if let Err(e) = health_guardian.read().await.check_health().await {
                error!("Health check failed: {}", e);
            }
            tokio::time::sleep(HEALTH_CHECK_INTERVAL).await;
        }
    });

    // Set up signal handlers
    let mut sigterm = signal(SignalKind::terminate())?;
    let mut sigint = signal(SignalKind::interrupt())?;
    
    // Start CLI handler
    let cli_guardian = guardian.clone();
    tokio::spawn(async move {
        if let Err(e) = run_cli(std::env::args().collect()) {
            error!("CLI error: {}", e);
        }
    });

    // Wait for shutdown signal
    tokio::select! {
        _ = sigterm.recv() => {
            info!("Received SIGTERM signal");
        }
        _ = sigint.recv() => {
            info!("Received SIGINT signal");
        }
    }

    // Perform graceful shutdown
    info!("Initiating graceful shutdown");
    let shutdown_result = tokio::time::timeout(
        SHUTDOWN_TIMEOUT,
        guardian.read().await.shutdown()
    ).await;

    match shutdown_result {
        Ok(Ok(_)) => {
            info!("Guardian system shutdown completed successfully");
            Ok(())
        }
        Ok(Err(e)) => {
            error!("Error during shutdown: {}", e);
            Err(e)
        }
        Err(_) => {
            error!("Shutdown timed out after {:?}", SHUTDOWN_TIMEOUT);
            Err(guardian::GuardianError::SystemError(
                "Shutdown timed out".to_string(),
            ))
        }
    }
}