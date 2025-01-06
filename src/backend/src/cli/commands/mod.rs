use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use clap::ArgMatches;
use metrics::{counter, histogram};
use tokio::time;
use tracing::{debug, error, info, instrument};

use crate::utils::error::{GuardianError, ErrorCategory, ErrorSeverity};

// Import command modules
mod config;
mod status;
mod threats;
mod models;

pub use config::ConfigCommand;
pub use status::StatusCommand;
pub use threats::ThreatsCommand;
pub use models::ModelsCommand;

// Constants for CLI configuration
const CLI_VERSION: &str = env!("CARGO_PKG_VERSION");
const APP_NAME: &str = "guardian-ctl";
const COMMAND_TIMEOUT: Duration = Duration::from_secs(1);

/// Access levels for command execution
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessLevel {
    Admin,
    Security,
    Operator,
    DataScientist,
}

/// Core trait defining command interface with access control
#[async_trait::async_trait]
pub trait Command: Send + Sync {
    /// Executes the command with access validation
    async fn execute(&self, args: ArgMatches) -> Result<(), GuardianError>;

    /// Returns required access level for command
    fn access_level(&self) -> AccessLevel;
}

/// Central registry for managing CLI commands with access control
#[derive(Debug)]
pub struct CommandRegistry {
    commands: HashMap<String, Box<dyn Command>>,
    metrics: Arc<metrics::MetricsCollector>,
    audit_log: Arc<crate::utils::logging::LogManager>,
}

impl CommandRegistry {
    /// Creates a new CommandRegistry instance with metrics and audit logging
    pub fn new(
        metrics: Arc<metrics::MetricsCollector>,
        audit_log: Arc<crate::utils::logging::LogManager>,
    ) -> Self {
        Self {
            commands: HashMap::new(),
            metrics,
            audit_log,
        }
    }

    /// Registers a new command with access level validation
    pub fn register(&mut self, name: String, command: Box<dyn Command>) -> Result<(), GuardianError> {
        // Validate command name
        if name.is_empty() {
            return Err(GuardianError::ValidationError {
                context: "Command name cannot be empty".into(),
                source: None,
                severity: ErrorSeverity::Medium,
                timestamp: time::OffsetDateTime::now_utc(),
                correlation_id: uuid::Uuid::new_v4(),
                category: ErrorCategory::Validation,
                retry_count: 0,
            });
        }

        // Check for existing command
        if self.commands.contains_key(&name) {
            return Err(GuardianError::ValidationError {
                context: format!("Command {} already registered", name),
                source: None,
                severity: ErrorSeverity::Medium,
                timestamp: time::OffsetDateTime::now_utc(),
                correlation_id: uuid::Uuid::new_v4(),
                category: ErrorCategory::Validation,
                retry_count: 0,
            });
        }

        // Register command
        self.commands.insert(name.clone(), command);
        
        info!("Registered command: {}", name);
        Ok(())
    }

    /// Executes a command with access validation and metrics
    #[instrument(skip(self, args))]
    pub async fn execute(
        &self,
        name: String,
        args: ArgMatches,
        access_level: AccessLevel,
    ) -> Result<(), GuardianError> {
        let start_time = Instant::now();
        let correlation_id = uuid::Uuid::new_v4();

        debug!(
            correlation_id = %correlation_id,
            command = %name,
            "Executing command"
        );

        // Look up command
        let command = self.commands.get(&name).ok_or_else(|| GuardianError::ValidationError {
            context: format!("Command {} not found", name),
            source: None,
            severity: ErrorSeverity::Medium,
            timestamp: time::OffsetDateTime::now_utc(),
            correlation_id,
            category: ErrorCategory::Validation,
            retry_count: 0,
        })?;

        // Validate access level
        self.validate_access(command.access_level(), access_level)?;

        // Execute with timeout
        let result = match time::timeout(COMMAND_TIMEOUT, command.execute(args)).await {
            Ok(res) => res,
            Err(_) => {
                error!("Command execution timeout");
                return Err(GuardianError::SystemError {
                    context: "Command execution timeout".into(),
                    source: None,
                    severity: ErrorSeverity::High,
                    timestamp: time::OffsetDateTime::now_utc(),
                    correlation_id,
                    category: ErrorCategory::System,
                    retry_count: 0,
                });
            }
        };

        // Record metrics
        let execution_time = start_time.elapsed();
        histogram!("guardian.cli.execution_time", execution_time.as_secs_f64());
        counter!("guardian.cli.commands.executed", 1);

        if let Err(e) = &result {
            counter!("guardian.cli.commands.failed", 1);
            error!(
                error = ?e,
                command = %name,
                correlation_id = %correlation_id,
                "Command execution failed"
            );
        }

        result
    }

    /// Validates user access level against command requirements
    fn validate_access(&self, required: AccessLevel, user: AccessLevel) -> Result<(), GuardianError> {
        let authorized = match required {
            AccessLevel::Admin => user == AccessLevel::Admin,
            AccessLevel::Security => matches!(user, AccessLevel::Admin | AccessLevel::Security),
            AccessLevel::Operator => matches!(
                user,
                AccessLevel::Admin | AccessLevel::Security | AccessLevel::Operator
            ),
            AccessLevel::DataScientist => matches!(
                user,
                AccessLevel::Admin | AccessLevel::DataScientist
            ),
        };

        if !authorized {
            return Err(GuardianError::SecurityError {
                context: "Insufficient access level".into(),
                source: None,
                severity: ErrorSeverity::High,
                timestamp: time::OffsetDateTime::now_utc(),
                correlation_id: uuid::Uuid::new_v4(),
                category: ErrorCategory::Security,
                retry_count: 0,
            });
        }

        Ok(())
    }
}

/// Registers all available CLI commands with their access levels
#[instrument(skip(registry))]
pub fn register_commands(registry: &mut CommandRegistry) -> Result<(), GuardianError> {
    // Register config command with admin access
    registry.register(
        "config".into(),
        Box::new(ConfigCommand::new(std::path::PathBuf::from("/etc/guardian/config.json"))?),
    )?;

    // Register status command with operator access
    registry.register(
        "status".into(),
        Box::new(StatusCommand::new(
            Arc::new(crate::core::system_state::SystemState::new(
                Arc::new(crate::core::metrics::CoreMetricsManager::new(
                    Arc::new(metrics::MetricsCollector::new()),
                    Default::default(),
                )?),
                Arc::new(crate::core::event_bus::EventBus::new(
                    Arc::new(crate::core::metrics::CoreMetricsManager::new(
                        Arc::new(metrics::MetricsCollector::new()),
                        Default::default(),
                    )?),
                )?),
                Default::default(),
            )?),
            Arc::new(crate::core::metrics::CoreMetricsManager::new(
                Arc::new(metrics::MetricsCollector::new()),
                Default::default(),
            )?),
        )),
    )?;

    // Register threats command with security access
    registry.register(
        "threats".into(),
        Box::new(ThreatsCommand::new(
            Arc::new(crate::security::threat_detection::ThreatDetector::new(
                Arc::new(crate::ml::inference_engine::InferenceEngine::new(
                    Arc::new(crate::ml::model_registry::ModelRegistry::new(
                        Arc::new(crate::storage::model_store::ModelStore::new(
                            Arc::new(crate::storage::zfs_manager::ZfsManager::new(
                                "guardian".into(),
                                vec![0u8; 32],
                                Arc::new(crate::utils::logging::LogManager::new()),
                                None,
                            ).await?),
                            std::path::PathBuf::from("/var/lib/guardian/models"),
                            Some(5),
                        ).await?),
                    ).await?),
                    Arc::new(crate::ml::feature_extractor::FeatureExtractor::new(
                        crate::core::metrics::CoreMetricsManager::new(
                            Arc::new(metrics::MetricsCollector::new()),
                            Default::default(),
                        )?,
                        None,
                    )),
                    Default::default(),
                ).await?),
                Arc::new(crate::core::event_bus::EventBus::new(
                    Arc::new(crate::core::metrics::CoreMetricsManager::new(
                        Arc::new(metrics::MetricsCollector::new()),
                        Default::default(),
                    )?),
                )?),
                Arc::new(metrics::MetricsCollector::new()),
                None,
            )),
            Arc::new(crate::security::response_engine::ResponseEngine::new(
                Arc::new(temporal_sdk::Client::new(
                    temporal_sdk::ConnectionOptions::default(),
                ).await?),
                Arc::new(crate::core::event_bus::EventBus::new(
                    Arc::new(crate::core::metrics::CoreMetricsManager::new(
                        Arc::new(metrics::MetricsCollector::new()),
                        Default::default(),
                    )?),
                )?),
                None,
            ).await?),
            Arc::new(metrics::MetricsCollector::new()),
        )),
    )?;

    // Register models command with data scientist access
    registry.register(
        "models".into(),
        Box::new(ModelsCommand::new(
            Arc::new(crate::ml::model_manager::ModelManager::new(
                Arc::new(crate::ml::model_registry::ModelRegistry::new(
                    Arc::new(crate::storage::model_store::ModelStore::new(
                        Arc::new(crate::storage::zfs_manager::ZfsManager::new(
                            "guardian".into(),
                            vec![0u8; 32],
                            Arc::new(crate::utils::logging::LogManager::new()),
                            None,
                        ).await?),
                        std::path::PathBuf::from("/var/lib/guardian/models"),
                        Some(5),
                    ).await?),
                ).await?),
                Arc::new(crate::storage::model_store::ModelStore::new(
                    Arc::new(crate::storage::zfs_manager::ZfsManager::new(
                        "guardian".into(),
                        vec![0u8; 32],
                        Arc::new(crate::utils::logging::LogManager::new()),
                        None,
                    ).await?),
                    std::path::PathBuf::from("/var/lib/guardian/models"),
                    Some(5),
                ).await?),
            ).await?),
            Arc::new(crate::ml::model_registry::ModelRegistry::new(
                Arc::new(crate::storage::model_store::ModelStore::new(
                    Arc::new(crate::storage::zfs_manager::ZfsManager::new(
                        "guardian".into(),
                        vec![0u8; 32],
                        Arc::new(crate::utils::logging::LogManager::new()),
                        None,
                    ).await?),
                    std::path::PathBuf::from("/var/lib/guardian/models"),
                    Some(5),
                ).await?),
            ).await?),
        )),
    )?;

    info!("All commands registered successfully");
    Ok(())
}