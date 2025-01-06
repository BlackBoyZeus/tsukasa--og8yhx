use clap::{Arg, ArgMatches, Command};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info, instrument, warn};
use metrics::{counter, gauge, histogram};

use crate::cli::commands::Command as CliCommand;
use crate::ml::model_registry::ModelRegistry;
use crate::ml::model_manager::ModelManager;
use crate::utils::error::GuardianError;

// Constants for model management operations
const COMMAND_NAME: &str = "models";
const HELP_TEXT: &str = "Securely manage ML models and versions with resource monitoring";
const OPERATION_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_RESOURCE_USAGE: f64 = 0.85;

/// Implements secure ML model management CLI commands with comprehensive monitoring
#[derive(Debug)]
pub struct ModelsCommand {
    registry: Arc<ModelRegistry>,
    manager: Arc<ModelManager>,
    resource_monitor: Arc<RwLock<ResourceMonitor>>,
}

impl ModelsCommand {
    /// Creates new ModelsCommand instance with secure dependencies
    pub fn new(
        registry: Arc<ModelRegistry>,
        manager: Arc<ModelManager>,
        resource_monitor: Arc<RwLock<ResourceMonitor>>,
    ) -> Self {
        Self {
            registry,
            manager,
            resource_monitor,
        }
    }

    /// Lists all registered ML models with security context
    #[instrument]
    async fn list_models(&self) -> Result<(), GuardianError> {
        info!("Listing registered models");
        
        // Check resource availability
        self.check_resources().await?;

        let models = self.registry.list_models().await?;
        
        println!("\nRegistered Models:");
        println!("{:<20} {:<15} {:<10} {:<15}", "MODEL ID", "VERSION", "STATUS", "LAST UPDATED");
        println!("{}", "-".repeat(60));

        for model in models {
            let status = self.manager.get_model_status(&model.id).await?;
            println!(
                "{:<20} {:<15} {:<10} {:<15}",
                model.id,
                model.version,
                status,
                model.updated_at.format("%Y-%m-%d %H:%M")
            );
        }

        // Record metrics
        counter!("guardian.cli.models.list").increment(1);
        Ok(())
    }

    /// Shows detailed model status with resource metrics
    #[instrument]
    async fn show_status(&self, model_id: String) -> Result<(), GuardianError> {
        info!(model_id = %model_id, "Showing model status");

        // Validate model existence
        let model = self.registry.get_model_version(&model_id, None).await?;
        let status = self.manager.get_model_status(&model_id).await?;
        let resources = self.manager.check_resources(&model_id).await?;

        println!("\nModel Status:");
        println!("ID:              {}", model_id);
        println!("Version:         {}", model.version);
        println!("Status:          {}", status);
        println!("Memory Usage:    {}MB", resources.memory_mb);
        println!("CPU Usage:       {}%", resources.cpu_percent);
        println!("GPU Usage:       {}%", resources.gpu_percent);
        println!("Last Inference:  {}", model.last_inference.unwrap_or_default());
        println!("Error Rate:      {}%", resources.error_rate);

        // Record metrics
        counter!("guardian.cli.models.status").increment(1);
        histogram!("guardian.models.memory_usage").record(resources.memory_mb as f64);
        
        Ok(())
    }

    /// Securely activates a specific model version
    #[instrument]
    async fn activate_version(&self, model_id: String, version: String) -> Result<(), GuardianError> {
        info!(
            model_id = %model_id,
            version = %version,
            "Activating model version"
        );

        // Validate model and version
        self.registry.validate_model(&model_id, &version).await?;

        // Check resource availability
        self.check_resources().await?;

        // Activate version with monitoring
        let start = std::time::Instant::now();
        self.registry.set_active_version(model_id.clone(), version.clone()).await?;

        // Record metrics
        counter!("guardian.cli.models.activate").increment(1);
        histogram!("guardian.models.activation_time").record(start.elapsed().as_secs_f64());

        println!("Successfully activated model {} version {}", model_id, version);
        Ok(())
    }

    /// Checks system resource availability
    async fn check_resources(&self) -> Result<(), GuardianError> {
        let monitor = self.resource_monitor.read().await;
        let usage = monitor.get_resource_usage().await?;

        if usage.memory_percent > MAX_RESOURCE_USAGE 
            || usage.cpu_percent > MAX_RESOURCE_USAGE 
            || usage.gpu_percent > MAX_RESOURCE_USAGE {
            return Err(GuardianError::ResourceError(
                "System resources exceeded maximum threshold".to_string()
            ));
        }
        Ok(())
    }
}

#[async_trait::async_trait]
impl CliCommand for ModelsCommand {
    fn name(&self) -> &'static str {
        COMMAND_NAME
    }

    fn configure(&self) -> Command {
        Command::new(COMMAND_NAME)
            .about(HELP_TEXT)
            .subcommand(Command::new("list")
                .about("List all registered models"))
            .subcommand(Command::new("status")
                .about("Show model status and metrics")
                .arg(Arg::new("model-id")
                    .required(true)
                    .help("Model identifier")))
            .subcommand(Command::new("activate")
                .about("Activate model version")
                .arg(Arg::new("model-id")
                    .required(true)
                    .help("Model identifier"))
                .arg(Arg::new("version")
                    .required(true)
                    .help("Version to activate")))
    }

    async fn execute(&self, args: &ArgMatches) -> Result<(), GuardianError> {
        match args.subcommand() {
            Some(("list", _)) => {
                self.list_models().await
            }
            Some(("status", sub_matches)) => {
                let model_id = sub_matches.get_one::<String>("model-id")
                    .ok_or_else(|| GuardianError::ValidationError("Model ID required".to_string()))?;
                self.show_status(model_id.clone()).await
            }
            Some(("activate", sub_matches)) => {
                let model_id = sub_matches.get_one::<String>("model-id")
                    .ok_or_else(|| GuardianError::ValidationError("Model ID required".to_string()))?;
                let version = sub_matches.get_one::<String>("version")
                    .ok_or_else(|| GuardianError::ValidationError("Version required".to_string()))?;
                self.activate_version(model_id.clone(), version.clone()).await
            }
            _ => Err(GuardianError::ValidationError("Invalid subcommand".to_string())),
        }
    }

    fn required_access(&self) -> AccessLevel {
        AccessLevel::DataScientist
    }

    fn help(&self) -> &'static str {
        HELP_TEXT
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn test_list_models() {
        // Test implementation
    }

    #[tokio::test]
    async fn test_show_status() {
        // Test implementation
    }

    #[tokio::test]
    async fn test_activate_version() {
        // Test implementation
    }

    #[tokio::test]
    async fn test_resource_check() {
        // Test implementation
    }
}