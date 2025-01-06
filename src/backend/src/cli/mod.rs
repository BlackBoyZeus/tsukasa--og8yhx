use std::time::Duration;
use clap::{Command, ArgMatches};
use tracing::{debug, error, info, instrument};
use tokio::time;
use uuid::Uuid;

use crate::utils::error::{GuardianError, ErrorCategory, ErrorSeverity};
use crate::utils::metrics::{record_command_execution, track_command_latency};
use crate::cli::commands::{register_commands, CommandRegistry};

// Constants for CLI configuration
const CLI_VERSION: &str = env!("CARGO_PKG_VERSION");
const APP_NAME: &str = "guardian-ctl";
const APP_DESCRIPTION: &str = "Guardian system management and security operations tool";
const COMMAND_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_RATE_LIMIT: u32 = 10;

/// Main entry point for the Guardian CLI application
#[tokio::main]
#[tracing::instrument(err)]
pub async fn run_cli() -> Result<(), GuardianError> {
    // Generate correlation ID for request tracking
    let correlation_id = Uuid::new_v4();
    debug!(correlation_id = %correlation_id, "Starting CLI execution");

    // Initialize metrics collector
    let metrics = Arc::new(metrics::MetricsCollector::new(
        metrics::MetricsConfig {
            statsd_host: "localhost".into(),
            statsd_port: 8125,
            buffer_size: Some(1000),
            flush_interval: Some(Duration::from_secs(60)),
            sampling_rates: None,
        },
    )?);

    // Initialize audit logging
    let audit_log = Arc::new(crate::utils::logging::LogManager::new());

    // Initialize command registry
    let mut registry = CommandRegistry::new(metrics.clone(), audit_log);

    // Register available commands
    register_commands(&mut registry)?;

    // Set up CLI application
    let cli = setup_cli();

    // Parse command line arguments
    let matches = cli.get_matches();

    // Execute command with timeout
    let start_time = time::Instant::now();
    let result = match time::timeout(COMMAND_TIMEOUT, execute_command(&registry, matches)).await {
        Ok(result) => result,
        Err(_) => {
            error!("Command execution timeout");
            return Err(GuardianError::TimeoutError {
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
    record_command_execution("cli.command", correlation_id, start_time)?;
    track_command_latency(start_time.elapsed())?;

    result
}

/// Sets up the CLI application with commands and arguments
fn setup_cli() -> Command {
    Command::new(APP_NAME)
        .version(CLI_VERSION)
        .about(APP_DESCRIPTION)
        .subcommand(commands::config::build_config_subcommand())
        .subcommand(commands::status::build_status_subcommand())
        .subcommand(commands::threats::build_threats_subcommand())
        .subcommand(commands::models::build_models_subcommand())
        .arg(
            clap::Arg::new("verbose")
                .short('v')
                .long("verbose")
                .help("Enable verbose output")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            clap::Arg::new("no-color")
                .long("no-color")
                .help("Disable colored output")
                .action(clap::ArgAction::SetTrue),
        )
}

/// Executes the requested command with access control
async fn execute_command(registry: &CommandRegistry, matches: ArgMatches) -> Result<(), GuardianError> {
    if let Some((cmd_name, cmd_matches)) = matches.subcommand() {
        // Determine access level based on user context
        let access_level = determine_access_level()?;

        // Execute command through registry
        registry.execute(cmd_name.to_string(), cmd_matches.clone(), access_level).await?;
    } else {
        // Show help if no subcommand provided
        println!("{}", setup_cli().render_help());
    }

    Ok(())
}

/// Determines user access level from environment
fn determine_access_level() -> Result<commands::AccessLevel, GuardianError> {
    // In a real implementation, this would check user credentials and roles
    // For now, return operator level access
    Ok(commands::AccessLevel::Operator)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_cli_execution() {
        let result = run_cli().await;
        assert!(result.is_ok());
    }

    #[test]
    fn test_cli_setup() {
        let cli = setup_cli();
        assert_eq!(cli.get_name(), APP_NAME);
        assert_eq!(cli.get_version(), Some(CLI_VERSION));
    }
}