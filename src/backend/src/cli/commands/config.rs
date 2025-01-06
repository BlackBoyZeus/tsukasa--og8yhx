use clap::{Arg, ArgMatches, Command};
use serde_json::Value;
use tracing::{debug, error, info, instrument, warn};
use std::path::PathBuf;
use std::sync::Arc;

use crate::cli::commands::Command as CliCommand;
use crate::config::app_config::AppConfig;
use crate::utils::error::GuardianError;
use crate::utils::validation::{validate_input, ValidationRules};

// Configuration command constants
const DEFAULT_CONFIG_PATH: &str = "/etc/guardian/config.yaml";
const CONFIG_COMMAND_NAME: &str = "config";
const MAX_CONFIG_SIZE: usize = 10 * 1024 * 1024; // 10MB
const CONFIG_BACKUP_COUNT: usize = 5;

/// Configuration version tracking
#[derive(Debug, Clone)]
struct ConfigVersion {
    version: String,
    last_updated: String,
    update_count: u32,
}

/// Resource monitoring for config operations
#[derive(Debug)]
struct ResourceMonitor {
    max_memory: usize,
    max_file_size: usize,
}

/// Command implementation for configuration management
#[derive(Debug)]
pub struct ConfigCommand {
    config_path: String,
    version: ConfigVersion,
    monitor: ResourceMonitor,
}

impl ConfigCommand {
    /// Creates a new ConfigCommand instance
    pub fn new() -> Self {
        Self {
            config_path: DEFAULT_CONFIG_PATH.to_string(),
            version: ConfigVersion {
                version: env!("CARGO_PKG_VERSION").to_string(),
                last_updated: chrono::Utc::now().to_rfc3339(),
                update_count: 0,
            },
            monitor: ResourceMonitor {
                max_memory: MAX_CONFIG_SIZE,
                max_file_size: MAX_CONFIG_SIZE,
            },
        }
    }

    /// Builds the configuration command interface
    fn build_cli() -> Command {
        Command::new(CONFIG_COMMAND_NAME)
            .about("Manage Guardian system configuration")
            .subcommand(
                Command::new("get")
                    .about("Get configuration values")
                    .arg(
                        Arg::new("key")
                            .help("Configuration key to retrieve")
                            .required(false)
                            .index(1),
                    )
                    .arg(
                        Arg::new("format")
                            .short('f')
                            .long("format")
                            .help("Output format (json|yaml)")
                            .default_value("json"),
                    ),
            )
            .subcommand(
                Command::new("set")
                    .about("Set configuration values")
                    .arg(
                        Arg::new("key")
                            .help("Configuration key to set")
                            .required(true),
                    )
                    .arg(
                        Arg::new("value")
                            .help("Value to set")
                            .required(true),
                    )
                    .arg(
                        Arg::new("encrypt")
                            .short('e')
                            .long("encrypt")
                            .help("Encrypt sensitive values"),
                    ),
            )
            .subcommand(
                Command::new("validate")
                    .about("Validate configuration")
                    .arg(
                        Arg::new("path")
                            .short('p')
                            .long("path")
                            .help("Configuration file path"),
                    ),
            )
            .subcommand(
                Command::new("backup")
                    .about("Backup configuration")
                    .arg(
                        Arg::new("output")
                            .short('o')
                            .long("output")
                            .help("Backup file path"),
                    ),
            )
            .subcommand(
                Command::new("restore")
                    .about("Restore configuration from backup")
                    .arg(
                        Arg::new("input")
                            .help("Backup file path")
                            .required(true),
                    ),
            )
            .subcommand(
                Command::new("encrypt")
                    .about("Encrypt configuration file")
                    .arg(
                        Arg::new("key")
                            .short('k')
                            .long("key")
                            .help("Encryption key file")
                            .required(true),
                    ),
            )
    }

    /// Handles the get configuration command
    #[instrument(skip(matches))]
    fn handle_get(&self, matches: &ArgMatches) -> Result<(), GuardianError> {
        let config = AppConfig::new(Some(self.config_path.clone()), None)?;
        
        if let Some(key) = matches.get_one::<String>("key") {
            // Validate key format
            validate_input(key, &ValidationRules {
                required: true,
                min_length: Some(1),
                max_length: Some(256),
                pattern: Some(r"^[a-zA-Z0-9_\.]+$".to_string()),
                ..Default::default()
            })?;

            let value = config.get_value(key)
                .ok_or_else(|| GuardianError::ConfigError(format!("Key not found: {}", key)))?;

            match matches.get_one::<String>("format").map(String::as_str) {
                Some("json") => println!("{}", serde_json::to_string_pretty(&value)?),
                Some("yaml") => println!("{}", serde_yaml::to_string(&value)?),
                _ => println!("{:?}", value),
            }
        } else {
            // Display entire configuration
            match matches.get_one::<String>("format").map(String::as_str) {
                Some("json") => println!("{}", serde_json::to_string_pretty(&config)?),
                Some("yaml") => println!("{}", serde_yaml::to_string(&config)?),
                _ => println!("{:?}", config),
            }
        }

        Ok(())
    }

    /// Handles the set configuration command
    #[instrument(skip(matches))]
    fn handle_set(&self, matches: &ArgMatches) -> Result<(), GuardianError> {
        let mut config = AppConfig::new(Some(self.config_path.clone()), None)?;
        
        let key = matches.get_one::<String>("key")
            .ok_or_else(|| GuardianError::ValidationError("Key is required".to_string()))?;
        let value = matches.get_one::<String>("value")
            .ok_or_else(|| GuardianError::ValidationError("Value is required".to_string()))?;

        // Validate key and value
        validate_input(key, &ValidationRules {
            required: true,
            min_length: Some(1),
            max_length: Some(256),
            pattern: Some(r"^[a-zA-Z0-9_\.]+$".to_string()),
            ..Default::default()
        })?;

        // Handle encryption if requested
        let final_value = if matches.get_flag("encrypt") {
            config.encrypt_value(value)?
        } else {
            value.to_string()
        };

        config.set_value(key, &final_value)?;
        config.validate()?;
        config.save(&self.config_path)?;

        info!(key = key, "Configuration value updated successfully");
        Ok(())
    }

    /// Handles the validate configuration command
    #[instrument(skip(matches))]
    fn handle_validate(&self, matches: &ArgMatches) -> Result<(), GuardianError> {
        let config_path = matches.get_one::<String>("path")
            .map(String::from)
            .unwrap_or_else(|| self.config_path.clone());

        let config = AppConfig::new(Some(config_path), None)?;
        config.validate()?;

        info!("Configuration validation successful");
        Ok(())
    }

    /// Handles the backup configuration command
    #[instrument(skip(matches))]
    fn handle_backup(&self, matches: &ArgMatches) -> Result<(), GuardianError> {
        let config = AppConfig::new(Some(self.config_path.clone()), None)?;
        
        let output_path = matches.get_one::<String>("output")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S");
                PathBuf::from(format!("{}.{}.backup", self.config_path, timestamp))
            });

        config.backup(&output_path)?;
        
        info!(
            path = %output_path.display(),
            "Configuration backup created successfully"
        );
        Ok(())
    }

    /// Handles the restore configuration command
    #[instrument(skip(matches))]
    fn handle_restore(&self, matches: &ArgMatches) -> Result<(), GuardianError> {
        let input_path = matches.get_one::<String>("input")
            .ok_or_else(|| GuardianError::ValidationError("Backup file path is required".to_string()))?;

        let config = AppConfig::new(None, None)?;
        config.restore(input_path)?;
        
        info!(
            path = input_path,
            "Configuration restored successfully"
        );
        Ok(())
    }

    /// Handles the encrypt configuration command
    #[instrument(skip(matches))]
    fn handle_encrypt(&self, matches: &ArgMatches) -> Result<(), GuardianError> {
        let key_file = matches.get_one::<String>("key")
            .ok_or_else(|| GuardianError::ValidationError("Encryption key file is required".to_string()))?;

        let config = AppConfig::new(Some(self.config_path.clone()), None)?;
        config.encrypt_file(key_file)?;
        
        info!("Configuration encrypted successfully");
        Ok(())
    }
}

impl CliCommand for ConfigCommand {
    fn name(&self) -> &'static str {
        CONFIG_COMMAND_NAME
    }

    #[instrument(skip(self, args))]
    fn execute(&self, args: &[String]) -> Result<(), GuardianError> {
        // Check resource limits
        if args.iter().map(|s| s.len()).sum::<usize>() > self.monitor.max_memory {
            return Err(GuardianError::ResourceError("Command arguments exceed size limit".to_string()));
        }

        // Parse command arguments
        let matches = Self::build_cli().try_get_matches_from(args)
            .map_err(|e| GuardianError::ValidationError(e.to_string()))?;

        // Execute appropriate subcommand
        match matches.subcommand() {
            Some(("get", sub_matches)) => self.handle_get(sub_matches),
            Some(("set", sub_matches)) => self.handle_set(sub_matches),
            Some(("validate", sub_matches)) => self.handle_validate(sub_matches),
            Some(("backup", sub_matches)) => self.handle_backup(sub_matches),
            Some(("restore", sub_matches)) => self.handle_restore(sub_matches),
            Some(("encrypt", sub_matches)) => self.handle_encrypt(sub_matches),
            _ => Err(GuardianError::ValidationError("Invalid subcommand".to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_config_command_creation() {
        let cmd = ConfigCommand::new();
        assert_eq!(cmd.name(), CONFIG_COMMAND_NAME);
        assert_eq!(cmd.config_path, DEFAULT_CONFIG_PATH);
    }

    #[test]
    fn test_config_validation() {
        let cmd = ConfigCommand::new();
        let result = cmd.execute(&["config".to_string(), "validate".to_string()]);
        assert!(result.is_ok());
    }

    #[test]
    fn test_config_backup_restore() {
        let dir = tempdir().unwrap();
        let backup_path = dir.path().join("config.backup");
        
        let cmd = ConfigCommand::new();
        
        // Create backup
        let backup_result = cmd.execute(&[
            "config".to_string(),
            "backup".to_string(),
            "--output".to_string(),
            backup_path.to_str().unwrap().to_string(),
        ]);
        assert!(backup_result.is_ok());

        // Restore from backup
        let restore_result = cmd.execute(&[
            "config".to_string(),
            "restore".to_string(),
            backup_path.to_str().unwrap().to_string(),
        ]);
        assert!(restore_result.is_ok());
    }
}