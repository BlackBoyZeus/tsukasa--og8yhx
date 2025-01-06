use std::{
    collections::HashMap,
    sync::Arc,
    time::Duration,
};
use tokio::sync::RwLock;
use tracing::{info, warn, error, instrument};
use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc};
use async_trait::async_trait;

use crate::utils::error::{GuardianError, ErrorCategory};
use crate::storage::model_store::ModelStore;

// Registry version and configuration constants
const REGISTRY_VERSION: &str = "1.0.0";
const MAX_MODEL_VERSIONS: usize = 10;
const MODEL_REGISTRY_PATH: &str = "registry/models";
const MODEL_VALIDATION_TIMEOUT: Duration = Duration::from_secs(30);
const CACHE_REFRESH_INTERVAL: Duration = Duration::from_secs(300);

/// Metadata for ML models in the registry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelMetadata {
    pub name: String,
    pub version: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub status: ModelStatus,
    pub metrics: Option<ModelMetrics>,
    pub validation_status: ValidationStatus,
    pub hash: String,
    pub size_bytes: u64,
}

/// Performance metrics for ML models
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelMetrics {
    pub inference_time_ms: f64,
    pub memory_usage_mb: f64,
    pub accuracy: f64,
    pub false_positives: u64,
    pub false_negatives: u64,
    pub total_inferences: u64,
    pub last_updated: DateTime<Utc>,
}

/// Model deployment status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ModelStatus {
    Active,
    Inactive,
    Failed,
    Validating,
    Deprecated,
}

/// Model validation status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ValidationStatus {
    Pending,
    Success,
    Failed(String),
}

/// Thread-safe model registry for managing ML model lifecycle
#[derive(Debug)]
pub struct ModelRegistry {
    model_store: Arc<ModelStore>,
    active_models: RwLock<HashMap<String, ModelMetadata>>,
    model_metrics: RwLock<HashMap<String, ModelMetrics>>,
}

#[async_trait]
impl ModelRegistry {
    /// Creates a new ModelRegistry instance with secure initialization
    pub async fn new(model_store: Arc<ModelStore>) -> Result<Self, GuardianError> {
        let registry = Self {
            model_store,
            active_models: RwLock::new(HashMap::new()),
            model_metrics: RwLock::new(HashMap::new()),
        };

        // Initialize registry state
        registry.load_registry_state().await?;
        
        // Start background metrics collection
        registry.start_metrics_collection();

        info!(
            version = REGISTRY_VERSION,
            "Model registry initialized successfully"
        );

        Ok(registry)
    }

    /// Registers a new model version with validation
    #[instrument(skip(self, model_data))]
    pub async fn register_model(
        &self,
        model_data: Vec<u8>,
        version: String,
        metadata: ModelMetadata,
    ) -> Result<ModelMetadata, GuardianError> {
        // Validate model data and version
        self.validate_model_data(&model_data, &version).await?;

        // Store model securely
        let stored_version = self.model_store.store_model(model_data, version.clone()).await?;

        // Create and validate metadata
        let mut metadata = metadata;
        metadata.version = version.clone();
        metadata.created_at = Utc::now();
        metadata.updated_at = Utc::now();
        metadata.status = ModelStatus::Inactive;
        metadata.validation_status = ValidationStatus::Pending;
        metadata.hash = stored_version.hash;
        metadata.size_bytes = stored_version.size;

        // Update registry state
        {
            let mut active_models = self.active_models.write().await;
            active_models.insert(version.clone(), metadata.clone());
        }

        info!(
            version = %version,
            size_bytes = metadata.size_bytes,
            "Model version registered successfully"
        );

        Ok(metadata)
    }

    /// Activates a model version with performance optimization
    #[instrument(skip(self))]
    pub async fn activate_model(&self, version: String) -> Result<(), GuardianError> {
        // Verify model exists
        let mut metadata = {
            let active_models = self.active_models.read().await;
            active_models.get(&version).cloned().ok_or_else(|| GuardianError::MLError {
                context: format!("Model version {} not found", version),
                source: None,
                severity: crate::utils::error::ErrorSeverity::High,
                timestamp: time::OffsetDateTime::now_utc(),
                correlation_id: uuid::Uuid::new_v4(),
                category: ErrorCategory::ML,
                retry_count: 0,
            })?
        };

        // Validate model before activation
        self.validate_model_version(&version).await?;

        // Update model status
        metadata.status = ModelStatus::Active;
        metadata.updated_at = Utc::now();

        // Update registry state
        {
            let mut active_models = self.active_models.write().await;
            active_models.insert(version.clone(), metadata);
        }

        info!(version = %version, "Model activated successfully");
        Ok(())
    }

    /// Retrieves detailed performance metrics
    #[instrument(skip(self))]
    pub async fn get_model_metrics(&self, version: String) -> Result<ModelMetrics, GuardianError> {
        let metrics = {
            let metrics_map = self.model_metrics.read().await;
            metrics_map.get(&version).cloned().ok_or_else(|| GuardianError::MLError {
                context: format!("Metrics not found for model version {}", version),
                source: None,
                severity: crate::utils::error::ErrorSeverity::Medium,
                timestamp: time::OffsetDateTime::now_utc(),
                correlation_id: uuid::Uuid::new_v4(),
                category: ErrorCategory::ML,
                retry_count: 0,
            })?
        };

        Ok(metrics)
    }

    /// Updates model metrics with performance data
    #[instrument(skip(self))]
    pub async fn update_metrics(
        &self,
        version: String,
        metrics: ModelMetrics,
    ) -> Result<(), GuardianError> {
        let mut metrics_map = self.model_metrics.write().await;
        metrics_map.insert(version.clone(), metrics);

        info!(version = %version, "Model metrics updated successfully");
        Ok(())
    }

    /// Loads existing registry state from storage
    async fn load_registry_state(&self) -> Result<(), GuardianError> {
        let versions = self.model_store.list_versions().await?;
        
        let mut active_models = self.active_models.write().await;
        for version in versions {
            active_models.insert(version.version.clone(), ModelMetadata {
                name: version.version.clone(),
                version: version.version,
                created_at: version.created_at,
                updated_at: Utc::now(),
                status: ModelStatus::Inactive,
                metrics: None,
                validation_status: ValidationStatus::Pending,
                hash: version.hash,
                size_bytes: version.size,
            });
        }

        Ok(())
    }

    /// Validates model data before registration
    async fn validate_model_data(&self, data: &[u8], version: &str) -> Result<(), GuardianError> {
        if data.is_empty() {
            return Err(GuardianError::MLError {
                context: "Model data cannot be empty".into(),
                source: None,
                severity: crate::utils::error::ErrorSeverity::High,
                timestamp: time::OffsetDateTime::now_utc(),
                correlation_id: uuid::Uuid::new_v4(),
                category: ErrorCategory::ML,
                retry_count: 0,
            });
        }

        // Verify version format
        if !version.starts_with('v') || !version.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-') {
            return Err(GuardianError::MLError {
                context: format!("Invalid version format: {}", version),
                source: None,
                severity: crate::utils::error::ErrorSeverity::High,
                timestamp: time::OffsetDateTime::now_utc(),
                correlation_id: uuid::Uuid::new_v4(),
                category: ErrorCategory::ML,
                retry_count: 0,
            });
        }

        Ok(())
    }

    /// Validates model version before activation
    async fn validate_model_version(&self, version: &str) -> Result<(), GuardianError> {
        let metadata = {
            let active_models = self.active_models.read().await;
            active_models.get(version).cloned().ok_or_else(|| GuardianError::MLError {
                context: format!("Model version {} not found", version),
                source: None,
                severity: crate::utils::error::ErrorSeverity::High,
                timestamp: time::OffsetDateTime::now_utc(),
                correlation_id: uuid::Uuid::new_v4(),
                category: ErrorCategory::ML,
                retry_count: 0,
            })?
        };

        // Verify model status
        if metadata.status == ModelStatus::Failed {
            return Err(GuardianError::MLError {
                context: format!("Model version {} failed validation", version),
                source: None,
                severity: crate::utils::error::ErrorSeverity::High,
                timestamp: time::OffsetDateTime::now_utc(),
                correlation_id: uuid::Uuid::new_v4(),
                category: ErrorCategory::ML,
                retry_count: 0,
            });
        }

        Ok(())
    }

    /// Starts background metrics collection
    fn start_metrics_collection(&self) {
        let registry = self.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(CACHE_REFRESH_INTERVAL);
            loop {
                interval.tick().await;
                if let Err(e) = registry.collect_metrics().await {
                    error!(error = ?e, "Failed to collect model metrics");
                }
            }
        });
    }

    /// Collects metrics for all active models
    async fn collect_metrics(&self) -> Result<(), GuardianError> {
        let active_models = self.active_models.read().await;
        for (version, metadata) in active_models.iter() {
            if metadata.status == ModelStatus::Active {
                // Collect and update metrics
                if let Some(metrics) = &metadata.metrics {
                    let mut updated_metrics = metrics.clone();
                    updated_metrics.last_updated = Utc::now();
                    self.update_metrics(version.clone(), updated_metrics).await?;
                }
            }
        }
        Ok(())
    }
}

impl Clone for ModelRegistry {
    fn clone(&self) -> Self {
        Self {
            model_store: Arc::clone(&self.model_store),
            active_models: RwLock::new(HashMap::new()),
            model_metrics: RwLock::new(HashMap::new()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[tokio::test]
    async fn test_model_registration() {
        let model_store = Arc::new(ModelStore::new(
            Arc::new(crate::storage::zfs_manager::ZfsManager::new(
                "testpool".to_string(),
                vec![0u8; 32],
                Arc::new(crate::utils::logging::LogManager::new()),
                None,
            ).await.unwrap()),
            PathBuf::from("/tmp/test_models"),
            Some(5),
        ).await.unwrap());

        let registry = ModelRegistry::new(model_store).await.unwrap();

        let test_data = vec![1, 2, 3, 4, 5];
        let version = "v1.0.0".to_string();
        let metadata = ModelMetadata {
            name: "test_model".to_string(),
            version: version.clone(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            status: ModelStatus::Inactive,
            metrics: None,
            validation_status: ValidationStatus::Pending,
            hash: "".to_string(),
            size_bytes: 0,
        };

        let result = registry.register_model(test_data, version.clone(), metadata).await;
        assert!(result.is_ok());

        let result = registry.activate_model(version).await;
        assert!(result.is_ok());
    }
}