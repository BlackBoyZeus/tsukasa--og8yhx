//! ML subsystem for AI Guardian providing threat detection, feature extraction,
//! model management, and inference capabilities with strict resource controls.
//! 
//! Version: 1.0.0
//! Dependencies:
//! - burn = "0.8"
//! - candle = "0.3"
//! - tokio = "1.32"
//! - tracing = "0.1"

use burn::backend::Backend;
use burn::tensor::backend::Backend as TensorBackend;
use candle::{Device, Tensor};
use tokio::sync::{RwLock, Semaphore};
use tracing::{error, info, instrument, warn};

use crate::utils::error::{GuardianError, ErrorCategory, ErrorSeverity};

// Submodules
pub mod model_registry;
pub mod feature_extractor;
pub mod inference_engine;

// Re-exports for convenient access
pub use model_registry::{ModelRegistry, ModelMetrics, ModelVersion};
pub use feature_extractor::{FeatureExtractor, Features, FeatureMetrics};
pub use inference_engine::{InferenceEngine, Prediction, InferenceMetrics};

// Constants for ML subsystem configuration and constraints
pub const ML_VERSION: &str = "1.0.0";
pub const DEFAULT_MODEL_PATH: &str = "models/guardian";
pub const MAX_INFERENCE_THREADS: usize = 4;
pub const MIN_CONFIDENCE_THRESHOLD: f32 = 0.99999;
pub const MAX_RESOURCE_USAGE_PERCENT: f32 = 5.0;

/// Configuration for the ML subsystem
#[derive(Debug, Clone)]
pub struct MLConfig {
    /// Path to model directory
    pub model_path: String,
    /// Maximum threads for inference
    pub max_threads: usize,
    /// Minimum confidence threshold
    pub confidence_threshold: f32,
    /// Maximum resource usage percentage
    pub max_resource_usage: f32,
    /// Enable hardware acceleration
    pub enable_gpu: bool,
}

impl Default for MLConfig {
    fn default() -> Self {
        Self {
            model_path: DEFAULT_MODEL_PATH.to_string(),
            max_threads: MAX_INFERENCE_THREADS,
            confidence_threshold: MIN_CONFIDENCE_THRESHOLD,
            max_resource_usage: MAX_RESOURCE_USAGE_PERCENT,
            enable_gpu: false,
        }
    }
}

/// Core ML subsystem managing all ML-related operations
pub struct MLSubsystem {
    /// Model registry for version control and metrics
    model_registry: RwLock<ModelRegistry>,
    /// Feature extraction with performance tracking
    feature_extractor: RwLock<FeatureExtractor>,
    /// Thread-safe inference engine
    inference_engine: RwLock<InferenceEngine>,
    /// Resource control semaphore
    thread_limiter: Semaphore,
    /// Hardware device for computation
    device: Device,
    /// Configuration parameters
    config: MLConfig,
}

impl MLSubsystem {
    /// Creates a new ML subsystem instance with the given configuration
    #[instrument(skip(config), err)]
    pub async fn new(config: MLConfig) -> Result<Self, GuardianError> {
        // Validate configuration
        Self::validate_config(&config).map_err(|e| GuardianError::MLError {
            context: "Invalid ML configuration".to_string(),
            source: Some(Box::new(e)),
            severity: ErrorSeverity::Critical,
            timestamp: time::OffsetDateTime::now_utc(),
            correlation_id: uuid::Uuid::new_v4(),
            category: ErrorCategory::ML,
            retry_count: 0,
        })?;

        // Initialize device
        let device = if config.enable_gpu {
            Device::cuda_if_available().unwrap_or(Device::Cpu)
        } else {
            Device::Cpu
        };

        info!("Initializing ML subsystem with device: {:?}", device);

        // Initialize components
        let model_registry = RwLock::new(ModelRegistry::new(&config.model_path).await?);
        let feature_extractor = RwLock::new(FeatureExtractor::new(&device)?);
        let inference_engine = RwLock::new(InferenceEngine::new(
            &device,
            config.confidence_threshold,
        )?);
        let thread_limiter = Semaphore::new(config.max_threads);

        Ok(Self {
            model_registry,
            feature_extractor,
            inference_engine,
            thread_limiter,
            device,
            config,
        })
    }

    /// Validates the ML configuration parameters
    fn validate_config(config: &MLConfig) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if config.max_threads == 0 || config.max_threads > 32 {
            return Err("Invalid thread count".into());
        }
        if config.confidence_threshold < 0.0 || config.confidence_threshold > 1.0 {
            return Err("Invalid confidence threshold".into());
        }
        if config.max_resource_usage <= 0.0 || config.max_resource_usage > 100.0 {
            return Err("Invalid resource usage limit".into());
        }
        Ok(())
    }

    /// Performs threat detection with resource controls and telemetry
    #[instrument(skip(self, input), err)]
    pub async fn detect_threat(&self, input: Tensor) -> Result<Prediction, GuardianError> {
        // Acquire thread permit
        let _permit = self.thread_limiter.acquire().await.map_err(|e| GuardianError::MLError {
            context: "Failed to acquire thread permit".to_string(),
            source: Some(Box::new(e)),
            severity: ErrorSeverity::High,
            timestamp: time::OffsetDateTime::now_utc(),
            correlation_id: uuid::Uuid::new_v4(),
            category: ErrorCategory::ML,
            retry_count: 0,
        })?;

        // Extract features
        let features = self.feature_extractor.write().await
            .extract_features(input).await?;

        // Perform inference
        let prediction = self.inference_engine.write().await
            .infer(features).await?;

        // Record metrics
        self.record_metrics(&prediction).await;

        Ok(prediction)
    }

    /// Records telemetry for ML operations
    #[instrument(skip(self, prediction))]
    async fn record_metrics(&self, prediction: &Prediction) {
        metrics::gauge!("guardian.ml.confidence", prediction.confidence as f64);
        metrics::histogram!("guardian.ml.inference_time", prediction.inference_time.as_secs_f64());
        metrics::counter!("guardian.ml.predictions_total", 1);
    }

    /// Updates ML models with version control
    #[instrument(skip(self, model_data), err)]
    pub async fn update_model(&self, model_data: Vec<u8>) -> Result<ModelVersion, GuardianError> {
        let version = self.model_registry.write().await
            .register_model(model_data).await?;
        
        // Update inference engine with new model
        self.inference_engine.write().await
            .load_model(&version).await?;

        info!("Successfully updated model to version: {}", version);
        Ok(version)
    }

    /// Gets current ML subsystem metrics
    #[instrument(skip(self))]
    pub async fn get_metrics(&self) -> MLMetrics {
        MLMetrics {
            model_metrics: self.model_registry.read().await.get_metrics(),
            feature_metrics: self.feature_extractor.read().await.get_metrics(),
            inference_metrics: self.inference_engine.read().await.get_metrics(),
            resource_usage: self.get_resource_usage(),
        }
    }

    /// Calculates current resource usage
    fn get_resource_usage(&self) -> f32 {
        let available_permits = self.thread_limiter.available_permits();
        let usage_percent = (self.config.max_threads - available_permits) as f32 
            / self.config.max_threads as f32 * 100.0;
        usage_percent
    }
}

/// Comprehensive metrics for ML subsystem
#[derive(Debug, Clone)]
pub struct MLMetrics {
    /// Model-related metrics
    pub model_metrics: ModelMetrics,
    /// Feature extraction metrics
    pub feature_metrics: FeatureMetrics,
    /// Inference engine metrics
    pub inference_metrics: InferenceMetrics,
    /// Current resource usage percentage
    pub resource_usage: f32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_ml_config_validation() {
        let invalid_config = MLConfig {
            max_threads: 0,
            ..Default::default()
        };
        assert!(MLSubsystem::validate_config(&invalid_config).is_err());

        let valid_config = MLConfig::default();
        assert!(MLSubsystem::validate_config(&valid_config).is_ok());
    }

    #[tokio::test]
    async fn test_resource_limits() {
        let config = MLConfig::default();
        let subsystem = MLSubsystem::new(config).await.unwrap();
        assert_eq!(subsystem.thread_limiter.available_permits(), MAX_INFERENCE_THREADS);
    }
}