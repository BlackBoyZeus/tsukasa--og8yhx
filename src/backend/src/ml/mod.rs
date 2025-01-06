//! ML Engine module for the Guardian system
//! Version: 2.1.0
//! 
//! Provides centralized access to machine learning capabilities including:
//! - Model management and versioning
//! - High-performance inference engine
//! - Feature extraction and preprocessing
//! - Training pipeline with validation
//! - Resource optimization and monitoring

use burn::backend::Backend;
use burn::config::Config as BurnConfig;
use candle_core::{Device, Tensor};
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, error, info, instrument, warn};

use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::utils::error::{GuardianError, Result};
use crate::config::ml_config::{MLConfig, InferenceConfig};

// Version constant for ML engine
pub const ML_VERSION: &str = "2.1.0";

// Default compute device
pub const DEFAULT_DEVICE: &str = "cuda";

// Submodules
pub mod model_registry;
pub mod inference_engine;
pub mod feature_extractor;
pub mod model_manager;
pub mod training_pipeline;

// Re-exports
pub use model_registry::ModelRegistry;
pub use inference_engine::InferenceEngine;
pub use feature_extractor::FeatureExtractor;
pub use model_manager::ModelManager;
pub use training_pipeline::TrainingPipeline;

/// Core ML Engine structure coordinating all ML operations
pub struct MLEngine {
    config: MLConfig,
    model_registry: Arc<ModelRegistry>,
    inference_engine: Arc<InferenceEngine>,
    feature_extractor: Arc<FeatureExtractor>,
    model_manager: Arc<ModelManager>,
    training_pipeline: Arc<TrainingPipeline>,
    device: Device,
    resource_monitor: Arc<RwLock<ResourceMonitor>>,
    shutdown_tx: mpsc::Sender<()>,
}

/// Resource monitoring and optimization
struct ResourceMonitor {
    last_check: Instant,
    cpu_usage: f32,
    memory_usage: f32,
    gpu_usage: Option<f32>,
    performance_metrics: PerformanceMetrics,
}

/// Performance tracking metrics
#[derive(Debug, Default)]
struct PerformanceMetrics {
    inference_latency: Vec<Duration>,
    batch_throughput: usize,
    model_accuracy: f32,
    resource_efficiency: f32,
}

impl MLEngine {
    /// Initialize the ML engine with comprehensive configuration and validation
    #[instrument(skip(config), fields(version = %ML_VERSION))]
    pub async fn init(config: MLConfig) -> Result<Self> {
        info!("Initializing ML Engine v{}", ML_VERSION);
        
        // Verify hardware capabilities and select optimal device
        let device = Self::initialize_device(&config)?;
        debug!("Selected compute device: {:?}", device);

        // Initialize communication channels
        let (shutdown_tx, mut shutdown_rx) = mpsc::channel(1);

        // Initialize core components with resource optimization
        let model_registry = Arc::new(ModelRegistry::new(&config)?);
        let inference_engine = Arc::new(InferenceEngine::new(&config, device.clone())?);
        let feature_extractor = Arc::new(FeatureExtractor::new(&config)?);
        let model_manager = Arc::new(ModelManager::new(&config, model_registry.clone())?);
        let training_pipeline = Arc::new(TrainingPipeline::new(&config)?);
        
        // Initialize resource monitoring
        let resource_monitor = Arc::new(RwLock::new(ResourceMonitor {
            last_check: Instant::now(),
            cpu_usage: 0.0,
            memory_usage: 0.0,
            gpu_usage: None,
            performance_metrics: PerformanceMetrics::default(),
        }));

        // Start resource monitoring task
        let monitor_clone = resource_monitor.clone();
        tokio::spawn(async move {
            while shutdown_rx.try_recv().is_err() {
                if let Err(e) = Self::monitor_resources(&monitor_clone).await {
                    error!("Resource monitoring error: {}", e);
                }
                tokio::time::sleep(Duration::from_millis(config.resource_config.check_interval_ms)).await;
            }
        });

        let engine = Self {
            config,
            model_registry,
            inference_engine,
            feature_extractor,
            model_manager,
            training_pipeline,
            device,
            resource_monitor,
            shutdown_tx,
        };

        // Validate engine health
        engine.validate_health().await?;
        
        info!("ML Engine initialization complete");
        Ok(engine)
    }

    /// Initialize optimal compute device based on configuration and availability
    fn initialize_device(config: &MLConfig) -> Result<Device> {
        if config.hardware_config.enable_cuda && Device::cuda_is_available(0) {
            Ok(Device::Cuda(0))
        } else if config.hardware_config.enable_metal && Device::metal_is_available() {
            Ok(Device::Metal)
        } else {
            warn!("Hardware acceleration unavailable, falling back to CPU");
            Ok(Device::Cpu)
        }
    }

    /// Monitor system resources and optimize performance
    async fn monitor_resources(monitor: &Arc<RwLock<ResourceMonitor>>) -> Result<()> {
        let mut lock = monitor.write().await;
        
        // Update resource usage metrics
        lock.cpu_usage = sys_info::cpu_load_aggregate()
            .map_err(|e| GuardianError::MLError(format!("CPU monitoring error: {}", e)))?
            .0;
            
        lock.memory_usage = sys_info::mem_info()
            .map_err(|e| GuardianError::MLError(format!("Memory monitoring error: {}", e)))?
            .total as f32;

        // Update GPU metrics if available
        if let Ok(gpu_info) = gpu_info::get_gpu_info() {
            lock.gpu_usage = Some(gpu_info.utilization);
        }

        Ok(())
    }

    /// Validate overall engine health and component status
    async fn validate_health(&self) -> Result<()> {
        // Verify model registry health
        self.model_registry.health_check().await?;

        // Verify inference engine health
        self.inference_engine.health_check().await?;

        // Verify feature extractor health
        self.feature_extractor.health_check().await?;

        // Verify model manager health
        self.model_manager.health_check().await?;

        // Verify training pipeline health
        self.training_pipeline.health_check().await?;

        Ok(())
    }

    /// Clean shutdown of ML engine components
    pub async fn shutdown(&self) -> Result<()> {
        info!("Initiating ML Engine shutdown");
        
        // Signal monitoring task to stop
        if let Err(e) = self.shutdown_tx.send(()).await {
            error!("Error sending shutdown signal: {}", e);
        }

        // Cleanup components
        self.model_registry.cleanup().await?;
        self.inference_engine.cleanup().await?;
        self.feature_extractor.cleanup().await?;
        self.model_manager.cleanup().await?;
        self.training_pipeline.cleanup().await?;

        info!("ML Engine shutdown complete");
        Ok(())
    }
}

impl Drop for MLEngine {
    fn drop(&mut self) {
        info!("ML Engine dropped");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ml_config::MLConfig;

    #[tokio::test]
    async fn test_ml_engine_initialization() {
        let config = MLConfig::new();
        let engine = MLEngine::init(config).await;
        assert!(engine.is_ok());
    }

    #[tokio::test]
    async fn test_resource_monitoring() {
        let monitor = Arc::new(RwLock::new(ResourceMonitor {
            last_check: Instant::now(),
            cpu_usage: 0.0,
            memory_usage: 0.0,
            gpu_usage: None,
            performance_metrics: PerformanceMetrics::default(),
        }));

        let result = MLEngine::monitor_resources(&monitor).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_engine_shutdown() {
        let config = MLConfig::new();
        let engine = MLEngine::init(config).await.unwrap();
        let result = engine.shutdown().await;
        assert!(result.is_ok());
    }
}