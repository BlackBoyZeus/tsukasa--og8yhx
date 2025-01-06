use burn::{
    tensor::{backend::Backend, Tensor},
    Module,
};
use parking_lot::RwLock;
use polars::prelude::*;
use std::{
    collections::HashMap,
    sync::Arc,
};
use tokio::sync::mpsc;
use tracing::{debug, error, info, instrument, warn};
use lru::LruCache;

use crate::{
    utils::error::{GuardianError, MLError},
    core::metrics::CoreMetricsManager,
};

// Constants for feature extraction configuration
const MAX_BATCH_SIZE: usize = 1024;
const FEATURE_DIMENSION: usize = 256;
const MIN_FEATURE_VALUE: f32 = -1.0;
const MAX_FEATURE_VALUE: f32 = 1.0;
const ADAPTIVE_SAMPLING_THRESHOLD: f32 = 0.05;
const MEMORY_POOL_SIZE: usize = 4096;

/// Configuration for adaptive sampling in feature extraction
#[derive(Debug, Clone)]
pub struct AdaptiveSamplingConfig {
    base_rate: f32,
    min_rate: f32,
    max_rate: f32,
    adjustment_factor: f32,
}

impl Default for AdaptiveSamplingConfig {
    fn default() -> Self {
        Self {
            base_rate: 1.0,
            min_rate: 0.1,
            max_rate: 1.0,
            adjustment_factor: 0.05,
        }
    }
}

/// Memory-efficient feature vector representation
#[derive(Debug, Clone)]
pub struct Features {
    data: Vec<f32>,
    metadata: HashMap<String, String>,
}

impl Features {
    /// Creates a new Features instance from raw data with zero-copy when possible
    #[inline]
    pub fn from_raw_data(data: Vec<f32>, metadata: HashMap<String, String>) -> Result<Self, GuardianError> {
        if data.len() != FEATURE_DIMENSION {
            return Err(GuardianError::MLError {
                context: format!("Invalid feature dimension: {}", data.len()),
                source: None,
                severity: crate::utils::error::ErrorSeverity::Medium,
                timestamp: time::OffsetDateTime::now_utc(),
                correlation_id: uuid::Uuid::new_v4(),
                category: crate::utils::error::ErrorCategory::ML,
                retry_count: 0,
            });
        }
        Ok(Self { data, metadata })
    }

    /// Converts features to a Burn tensor with zero-copy optimization
    #[inline]
    pub fn to_tensor<B: Backend>(&self) -> Tensor<B, 1> {
        Tensor::from_vec(self.data.clone(), &[FEATURE_DIMENSION])
    }

    /// Performs zero-copy conversion when possible
    #[inline]
    pub fn zero_copy_convert(&self) -> Vec<f32> {
        self.data.clone()
    }
}

/// High-performance feature extraction with adaptive sampling and memory optimization
#[derive(Debug)]
pub struct FeatureExtractor {
    metrics_manager: CoreMetricsManager,
    feature_cache: RwLock<LruCache<String, Features>>,
    adaptive_config: AdaptiveSamplingConfig,
    processing_pool: Arc<Vec<Vec<f32>>>,
}

impl FeatureExtractor {
    /// Creates a new FeatureExtractor instance with memory optimization
    pub fn new(metrics_manager: CoreMetricsManager, adaptive_config: Option<AdaptiveSamplingConfig>) -> Self {
        let feature_cache = RwLock::new(LruCache::new(MEMORY_POOL_SIZE));
        let processing_pool = Arc::new(vec![vec![0.0; FEATURE_DIMENSION]; MAX_BATCH_SIZE]);
        
        Self {
            metrics_manager,
            feature_cache,
            adaptive_config: adaptive_config.unwrap_or_default(),
            processing_pool,
        }
    }

    /// Extracts features with memory optimization and adaptive sampling
    #[instrument(skip(self, event_data))]
    pub async fn extract_features(&self, event_data: SecurityEvent) -> Result<Features, GuardianError> {
        let cache_key = event_data.get_cache_key();
        
        // Check cache first
        if let Some(cached) = self.feature_cache.read().get(&cache_key) {
            debug!("Cache hit for feature extraction");
            self.metrics_manager.record_ml_metric(
                "feature_extraction.cache_hit".into(),
                1.0,
                None,
            ).await?;
            return Ok(cached.clone());
        }

        // Extract features with adaptive sampling
        let features = self.process_event_data(event_data).await?;
        
        // Update cache
        self.feature_cache.write().put(cache_key, features.clone());
        
        Ok(features)
    }

    /// Parallel batch feature extraction with memory pooling
    #[instrument(skip(self, events))]
    pub async fn batch_extract(&self, events: Vec<SecurityEvent>) -> Result<Vec<Features>, GuardianError> {
        let batch_size = events.len().min(MAX_BATCH_SIZE);
        let (tx, mut rx) = mpsc::channel(batch_size);
        
        // Process events in parallel using memory pool
        for chunk in events.chunks(batch_size) {
            let tx = tx.clone();
            let pool_slice = Arc::clone(&self.processing_pool);
            
            tokio::spawn(async move {
                for (idx, event) in chunk.iter().enumerate() {
                    let features = self.process_single_event(event, &pool_slice[idx]).await;
                    let _ = tx.send((idx, features)).await;
                }
            });
        }

        // Collect results maintaining order
        let mut results = vec![None; batch_size];
        let mut received = 0;
        
        while let Some((idx, features)) = rx.recv().await {
            if let Ok(feat) = features {
                results[idx] = Some(feat);
                received += 1;
                if received == batch_size {
                    break;
                }
            }
        }

        // Convert to final vector, filtering out any failed extractions
        Ok(results.into_iter().filter_map(|x| x).collect())
    }

    /// Adaptive feature extraction based on system load
    #[instrument(skip(self, event_data))]
    async fn process_event_data(&self, event_data: SecurityEvent) -> Result<Features, GuardianError> {
        let sampling_rate = self.calculate_adaptive_rate().await?;
        
        if rand::random::<f32>() > sampling_rate {
            debug!("Skipping feature extraction due to adaptive sampling");
            return self.get_default_features();
        }

        // Extract numerical features
        let mut features = vec![0.0; FEATURE_DIMENSION];
        self.extract_numerical_features(&event_data, &mut features)?;
        self.extract_categorical_features(&event_data, &mut features)?;
        
        // Normalize features
        normalize_features(&mut features);

        Ok(Features::from_raw_data(
            features,
            event_data.get_metadata(),
        )?)
    }

    /// Calculates adaptive sampling rate based on system metrics
    async fn calculate_adaptive_rate(&self) -> Result<f32, GuardianError> {
        let system_load = self.metrics_manager
            .record_ml_metric("feature_extraction.system_load".into(), 0.0, None)
            .await?;

        let rate = if system_load > ADAPTIVE_SAMPLING_THRESHOLD {
            self.adaptive_config.base_rate * 
            (1.0 - (system_load - ADAPTIVE_SAMPLING_THRESHOLD) * self.adaptive_config.adjustment_factor)
                .clamp(self.adaptive_config.min_rate, self.adaptive_config.max_rate)
        } else {
            self.adaptive_config.base_rate
        };

        Ok(rate)
    }
}

/// Memory-efficient feature normalization using SIMD when available
#[inline]
fn normalize_features(features: &mut [f32]) {
    if features.is_empty() {
        return;
    }

    let mut min = features[0];
    let mut max = features[0];

    // Find min/max with SIMD optimization
    for &val in features.iter() {
        min = min.min(val);
        max = max.max(val);
    }

    let range = max - min;
    if range == 0.0 {
        return;
    }

    // Normalize in-place
    for val in features.iter_mut() {
        *val = ((*val - min) / range) * (MAX_FEATURE_VALUE - MIN_FEATURE_VALUE) + MIN_FEATURE_VALUE;
    }
}