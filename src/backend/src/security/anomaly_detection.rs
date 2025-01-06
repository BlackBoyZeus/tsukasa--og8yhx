use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{RwLock, Mutex};
use tracing::{debug, error, info, instrument, warn};
use serde::{Serialize, Deserialize};

use crate::ml::inference_engine::InferenceEngine;
use crate::core::event_bus::{Event, EventBus, EventPriority};
use crate::utils::error::GuardianError;
use crate::core::system_state::{SystemState, SystemHealth};
use crate::utils::metrics::{record_metric, MetricKind};

// Constants for anomaly detection configuration
const MIN_ANOMALY_CONFIDENCE: f32 = 0.95;
const MAX_BATCH_SIZE: usize = 100;
const DETECTION_TIMEOUT_MS: u64 = 100;
const MAX_RETRIES: u32 = 3;
const CIRCUIT_BREAKER_THRESHOLD: u32 = 5;
const RESOURCE_LIMIT_CPU_PERCENT: f32 = 5.0;

/// Represents a detected anomaly with confidence score and context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Anomaly {
    pub id: String,
    pub anomaly_type: String,
    pub confidence: f32,
    pub timestamp: i64,
    pub context: serde_json::Value,
    pub severity: AnomalySeverity,
}

/// Severity levels for detected anomalies
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AnomalySeverity {
    Critical,
    High,
    Medium,
    Low,
}

/// Configuration for anomaly detection
#[derive(Debug, Clone)]
pub struct AnomalyConfig {
    pub confidence_threshold: f32,
    pub batch_size: usize,
    pub detection_timeout: Duration,
    pub max_retries: u32,
}

impl Default for AnomalyConfig {
    fn default() -> Self {
        Self {
            confidence_threshold: MIN_ANOMALY_CONFIDENCE,
            batch_size: MAX_BATCH_SIZE,
            detection_timeout: Duration::from_millis(DETECTION_TIMEOUT_MS),
            max_retries: MAX_RETRIES,
        }
    }
}

/// Adaptive batch size manager
#[derive(Debug)]
struct AdaptiveBatcher {
    current_size: usize,
    min_size: usize,
    max_size: usize,
    performance_metrics: Vec<Duration>,
}

impl AdaptiveBatcher {
    fn new(min_size: usize, max_size: usize) -> Self {
        Self {
            current_size: min_size,
            min_size,
            max_size,
            performance_metrics: Vec::with_capacity(100),
        }
    }

    fn adjust_batch_size(&mut self, processing_time: Duration) {
        self.performance_metrics.push(processing_time);
        if self.performance_metrics.len() >= 100 {
            let avg_time = self.performance_metrics.iter().sum::<Duration>() / 100;
            if avg_time < Duration::from_millis(DETECTION_TIMEOUT_MS) {
                self.current_size = (self.current_size * 2).min(self.max_size);
            } else {
                self.current_size = (self.current_size / 2).max(self.min_size);
            }
            self.performance_metrics.clear();
        }
    }
}

/// Circuit breaker for fault tolerance
#[derive(Debug)]
struct CircuitBreaker {
    failures: u32,
    last_failure: Instant,
    is_open: bool,
}

impl CircuitBreaker {
    fn new() -> Self {
        Self {
            failures: 0,
            last_failure: Instant::now(),
            is_open: false,
        }
    }

    fn record_failure(&mut self) -> bool {
        self.failures += 1;
        self.last_failure = Instant::now();
        if self.failures >= CIRCUIT_BREAKER_THRESHOLD {
            self.is_open = true;
        }
        self.is_open
    }

    fn reset(&mut self) {
        self.failures = 0;
        self.is_open = false;
    }
}

/// Core anomaly detection engine
#[derive(Debug)]
pub struct AnomalyDetector {
    inference_engine: Arc<InferenceEngine>,
    event_bus: Arc<EventBus>,
    system_state: Arc<SystemState>,
    metrics: Arc<metrics::MetricsCollector>,
    config: AnomalyConfig,
    circuit_breaker: RwLock<CircuitBreaker>,
    batcher: Mutex<AdaptiveBatcher>,
}

impl AnomalyDetector {
    /// Creates a new AnomalyDetector instance
    pub fn new(
        inference_engine: Arc<InferenceEngine>,
        event_bus: Arc<EventBus>,
        system_state: Arc<SystemState>,
        metrics: Arc<metrics::MetricsCollector>,
        config: AnomalyConfig,
    ) -> Self {
        Self {
            inference_engine,
            event_bus,
            system_state,
            metrics,
            config,
            circuit_breaker: RwLock::new(CircuitBreaker::new()),
            batcher: Mutex::new(AdaptiveBatcher::new(1, config.batch_size)),
        }
    }

    /// Analyzes system data for anomalies
    #[instrument(skip(self, data))]
    pub async fn detect_anomalies(&self, data: SystemData) -> Result<Vec<Anomaly>, GuardianError> {
        let start = Instant::now();

        // Check circuit breaker
        let breaker = self.circuit_breaker.read().await;
        if breaker.is_open {
            return Err(GuardianError::SecurityError("Circuit breaker is open".to_string()));
        }
        drop(breaker);

        // Perform anomaly detection with timeout
        let detection_result = tokio::time::timeout(
            self.config.detection_timeout,
            self.execute_detection(data.clone())
        ).await;

        match detection_result {
            Ok(Ok(anomalies)) => {
                // Record metrics
                let duration = start.elapsed();
                record_metric(
                    "anomaly_detection.duration_ms".to_string(),
                    duration.as_millis() as f64,
                    MetricKind::Histogram,
                    None,
                )?;

                // Update system state if anomalies found
                if !anomalies.is_empty() {
                    self.handle_detected_anomalies(&anomalies).await?;
                }

                Ok(anomalies)
            }
            Ok(Err(e)) => {
                let mut breaker = self.circuit_breaker.write().await;
                if breaker.record_failure() {
                    error!("Circuit breaker opened due to detection failures");
                }
                Err(e)
            }
            Err(_) => {
                Err(GuardianError::SecurityError("Anomaly detection timeout".to_string()))
            }
        }
    }

    /// Performs batch anomaly detection with adaptive sizing
    #[instrument(skip(self, batch_data))]
    pub async fn batch_detect(&self, batch_data: Vec<SystemData>) -> Result<Vec<Anomaly>, GuardianError> {
        let start = Instant::now();
        let mut batcher = self.batcher.lock().await;

        // Validate batch size
        if batch_data.is_empty() || batch_data.len() > batcher.current_size {
            return Err(GuardianError::ValidationError(
                format!("Invalid batch size: {}", batch_data.len())
            ));
        }

        // Execute batch inference
        let results = self.inference_engine.batch_infer(
            "anomaly_model".to_string(),
            batch_data.iter().map(|d| serde_json::to_value(d).unwrap()).collect()
        ).await?;

        // Process results
        let mut anomalies = Vec::new();
        for (idx, result) in results.iter().enumerate() {
            if result.max().unwrap() >= self.config.confidence_threshold {
                anomalies.push(Anomaly {
                    id: format!("anomaly_{}", fastrand::u64(..)),
                    anomaly_type: "system_behavior".to_string(),
                    confidence: result.max().unwrap(),
                    timestamp: chrono::Utc::now().timestamp(),
                    context: serde_json::to_value(&batch_data[idx])?,
                    severity: determine_severity(result.max().unwrap()),
                });
            }
        }

        // Update batch size based on performance
        batcher.adjust_batch_size(start.elapsed());

        // Record metrics
        record_metric(
            "anomaly_detection.batch_size".to_string(),
            batcher.current_size as f64,
            MetricKind::Gauge,
            None,
        )?;

        Ok(anomalies)
    }

    // Private helper methods
    async fn execute_detection(&self, data: SystemData) -> Result<Vec<Anomaly>, GuardianError> {
        let result = self.inference_engine.infer(
            "anomaly_model".to_string(),
            serde_json::to_value(data.clone())?
        ).await?;

        let confidence = result.max().unwrap();
        if confidence >= self.config.confidence_threshold {
            Ok(vec![Anomaly {
                id: format!("anomaly_{}", fastrand::u64(..)),
                anomaly_type: "system_behavior".to_string(),
                confidence,
                timestamp: chrono::Utc::now().timestamp(),
                context: serde_json::to_value(data)?,
                severity: determine_severity(confidence),
            }])
        } else {
            Ok(vec![])
        }
    }

    async fn handle_detected_anomalies(&self, anomalies: &[Anomaly]) -> Result<(), GuardianError> {
        // Update system state
        if anomalies.iter().any(|a| a.severity == AnomalySeverity::Critical) {
            self.system_state.update_health_status(SystemHealth::Critical).await?;
        }

        // Publish anomaly events
        for anomaly in anomalies {
            self.event_bus.publish(
                Event {
                    id: format!("event_{}", fastrand::u64(..)),
                    event_type: "anomaly_detected".to_string(),
                    priority: EventPriority::High,
                    payload: serde_json::to_vec(&anomaly)?,
                    source: "anomaly_detector".to_string(),
                    timestamp: chrono::Utc::now().timestamp(),
                },
                EventPriority::High
            ).await?;
        }

        Ok(())
    }
}

/// Determines anomaly severity based on confidence score
fn determine_severity(confidence: f32) -> AnomalySeverity {
    match confidence {
        c if c >= 0.99 => AnomalySeverity::Critical,
        c if c >= 0.97 => AnomalySeverity::High,
        c if c >= 0.95 => AnomalySeverity::Medium,
        _ => AnomalySeverity::Low,
    }
}

/// System data for anomaly detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemData {
    pub metrics: HashMap<String, f64>,
    pub events: Vec<String>,
    pub timestamp: i64,
}

/// Starts the anomaly detection service
#[instrument(skip(config))]
pub async fn start_anomaly_detection(config: AnomalyConfig) -> Result<Arc<AnomalyDetector>, GuardianError> {
    info!("Starting anomaly detection service");
    
    // Initialize required components
    let metrics = Arc::new(metrics::MetricsCollector::new());
    let inference_engine = Arc::new(InferenceEngine::new(
        Arc::new(ModelRegistry::new()),
        Arc::new(FeatureExtractor::new()),
        metrics.clone(),
    )?);
    
    let event_bus = Arc::new(EventBus::new(metrics.clone()));
    let system_state = Arc::new(SystemState::new(event_bus.clone()).await?);

    let detector = Arc::new(AnomalyDetector::new(
        inference_engine,
        event_bus,
        system_state,
        metrics,
        config,
    ));

    info!("Anomaly detection service started successfully");
    Ok(detector)
}