use metrics::{counter, gauge, histogram, Key, KeyName, Unit};
use metrics_exporter_statsd::{StatsdClient, StatsdError};
use ring_buffer::{RingBuffer, RingBufferWrite};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::time;

use crate::error::GuardianError;

// Core constants for metrics configuration
const METRICS_BUFFER_SIZE: usize = 1000;
const FLUSH_INTERVAL: Duration = Duration::from_secs(60);
const STATSD_PREFIX: &str = "guardian";
const MAX_RETRY_ATTEMPTS: u32 = 3;
const CIRCUIT_BREAKER_THRESHOLD: u32 = 5;

/// Supported metric types
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum MetricType {
    Counter,
    Gauge,
    Histogram,
}

/// Priority levels for metrics processing
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum MetricPriority {
    Critical,
    High,
    Medium,
    Low,
}

/// Configuration for metrics collection
#[derive(Debug, Clone, Deserialize)]
pub struct MetricsConfig {
    pub statsd_host: String,
    pub statsd_port: u16,
    pub buffer_size: Option<usize>,
    pub flush_interval: Option<Duration>,
    pub sampling_rates: Option<HashMap<MetricPriority, f64>>,
}

/// Individual metric data structure
#[derive(Debug, Clone, Serialize)]
struct Metric {
    name: String,
    value: f64,
    metric_type: MetricType,
    priority: MetricPriority,
    timestamp: Instant,
    tags: HashMap<String, String>,
}

/// Circuit breaker for StatsD connection
#[derive(Debug)]
struct CircuitBreaker {
    failures: u32,
    last_failure: Instant,
    state: CircuitBreakerState,
}

#[derive(Debug, PartialEq)]
enum CircuitBreakerState {
    Closed,
    Open,
    HalfOpen,
}

/// Core metrics collection struct
#[derive(Debug)]
pub struct MetricsCollector {
    ring_buffer: Arc<Mutex<RingBuffer<Metric>>>,
    statsd_client: StatsdClient,
    last_flush: Arc<Mutex<Instant>>,
    config: MetricsConfig,
    priority_queues: Vec<Arc<Mutex<Vec<Metric>>>>,
    circuit_breaker: Arc<Mutex<CircuitBreaker>>,
}

impl MetricsCollector {
    /// Creates a new MetricsCollector instance
    pub fn new(config: MetricsConfig) -> Result<Self, GuardianError> {
        let buffer_size = config.buffer_size.unwrap_or(METRICS_BUFFER_SIZE);
        let statsd_client = StatsdClient::new(
            &config.statsd_host,
            config.statsd_port,
            STATSD_PREFIX,
        ).map_err(|e| GuardianError::MetricsError {
            context: "Failed to create StatsD client".into(),
            source: Some(Box::new(e)),
        })?;

        let collector = Self {
            ring_buffer: Arc::new(Mutex::new(RingBuffer::new(buffer_size))),
            statsd_client,
            last_flush: Arc::new(Mutex::new(Instant::now())),
            config,
            priority_queues: vec![
                Arc::new(Mutex::new(Vec::new())), // Critical
                Arc::new(Mutex::new(Vec::new())), // High
                Arc::new(Mutex::new(Vec::new())), // Medium
                Arc::new(Mutex::new(Vec::new())), // Low
            ],
            circuit_breaker: Arc::new(Mutex::new(CircuitBreaker {
                failures: 0,
                last_failure: Instant::now(),
                state: CircuitBreakerState::Closed,
            })),
        };

        // Start background flush task
        let collector_clone = collector.clone();
        tokio::spawn(async move {
            let interval = collector_clone.config.flush_interval.unwrap_or(FLUSH_INTERVAL);
            let mut interval_timer = time::interval(interval);
            loop {
                interval_timer.tick().await;
                if let Err(e) = collector_clone.flush_metrics().await {
                    counter!("guardian.metrics.flush.errors", 1);
                    eprintln!("Error flushing metrics: {:?}", e);
                }
            }
        });

        Ok(collector)
    }

    /// Records a single metric with priority and sampling
    pub fn record_metric(
        &self,
        name: String,
        value: f64,
        metric_type: MetricType,
        priority: MetricPriority,
        tags: Option<HashMap<String, String>>,
    ) -> Result<(), GuardianError> {
        // Apply sampling based on priority
        let sampling_rates = self.config.sampling_rates.as_ref()
            .unwrap_or(&HashMap::new());
        let sample_rate = sampling_rates.get(&priority).unwrap_or(&1.0);
        
        if rand::random::<f64>() > *sample_rate {
            return Ok(());
        }

        let metric = Metric {
            name,
            value,
            metric_type,
            priority,
            timestamp: Instant::now(),
            tags: tags.unwrap_or_default(),
        };

        // Add to appropriate priority queue
        let queue_idx = match priority {
            MetricPriority::Critical => 0,
            MetricPriority::High => 1,
            MetricPriority::Medium => 2,
            MetricPriority::Low => 3,
        };

        let mut queue = self.priority_queues[queue_idx].lock().map_err(|e| GuardianError::MetricsError {
            context: "Failed to lock priority queue".into(),
            source: Some(Box::new(e)),
        })?;

        queue.push(metric);

        // Check buffer pressure
        if queue.len() >= self.config.buffer_size.unwrap_or(METRICS_BUFFER_SIZE) {
            counter!("guardian.metrics.buffer.pressure", 1);
            self.flush_metrics().await?;
        }

        Ok(())
    }

    /// Collects metrics based on priority
    pub async fn collect_metrics(&self, priority: Option<MetricPriority>) -> Result<Vec<Metric>, GuardianError> {
        let mut collected = Vec::new();

        // Determine which queues to process based on priority
        let queue_indices = match priority {
            Some(MetricPriority::Critical) => vec![0],
            Some(MetricPriority::High) => vec![0, 1],
            Some(MetricPriority::Medium) => vec![0, 1, 2],
            Some(MetricPriority::Low) | None => vec![0, 1, 2, 3],
        };

        for idx in queue_indices {
            let mut queue = self.priority_queues[idx].lock().map_err(|e| GuardianError::MetricsError {
                context: "Failed to lock priority queue".into(),
                source: Some(Box::new(e)),
            })?;

            collected.extend(queue.drain(..));
        }

        Ok(collected)
    }

    /// Flushes metrics to StatsD with retry logic
    pub async fn flush_metrics(&self) -> Result<(), GuardianError> {
        let circuit_breaker = self.circuit_breaker.lock().map_err(|e| GuardianError::MetricsError {
            context: "Failed to lock circuit breaker".into(),
            source: Some(Box::new(e)),
        })?;

        if circuit_breaker.state == CircuitBreakerState::Open {
            return Err(GuardianError::MetricsError {
                context: "Circuit breaker is open".into(),
                source: None,
            });
        }

        let metrics = self.collect_metrics(None).await?;
        if metrics.is_empty() {
            return Ok(());
        }

        for metric in metrics {
            let key = Key::from_parts(metric.name, metric.tags);
            match metric.metric_type {
                MetricType::Counter => self.statsd_client.increment(&key),
                MetricType::Gauge => self.statsd_client.gauge(&key, metric.value),
                MetricType::Histogram => self.statsd_client.histogram(&key, metric.value),
            }.map_err(|e| GuardianError::MetricsError {
                context: "Failed to send metric to StatsD".into(),
                source: Some(Box::new(e)),
            })?;
        }

        *self.last_flush.lock().unwrap() = Instant::now();
        counter!("guardian.metrics.flush.success", 1);

        Ok(())
    }
}

impl Clone for MetricsCollector {
    fn clone(&self) -> Self {
        Self {
            ring_buffer: Arc::clone(&self.ring_buffer),
            statsd_client: self.statsd_client.clone(),
            last_flush: Arc::clone(&self.last_flush),
            config: self.config.clone(),
            priority_queues: self.priority_queues.clone(),
            circuit_breaker: Arc::clone(&self.circuit_breaker),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn test_metrics_collection() {
        let config = MetricsConfig {
            statsd_host: "localhost".into(),
            statsd_port: 8125,
            buffer_size: Some(100),
            flush_interval: Some(Duration::from_secs(1)),
            sampling_rates: None,
        };

        let collector = MetricsCollector::new(config).unwrap();
        
        collector.record_metric(
            "test.counter".into(),
            1.0,
            MetricType::Counter,
            MetricPriority::High,
            None,
        ).unwrap();

        let metrics = collector.collect_metrics(None).await.unwrap();
        assert_eq!(metrics.len(), 1);
    }
}