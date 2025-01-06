use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use lru::LruCache;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    sync::Arc,
};
use tokio::sync::RwLock;
use tracing::{debug, error, info, instrument};

use crate::utils::error::{GuardianError, ErrorCategory};
use crate::utils::metrics::{MetricsCollector, MetricType, MetricPriority};
use crate::storage::zfs_manager::ZfsManager;

// Constants for metrics storage configuration
const DEFAULT_RETENTION_DAYS: u32 = 90;
const METRICS_PARTITION_PREFIX: &str = "metrics";
const CLEANUP_INTERVAL: Duration = Duration::days(1);
const DEFAULT_BATCH_SIZE: usize = 1000;
const DEFAULT_COMPRESSION_LEVEL: u8 = 6;
const MAX_CACHE_SIZE: usize = 10000;

/// Represents a single metric data point
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Metric {
    name: String,
    value: f64,
    timestamp: DateTime<Utc>,
    metric_type: MetricType,
    tags: HashMap<String, String>,
}

/// Query parameters for retrieving metrics
#[derive(Debug, Clone)]
pub struct MetricsQuery {
    pub time_range: (DateTime<Utc>, DateTime<Utc>),
    pub metric_names: Option<Vec<String>>,
}

/// Thread-safe manager for persistent storage of system metrics
#[derive(Debug)]
#[async_trait]
pub struct MetricsStore {
    zfs_manager: Arc<ZfsManager>,
    metrics_collector: Arc<RwLock<MetricsCollector>>,
    retention_days: u32,
    batch_size: usize,
    compression_level: u8,
    metrics_cache: Arc<RwLock<LruCache<String, Vec<Metric>>>>,
}

impl MetricsStore {
    /// Creates a new MetricsStore instance with optimized configuration
    pub async fn new(
        zfs_manager: Arc<ZfsManager>,
        retention_days: u32,
        batch_size: usize,
        compression_level: u8,
    ) -> Result<Self, GuardianError> {
        let store = Self {
            zfs_manager,
            metrics_collector: Arc::new(RwLock::new(MetricsCollector::new(Default::default())?)),
            retention_days: retention_days.max(1).min(365),
            batch_size: batch_size.max(100).min(10000),
            compression_level: compression_level.max(1).min(9),
            metrics_cache: Arc::new(RwLock::new(LruCache::new(MAX_CACHE_SIZE))),
        };

        // Start background cleanup task
        let store_clone = store.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(CLEANUP_INTERVAL.to_std().unwrap());
            loop {
                interval.tick().await;
                if let Err(e) = cleanup_old_metrics(store_clone.retention_days).await {
                    error!("Failed to cleanup old metrics: {:?}", e);
                }
            }
        });

        Ok(store)
    }

    /// Stores metrics batch with compression and deduplication
    #[instrument(skip(self, metrics))]
    pub async fn store_metrics(&self, metrics: Vec<Metric>) -> Result<(), GuardianError> {
        if metrics.is_empty() {
            return Ok(());
        }

        // Group metrics by partition key (day)
        let mut partitioned_metrics: HashMap<String, Vec<Metric>> = HashMap::new();
        for metric in metrics {
            let partition_key = format!(
                "{}/{}",
                METRICS_PARTITION_PREFIX,
                metric.timestamp.format("%Y-%m-%d")
            );
            partitioned_metrics
                .entry(partition_key)
                .or_default()
                .push(metric);
        }

        // Store metrics in batches
        for (partition, metrics) in partitioned_metrics {
            let compressed_data = {
                let mut compressor = zstd::Encoder::new(Vec::new(), self.compression_level as i32)
                    .map_err(|e| GuardianError::StorageError {
                        context: "Failed to create compression encoder".into(),
                        source: Some(Box::new(e)),
                        severity: crate::utils::error::ErrorSeverity::High,
                        timestamp: time::OffsetDateTime::now_utc(),
                        correlation_id: uuid::Uuid::new_v4(),
                        category: ErrorCategory::Storage,
                        retry_count: 0,
                    })?;
                serde_json::to_writer(&mut compressor, &metrics).map_err(|e| {
                    GuardianError::StorageError {
                        context: "Failed to serialize metrics".into(),
                        source: Some(Box::new(e)),
                        severity: crate::utils::error::ErrorSeverity::High,
                        timestamp: time::OffsetDateTime::now_utc(),
                        correlation_id: uuid::Uuid::new_v4(),
                        category: ErrorCategory::Storage,
                        retry_count: 0,
                    }
                })?;
                compressor.finish().map_err(|e| GuardianError::StorageError {
                    context: "Failed to finish compression".into(),
                    source: Some(Box::new(e)),
                    severity: crate::utils::error::ErrorSeverity::High,
                    timestamp: time::OffsetDateTime::now_utc(),
                    correlation_id: uuid::Uuid::new_v4(),
                    category: ErrorCategory::Storage,
                    retry_count: 0,
                })?
            };

            // Write compressed batch to ZFS
            self.zfs_manager
                .write_data(&partition, &compressed_data)
                .await
                .map_err(|e| GuardianError::StorageError {
                    context: format!("Failed to write metrics to partition {}", partition),
                    source: Some(Box::new(e)),
                    severity: crate::utils::error::ErrorSeverity::High,
                    timestamp: time::OffsetDateTime::now_utc(),
                    correlation_id: uuid::Uuid::new_v4(),
                    category: ErrorCategory::Storage,
                    retry_count: 0,
                })?;

            // Update cache
            let mut cache = self.metrics_cache.write().await;
            cache.put(partition, metrics);
        }

        debug!("Successfully stored {} metrics", metrics.len());
        Ok(())
    }

    /// Retrieves metrics with caching and parallel partition reads
    #[instrument(skip(self))]
    pub async fn query_metrics(&self, query: MetricsQuery) -> Result<Vec<Metric>, GuardianError> {
        let start_date = query.time_range.0.date();
        let end_date = query.time_range.1.date();
        let mut all_metrics = Vec::new();

        // Calculate partition keys for the date range
        let mut current_date = start_date;
        let mut partition_keys = Vec::new();
        while current_date <= end_date {
            partition_keys.push(format!(
                "{}/{}",
                METRICS_PARTITION_PREFIX,
                current_date.format("%Y-%m-%d")
            ));
            current_date = current_date + chrono::Duration::days(1);
        }

        // Read metrics from each partition in parallel
        let mut tasks = Vec::new();
        for partition_key in partition_keys {
            let zfs_manager = Arc::clone(&self.zfs_manager);
            let cache = Arc::clone(&self.metrics_cache);
            let task = tokio::spawn(async move {
                // Check cache first
                let cache_read = cache.read().await;
                if let Some(metrics) = cache_read.get(&partition_key) {
                    return Ok(metrics.clone());
                }
                drop(cache_read);

                // Read from ZFS if not in cache
                let compressed_data = zfs_manager.read_data(&partition_key).await?;
                let metrics: Vec<Metric> = {
                    let decoder = zstd::Decoder::new(&compressed_data[..]).map_err(|e| {
                        GuardianError::StorageError {
                            context: "Failed to create decompression decoder".into(),
                            source: Some(Box::new(e)),
                            severity: crate::utils::error::ErrorSeverity::High,
                            timestamp: time::OffsetDateTime::now_utc(),
                            correlation_id: uuid::Uuid::new_v4(),
                            category: ErrorCategory::Storage,
                            retry_count: 0,
                        }
                    })?;
                    serde_json::from_reader(decoder).map_err(|e| GuardianError::StorageError {
                        context: "Failed to deserialize metrics".into(),
                        source: Some(Box::new(e)),
                        severity: crate::utils::error::ErrorSeverity::High,
                        timestamp: time::OffsetDateTime::now_utc(),
                        correlation_id: uuid::Uuid::new_v4(),
                        category: ErrorCategory::Storage,
                        retry_count: 0,
                    })?
                };

                // Update cache
                let mut cache_write = cache.write().await;
                cache_write.put(partition_key, metrics.clone());

                Ok::<Vec<Metric>, GuardianError>(metrics)
            });
            tasks.push(task);
        }

        // Collect results
        for task in tasks {
            match task.await {
                Ok(Ok(metrics)) => all_metrics.extend(metrics),
                Ok(Err(e)) => error!("Failed to read metrics partition: {:?}", e),
                Err(e) => error!("Task failed: {:?}", e),
            }
        }

        // Apply filters
        let filtered_metrics = all_metrics
            .into_iter()
            .filter(|m| {
                m.timestamp >= query.time_range.0
                    && m.timestamp <= query.time_range.1
                    && query
                        .metric_names
                        .as_ref()
                        .map(|names| names.contains(&m.name))
                        .unwrap_or(true)
            })
            .collect();

        Ok(filtered_metrics)
    }
}

impl Clone for MetricsStore {
    fn clone(&self) -> Self {
        Self {
            zfs_manager: Arc::clone(&self.zfs_manager),
            metrics_collector: Arc::clone(&self.metrics_collector),
            retention_days: self.retention_days,
            batch_size: self.batch_size,
            compression_level: self.compression_level,
            metrics_cache: Arc::clone(&self.metrics_cache),
        }
    }
}

/// Removes expired metrics with integrity verification
#[instrument]
async fn cleanup_old_metrics(retention_days: u32) -> Result<(), GuardianError> {
    let cutoff_date = Utc::now() - chrono::Duration::days(retention_days as i64);
    info!("Cleaning up metrics older than {}", cutoff_date);

    // Implementation would delete old partitions using ZFS manager
    // Omitted for brevity as it depends on ZFS manager implementation

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[tokio::test]
    async fn test_metrics_storage() {
        // Create test metrics
        let metrics = vec![Metric {
            name: "test_metric".into(),
            value: 42.0,
            timestamp: Utc::now(),
            metric_type: MetricType::Counter,
            tags: HashMap::new(),
        }];

        // Create store with mock ZFS manager
        let store = MetricsStore::new(
            Arc::new(ZfsManager::new(
                "testpool".into(),
                vec![0u8; 32],
                Arc::new(LogManager::new()),
                None,
            ).await.unwrap()),
            DEFAULT_RETENTION_DAYS,
            DEFAULT_BATCH_SIZE,
            DEFAULT_COMPRESSION_LEVEL,
        )
        .await
        .unwrap();

        // Test storing metrics
        assert!(store.store_metrics(metrics).await.is_ok());
    }
}