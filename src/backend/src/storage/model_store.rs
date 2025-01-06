use std::{
    path::PathBuf,
    sync::Arc,
};
use tokio::sync::RwLock;
use async_trait::async_trait;
use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc};
use sha2::{Sha256, Digest};
use lru::LruCache;
use tracing::{info, warn, error, instrument};

use crate::utils::error::{GuardianError, ErrorCategory};
use crate::storage::zfs_manager::ZfsManager;

// Constants for model storage configuration
const MODEL_DATASET_PREFIX: &str = "models";
const VERSION_INDEX_FILE: &str = "version_index.json";
const MAX_MODEL_SIZE: u64 = 1024 * 1024 * 1024; // 1GB
const VERSION_REGEX: &str = r"^v\d+\.\d+\.\d+$";
const DEFAULT_CACHE_SIZE: usize = 5;

/// Metadata for stored ML model versions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelVersion {
    pub version: String,
    pub created_at: DateTime<Utc>,
    pub hash: String,
    pub size: u64,
    pub compression_ratio: f64,
}

/// Manages secure storage and versioning of ML models
#[derive(Debug)]
#[async_trait]
pub struct ModelStore {
    zfs_manager: Arc<ZfsManager>,
    base_path: PathBuf,
    model_cache: Arc<RwLock<LruCache<String, Vec<u8>>>>,
}

impl ModelStore {
    /// Creates a new ModelStore instance with caching
    pub async fn new(
        zfs_manager: Arc<ZfsManager>,
        base_path: PathBuf,
        cache_size: Option<usize>,
    ) -> Result<Self, GuardianError> {
        let cache_size = cache_size.unwrap_or(DEFAULT_CACHE_SIZE);
        
        // Initialize model storage dataset with LZ4 compression
        let dataset_path = format!("{}/{}", base_path.display(), MODEL_DATASET_PREFIX);
        zfs_manager.create_dataset(
            &dataset_path,
            Some(std::collections::HashMap::from([
                ("compression".to_string(), "lz4".to_string()),
            ])),
            None,
        ).await.map_err(|e| GuardianError::StorageError {
            context: "Failed to initialize model storage dataset".into(),
            source: Some(Box::new(e)),
            severity: crate::utils::error::ErrorSeverity::Critical,
            timestamp: time::OffsetDateTime::now_utc(),
            correlation_id: uuid::Uuid::new_v4(),
            category: ErrorCategory::Storage,
            retry_count: 0,
        })?;

        Ok(Self {
            zfs_manager,
            base_path,
            model_cache: Arc::new(RwLock::new(LruCache::new(cache_size))),
        })
    }

    /// Stores a new ML model version with verification
    #[instrument(skip(self, model_data))]
    pub async fn store_model(
        &self,
        model_data: Vec<u8>,
        version: String,
    ) -> Result<ModelVersion, GuardianError> {
        // Validate model size and version format
        if model_data.len() as u64 > MAX_MODEL_SIZE {
            return Err(GuardianError::StorageError {
                context: format!("Model size exceeds maximum allowed size of {} bytes", MAX_MODEL_SIZE),
                source: None,
                severity: crate::utils::error::ErrorSeverity::High,
                timestamp: time::OffsetDateTime::now_utc(),
                correlation_id: uuid::Uuid::new_v4(),
                category: ErrorCategory::Storage,
                retry_count: 0,
            });
        }

        validate_version(&version)?;

        // Calculate model hash
        let mut hasher = Sha256::new();
        hasher.update(&model_data);
        let hash = format!("{:x}", hasher.finalize());

        // Create version dataset
        let version_path = format!("{}/{}/{}", self.base_path.display(), MODEL_DATASET_PREFIX, version);
        self.zfs_manager.create_dataset(
            &version_path,
            Some(std::collections::HashMap::from([
                ("compression".to_string(), "lz4".to_string()),
            ])),
            None,
        ).await?;

        // Store model data
        let model_file = format!("{}/model.bin", version_path);
        tokio::fs::write(&model_file, &model_data).await.map_err(|e| GuardianError::StorageError {
            context: format!("Failed to write model data for version {}", version),
            source: Some(Box::new(e)),
            severity: crate::utils::error::ErrorSeverity::High,
            timestamp: time::OffsetDateTime::now_utc(),
            correlation_id: uuid::Uuid::new_v4(),
            category: ErrorCategory::Storage,
            retry_count: 0,
        })?;

        // Create version metadata
        let version_info = ModelVersion {
            version: version.clone(),
            created_at: Utc::now(),
            hash,
            size: model_data.len() as u64,
            compression_ratio: 0.0, // Will be updated with actual ZFS compression ratio
        };

        // Update cache
        self.model_cache.write().await.put(version.clone(), model_data);

        info!("Stored model version {} successfully", version);
        Ok(version_info)
    }

    /// Loads a specific model version with caching
    #[instrument(skip(self))]
    pub async fn load_model(&self, version: String) -> Result<Vec<u8>, GuardianError> {
        // Check cache first
        if let Some(cached_data) = self.model_cache.read().await.get(&version) {
            // Verify cached data integrity
            let mut hasher = Sha256::new();
            hasher.update(cached_data);
            let cached_hash = format!("{:x}", hasher.finalize());

            let version_path = format!("{}/{}/{}", self.base_path.display(), MODEL_DATASET_PREFIX, version);
            let metadata_file = format!("{}/metadata.json", version_path);
            let metadata: ModelVersion = tokio::fs::read_to_string(&metadata_file)
                .await
                .map_err(|e| GuardianError::StorageError {
                    context: format!("Failed to read metadata for version {}", version),
                    source: Some(Box::new(e)),
                    severity: crate::utils::error::ErrorSeverity::Medium,
                    timestamp: time::OffsetDateTime::now_utc(),
                    correlation_id: uuid::Uuid::new_v4(),
                    category: ErrorCategory::Storage,
                    retry_count: 0,
                })
                .and_then(|data| serde_json::from_str(&data).map_err(|e| GuardianError::StorageError {
                    context: format!("Failed to parse metadata for version {}", version),
                    source: Some(Box::new(e)),
                    severity: crate::utils::error::ErrorSeverity::Medium,
                    timestamp: time::OffsetDateTime::now_utc(),
                    correlation_id: uuid::Uuid::new_v4(),
                    category: ErrorCategory::Storage,
                    retry_count: 0,
                }))?;

            if cached_hash == metadata.hash {
                return Ok(cached_data.clone());
            }
        }

        // Load from storage
        let version_path = format!("{}/{}/{}", self.base_path.display(), MODEL_DATASET_PREFIX, version);
        let model_file = format!("{}/model.bin", version_path);
        
        let model_data = tokio::fs::read(&model_file).await.map_err(|e| GuardianError::StorageError {
            context: format!("Failed to read model data for version {}", version),
            source: Some(Box::new(e)),
            severity: crate::utils::error::ErrorSeverity::High,
            timestamp: time::OffsetDateTime::now_utc(),
            correlation_id: uuid::Uuid::new_v4(),
            category: ErrorCategory::Storage,
            retry_count: 0,
        })?;

        // Update cache
        self.model_cache.write().await.put(version.clone(), model_data.clone());

        Ok(model_data)
    }

    /// Lists all available model versions
    #[instrument(skip(self))]
    pub async fn list_versions(&self) -> Result<Vec<ModelVersion>, GuardianError> {
        let versions_path = format!("{}/{}", self.base_path.display(), MODEL_DATASET_PREFIX);
        let mut versions = Vec::new();

        let mut entries = tokio::fs::read_dir(&versions_path).await.map_err(|e| GuardianError::StorageError {
            context: "Failed to read versions directory".into(),
            source: Some(Box::new(e)),
            severity: crate::utils::error::ErrorSeverity::Medium,
            timestamp: time::OffsetDateTime::now_utc(),
            correlation_id: uuid::Uuid::new_v4(),
            category: ErrorCategory::Storage,
            retry_count: 0,
        })?;

        while let Some(entry) = entries.next_entry().await.map_err(|e| GuardianError::StorageError {
            context: "Failed to read version entry".into(),
            source: Some(Box::new(e)),
            severity: crate::utils::error::ErrorSeverity::Medium,
            timestamp: time::OffsetDateTime::now_utc(),
            correlation_id: uuid::Uuid::new_v4(),
            category: ErrorCategory::Storage,
            retry_count: 0,
        })? {
            let metadata_file = entry.path().join("metadata.json");
            if metadata_file.exists() {
                let metadata: ModelVersion = tokio::fs::read_to_string(&metadata_file)
                    .await
                    .map_err(|e| GuardianError::StorageError {
                        context: format!("Failed to read metadata file: {:?}", metadata_file),
                        source: Some(Box::new(e)),
                        severity: crate::utils::error::ErrorSeverity::Medium,
                        timestamp: time::OffsetDateTime::now_utc(),
                        correlation_id: uuid::Uuid::new_v4(),
                        category: ErrorCategory::Storage,
                        retry_count: 0,
                    })
                    .and_then(|data| serde_json::from_str(&data).map_err(|e| GuardianError::StorageError {
                        context: format!("Failed to parse metadata file: {:?}", metadata_file),
                        source: Some(Box::new(e)),
                        severity: crate::utils::error::ErrorSeverity::Medium,
                        timestamp: time::OffsetDateTime::now_utc(),
                        correlation_id: uuid::Uuid::new_v4(),
                        category: ErrorCategory::Storage,
                        retry_count: 0,
                    }))?;
                versions.push(metadata);
            }
        }

        Ok(versions)
    }

    /// Deletes a specific model version
    #[instrument(skip(self))]
    pub async fn delete_version(&self, version: String) -> Result<(), GuardianError> {
        validate_version(&version)?;

        let version_path = format!("{}/{}/{}", self.base_path.display(), MODEL_DATASET_PREFIX, version);
        self.zfs_manager.destroy_dataset(&version_path).await?;

        // Remove from cache
        self.model_cache.write().await.pop(&version);

        info!("Deleted model version {} successfully", version);
        Ok(())
    }
}

/// Validates model version string format and uniqueness
#[inline]
fn validate_version(version: &str) -> Result<(), GuardianError> {
    let re = regex::Regex::new(VERSION_REGEX).unwrap();
    if !re.is_match(version) {
        return Err(GuardianError::StorageError {
            context: format!("Invalid version format: {}. Must match pattern: {}", version, VERSION_REGEX),
            source: None,
            severity: crate::utils::error::ErrorSeverity::Medium,
            timestamp: time::OffsetDateTime::now_utc(),
            correlation_id: uuid::Uuid::new_v4(),
            category: ErrorCategory::Storage,
            retry_count: 0,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[tokio::test]
    async fn test_model_storage() {
        let zfs_manager = Arc::new(ZfsManager::new(
            "testpool".to_string(),
            vec![0u8; 32],
            Arc::new(crate::utils::logging::LogManager::new()),
            None,
        ).await.unwrap());

        let store = ModelStore::new(
            zfs_manager,
            PathBuf::from("/guardian/models"),
            Some(5),
        ).await.unwrap();

        let test_data = vec![1, 2, 3, 4, 5];
        let version = "v1.0.0".to_string();

        // Test storing model
        let result = store.store_model(test_data.clone(), version.clone()).await;
        assert!(result.is_ok());

        // Test loading model
        let loaded_data = store.load_model(version.clone()).await.unwrap();
        assert_eq!(loaded_data, test_data);

        // Test version listing
        let versions = store.list_versions().await.unwrap();
        assert_eq!(versions.len(), 1);
        assert_eq!(versions[0].version, version);

        // Test version deletion
        assert!(store.delete_version(version).await.is_ok());
    }

    #[tokio::test]
    async fn test_version_validation() {
        assert!(validate_version("v1.0.0").is_ok());
        assert!(validate_version("invalid").is_err());
        assert!(validate_version("v1.0").is_err());
        assert!(validate_version("v1.0.0-alpha").is_err());
    }
}