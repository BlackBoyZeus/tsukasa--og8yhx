use std::{sync::Arc, time::Duration};
use tonic::{Request, Response, Status};
use tokio::time::timeout;
use metrics::{counter, histogram};
use tracing::{info, warn, error, instrument};
use temporal_sdk_core::{WorkflowClient, WorkflowOptions};
use uuid::Uuid;

use crate::ml::model_manager::{ModelManager, ModelMetadata, ModelStatus, ValidationStatus};
use crate::utils::error::{GuardianError, ErrorCategory};
use crate::proto::ml::{
    MLServiceServer, ModelInferenceRequest, InferenceResult, TrainingRequest, 
    TrainingJob, ModelStatusRequest, Model, ModelUpdateRequest,
    ModelType, ModelStatus as ProtoModelStatus, TrainingStatus,
};

// Constants for service configuration
const INFERENCE_TIMEOUT_MS: u64 = 100;
const MAX_BATCH_SIZE: usize = 128;
const SERVICE_NAME: &str = "guardian.ml.v1.MLService";
const CIRCUIT_BREAKER_THRESHOLD: u32 = 5;
const CIRCUIT_BREAKER_TIMEOUT_MS: u64 = 5000;
const METRICS_FLUSH_INTERVAL_MS: u64 = 1000;

/// Enhanced gRPC service implementation for ML operations
#[derive(Debug)]
pub struct MLService {
    model_manager: Arc<ModelManager>,
    temporal_client: Arc<WorkflowClient>,
    circuit_breaker: Arc<CircuitBreaker>,
    metrics_reporter: Arc<MetricsReporter>,
}

impl MLService {
    /// Creates a new MLService instance with enhanced security and monitoring
    pub fn new(
        model_manager: Arc<ModelManager>,
        temporal_client: Arc<WorkflowClient>,
        circuit_breaker: Arc<CircuitBreaker>,
        metrics_reporter: Arc<MetricsReporter>,
    ) -> Self {
        Self {
            model_manager,
            temporal_client,
            circuit_breaker,
            metrics_reporter,
        }
    }
}

#[tonic::async_trait]
impl MLServiceServer for MLService {
    /// Handles model inference requests with performance optimization
    #[instrument(skip(self, request))]
    async fn inference_request(
        &self,
        request: Request<ModelInferenceRequest>,
    ) -> Result<Response<InferenceResult>, Status> {
        let start = std::time::Instant::now();
        let correlation_id = Uuid::new_v4();

        // Check circuit breaker status
        if !self.circuit_breaker.check().await {
            counter!("guardian.ml.inference.circuit_breaker_trips", 1);
            return Err(Status::unavailable("Service temporarily unavailable"));
        }

        let req = request.into_inner();
        
        // Validate request
        if req.input_data.is_empty() {
            return Err(Status::invalid_argument("Input data cannot be empty"));
        }

        // Execute inference with timeout
        let inference_result = match timeout(
            Duration::from_millis(INFERENCE_TIMEOUT_MS),
            self.model_manager.load_model(req.model_id.clone()),
        ).await {
            Ok(Ok(model)) => {
                let result = model.inference(&req.input_data).await.map_err(|e| {
                    error!("Inference error: {:?}", e);
                    Status::internal("Inference execution failed")
                })?;

                InferenceResult {
                    result_id: Uuid::new_v4().to_string(),
                    model_id: req.model_id,
                    prediction: result.prediction,
                    confidence: result.confidence,
                    timestamp: Some(prost_types::Timestamp::from(std::time::SystemTime::now())),
                    features: result.features,
                    inference_time: start.elapsed().as_micros() as i64,
                }
            },
            Ok(Err(e)) => {
                error!("Model load error: {:?}", e);
                return Err(Status::not_found("Model not found"));
            },
            Err(_) => {
                counter!("guardian.ml.inference.timeouts", 1);
                return Err(Status::deadline_exceeded("Inference timeout"));
            }
        };

        // Record metrics
        histogram!("guardian.ml.inference.latency", start.elapsed().as_millis() as f64);
        counter!("guardian.ml.inference.requests", 1);

        Ok(Response::new(inference_result))
    }

    /// Initiates model training with Temporal.io workflow
    #[instrument(skip(self, request))]
    async fn train_model(
        &self,
        request: Request<TrainingRequest>,
    ) -> Result<Response<TrainingJob>, Status> {
        let req = request.into_inner();
        let workflow_id = format!("train-model-{}", Uuid::new_v4());

        // Start Temporal workflow
        let workflow = self.temporal_client.start_workflow(
            "TrainModelWorkflow",
            req.clone(),
            &WorkflowOptions {
                workflow_id: workflow_id.clone(),
                task_queue: "ml-training".to_string(),
                ..Default::default()
            },
        ).await.map_err(|e| {
            error!("Failed to start training workflow: {:?}", e);
            Status::internal("Failed to initiate training")
        })?;

        let training_job = TrainingJob {
            job_id: workflow_id,
            model_id: req.model_id,
            status: TrainingStatus::Pending as i32,
            progress: 0.0,
            metrics: None,
            start_time: Some(prost_types::Timestamp::from(std::time::SystemTime::now())),
            estimated_completion: None,
            validation_errors: vec![],
        };

        counter!("guardian.ml.training.starts", 1);
        Ok(Response::new(training_job))
    }

    /// Retrieves model status with caching
    #[instrument(skip(self, request))]
    async fn get_model_status(
        &self,
        request: Request<ModelStatusRequest>,
    ) -> Result<Response<Model>, Status> {
        let req = request.into_inner();
        
        let metadata = self.model_manager.get_model_metadata(&req.model_id).await
            .map_err(|e| {
                error!("Failed to get model metadata: {:?}", e);
                Status::not_found("Model not found")
            })?;

        let model = Model {
            model_id: metadata.version,
            version: metadata.name,
            model_type: metadata.model_type as i32,
            status: ProtoModelStatus::from(metadata.status) as i32,
            accuracy: metadata.metrics.map(|m| m.accuracy).unwrap_or(0.0),
            last_updated: Some(prost_types::Timestamp::from(metadata.updated_at.into())),
            performance_metrics: metadata.metrics.map(|m| m.to_hash_map()).unwrap_or_default(),
            model_hash: metadata.hash.into_bytes(),
        };

        counter!("guardian.ml.status.requests", 1);
        Ok(Response::new(model))
    }

    /// Updates model version with validation
    #[instrument(skip(self, request))]
    async fn update_model(
        &self,
        request: Request<ModelUpdateRequest>,
    ) -> Result<Response<Model>, Status> {
        let req = request.into_inner();
        
        // Validate model data
        if req.model_data.is_empty() {
            return Err(Status::invalid_argument("Model data cannot be empty"));
        }

        let metadata = ModelMetadata {
            name: req.model_id.clone(),
            version: req.version.clone(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            status: ModelStatus::Inactive,
            metrics: None,
            validation_status: ValidationStatus::Pending,
            hash: String::new(),
            size_bytes: req.model_data.len() as u64,
        };

        // Deploy model
        self.model_manager.deploy_model(
            req.model_data,
            req.version.clone(),
            metadata.clone(),
        ).await.map_err(|e| {
            error!("Model deployment failed: {:?}", e);
            Status::internal("Failed to deploy model")
        })?;

        let model = Model {
            model_id: metadata.version,
            version: metadata.name,
            model_type: ModelType::ThreatDetection as i32,
            status: ProtoModelStatus::from(metadata.status) as i32,
            accuracy: 0.0,
            last_updated: Some(prost_types::Timestamp::from(std::time::SystemTime::now())),
            performance_metrics: Default::default(),
            model_hash: metadata.hash.into_bytes(),
        };

        counter!("guardian.ml.model.updates", 1);
        Ok(Response::new(model))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[tokio::test]
    async fn test_inference_request() {
        let model_store = Arc::new(ModelStore::new(
            Arc::new(ZfsManager::new(
                "testpool".to_string(),
                vec![0u8; 32],
                Arc::new(LogManager::new()),
                None,
            ).await.unwrap()),
            PathBuf::from("/tmp/test_models"),
            Some(5),
        ).await.unwrap());

        let model_manager = Arc::new(ModelManager::new(
            Arc::new(ModelRegistry::new(model_store).await.unwrap()),
            model_store,
        ).await.unwrap());

        let service = MLService::new(
            model_manager,
            Arc::new(WorkflowClient::new("localhost:7233").await.unwrap()),
            Arc::new(CircuitBreaker::new(CIRCUIT_BREAKER_THRESHOLD)),
            Arc::new(MetricsReporter::new()),
        );

        let request = Request::new(ModelInferenceRequest {
            model_id: "test-model".to_string(),
            input_data: vec![1, 2, 3],
            parameters: Default::default(),
            return_features: false,
        });

        let response = service.inference_request(request).await;
        assert!(response.is_ok());
    }
}