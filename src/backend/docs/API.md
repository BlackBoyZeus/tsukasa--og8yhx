# AI Guardian System API Documentation

## Table of Contents
- [Overview](#overview)
- [Authentication](#authentication)
- [Services](#services)
  - [Guardian Service](#guardian-service)
  - [Security Service](#security-service)
  - [ML Service](#ml-service)
- [Integration Patterns](#integration-patterns)
- [Error Handling](#error-handling)
- [Performance Characteristics](#performance-characteristics)

## Overview

The AI Guardian system exposes a comprehensive set of gRPC services for system management, security operations, and ML-based threat detection. All services require mutual TLS (mTLS) authentication and implement rate limiting and circuit breaker patterns.

## Authentication

### mTLS Configuration
- Protocol: TLS 1.3
- Certificate Requirements:
  - X.509 v3
  - 4096-bit RSA or P-256 ECC
  - Maximum validity: 90 days
- Certificate Authority: Internal PKI

### Rate Limiting
```
| Service          | Rate Limit    | Burst Limit |
|------------------|---------------|-------------|
| Guardian Service | 1000 req/min  | 100 req/sec |
| Security Service | 2000 req/min  | 200 req/sec |
| ML Service       | 500 req/min   | 50 req/sec  |
```

## Services

### Guardian Service

Core system management and monitoring service.

#### Methods

##### GetSystemStatus
```protobuf
rpc GetSystemStatus(google.protobuf.Empty) returns (SystemStatus)
```
Returns comprehensive system status including component health and metrics.

**Response:**
```json
{
  "state": "SYSTEM_STATE_RUNNING",
  "uptime_seconds": 86400,
  "metrics": {
    "cpu_usage": 0.45,
    "memory_usage": 0.62,
    "gpu_usage": 0.25
  },
  "components": [
    {
      "component_id": "ml-engine",
      "state": "SYSTEM_STATE_RUNNING",
      "version": "1.2.0"
    }
  ]
}
```

##### StreamMetrics
```protobuf
rpc StreamMetrics(MetricsFilter) returns (stream SystemMetrics)
```
Streams real-time system metrics with configurable filtering.

**Request:**
```json
{
  "metric_names": ["cpu_usage", "memory_usage"],
  "sample_rate_ms": 1000,
  "threshold": 0.8
}
```

### Security Service

Comprehensive security operations and threat management.

#### Methods

##### MonitorThreats
```protobuf
rpc MonitorThreats(MonitorThreatsRequest) returns (stream ThreatAlert)
```
Streams real-time threat alerts with severity filtering.

**Request:**
```json
{
  "severity_filters": ["THREAT_SEVERITY_HIGH", "THREAT_SEVERITY_CRITICAL"],
  "include_ml_analysis": true
}
```

##### ExecuteResponse
```protobuf
rpc ExecuteResponse(ResponseAction) returns (ResponseResult)
```
Executes security response actions for detected threats.

**Request:**
```json
{
  "threat_id": "550e8400-e29b-41d4-a716-446655440000",
  "action_type": "ISOLATE_PROCESS",
  "parameters": {
    "process_id": "1234",
    "timeout_ms": "5000"
  }
}
```

### ML Service

Machine learning inference and model management.

#### Methods

##### Predict
```protobuf
rpc Predict(PredictRequest) returns (PredictResponse)
```
High-performance single prediction inference.

**Request:**
```json
{
  "input_data": {
    "metrics": {
      "cpu_usage": 0.85,
      "memory_pressure": 0.75
    },
    "metadata": {
      "source": "system_monitor"
    }
  }
}
```

## Integration Patterns

### Circuit Breaker Configuration
```
| Service          | Failure Threshold | Timeout | Reset Time |
|------------------|------------------|---------|------------|
| Guardian Service | 5 failures       | 1s      | 30s        |
| Security Service | 3 failures       | 2s      | 60s        |
| ML Service       | 5 failures       | 500ms   | 45s        |
```

### Health Check Endpoints
All services implement a standard health check interface:
```protobuf
rpc PerformHealthCheck(HealthCheckRequest) returns (HealthCheckResponse)
```

### Service Discovery
Services register with the system registry on startup with the following metadata:
- Service ID (UUID)
- Service Type
- Version
- Health Check URL
- Resource Requirements

## Error Handling

### Standard Error Codes
```
| Code | Description           | Recovery Action          |
|------|----------------------|-------------------------|
| 1    | Invalid Request      | Fix request parameters  |
| 2    | Authentication Error | Refresh certificates    |
| 3    | Rate Limited         | Implement backoff       |
| 4    | Service Unavailable  | Retry with exponential backoff |
| 5    | Internal Error       | Contact system admin    |
```

### Error Response Format
```json
{
  "error_code": 1,
  "message": "Invalid request parameters",
  "details": {
    "field": "metrics",
    "reason": "Required field missing"
  },
  "request_id": "550e8400-e29b-41d4-a716-446655440000"
}
```

## Performance Characteristics

### Latency Requirements
```
| Operation          | P95 Latency | P99 Latency |
|-------------------|-------------|-------------|
| Status Retrieval  | 50ms        | 100ms       |
| Threat Detection  | 100ms       | 200ms       |
| ML Inference      | 20ms        | 50ms        |
```

### Resource Utilization
- Maximum connections per client: 100
- Maximum concurrent streams per connection: 50
- Keep-alive timeout: 30s
- Maximum message size: 4MB

### Monitoring Metrics
All services export the following metrics:
- Request rate
- Error rate
- Response latency
- Resource utilization
- Circuit breaker status
- Active connections