# Contributing to AI Guardian

## Table of Contents
- [Introduction](#introduction)
- [Development Environment Setup](#development-environment-setup)
- [Code Style Guidelines](#code-style-guidelines)
- [Security Requirements](#security-requirements)
- [Testing Guidelines](#testing-guidelines)
- [Pull Request Process](#pull-request-process)
- [CI/CD Pipeline](#cicd-pipeline)
- [Documentation](#documentation)
- [FreeBSD Integration](#freebsd-integration)
- [ML Model Contributions](#ml-model-contributions)
- [Temporal Workflow Guidelines](#temporal-workflow-guidelines)
- [Performance Requirements](#performance-requirements)
- [License Compliance](#license-compliance)

## Introduction

AI Guardian is a critical security system for proprietary gaming consoles. All contributions must maintain the highest standards of security, performance, and reliability. Before contributing, please read our [Code of Conduct](CODE_OF_CONDUCT.md) and [Security Policy](SECURITY.md).

## Development Environment Setup

### Required Tools
- Rust 1.75+ with nightly toolchain
- FreeBSD 13.0+ development environment
- TPM/HSM simulator for security testing
- Temporal.io CLI (1.20+)
- Burn ML framework (0.8+)
- Candle inference engine (0.3+)

### Environment Configuration
```bash
# Install Rust toolchain
curl --proto '=https' --tlsv1.3 https://sh.rustup.rs -sSf | sh
rustup toolchain install nightly
rustup component add clippy rustfmt miri

# FreeBSD development tools
pkg install -y llvm14 cmake ninja protobuf

# ML development tools
cargo install burn-cli
cargo install candle-cli
```

## Code Style Guidelines

### Rust Guidelines
- Follow Rust 2021 edition idioms
- Use `unsafe` blocks only when absolutely necessary with thorough documentation
- Implement comprehensive error handling using custom error types
- Utilize Rust's type system for compile-time guarantees
- Apply `#[deny(unsafe_code)]` where possible

### Memory Safety
- Zero-copy operations when feasible
- Explicit memory management documentation
- Resource cleanup in destructors
- No raw pointer manipulation without security review

### Performance Optimization
- Benchmark-driven development
- Profile-guided optimization
- Cache-friendly data structures
- Async/await for I/O operations

## Security Requirements

### Code Security
- Follow [SECURITY.md](SECURITY.md) guidelines
- Implement defense-in-depth strategies
- Use secure cryptographic primitives
- Regular dependency audits
- Threat modeling for new features

### Vulnerability Management
- Private vulnerability reporting
- Security patch fast-tracking
- Regular security assessments
- Incident response procedures

## Testing Guidelines

### Required Tests
- Unit tests (100% coverage for security-critical code)
- Integration tests
- Fuzz testing for input handling
- Performance benchmarks
- Security test cases

### Test Documentation
```rust
/// Test security-critical functionality
#[test]
fn test_secure_operation() {
    // Test setup
    // Security assertions
    // Cleanup
}
```

## Pull Request Process

1. Security Review Checklist
   - [ ] Threat model assessment
   - [ ] Security testing completed
   - [ ] Dependency audit
   - [ ] Performance impact analysis

2. Documentation Requirements
   - Updated technical documentation
   - Security considerations
   - Performance benchmarks
   - API changes

3. Code Review Standards
   - Two security engineer approvals
   - Performance review
   - Documentation review
   - Integration test verification

## CI/CD Pipeline

Our CI/CD pipeline enforces:
- Security scanning (see [security-scan.yml](.github/workflows/security-scan.yml))
- Performance benchmarking
- FreeBSD compatibility (see [freebsd-ci.yml](.github/workflows/freebsd-ci.yml))
- Backend validation (see [backend-ci.yml](.github/workflows/backend-ci.yml))

## Documentation

### Required Documentation
- API specifications
- Security considerations
- Performance characteristics
- Integration guidelines
- Threat model updates

### Code Documentation
```rust
/// Security-critical function for system integrity
///
/// # Security Considerations
/// - Requires TPM attestation
/// - Implements defense-in-depth
///
/// # Performance
/// - O(1) time complexity
/// - Zero-copy implementation
```

## FreeBSD Integration

### Kernel Integration
- Follow FreeBSD kernel coding style
- Implement Capsicum capabilities
- Use GELI for disk encryption
- Proper jail isolation

### Driver Development
- Memory-safe driver interfaces
- DMA security controls
- Resource management
- Performance optimization

## ML Model Contributions

### Model Requirements
- Documented training data
- Performance benchmarks
- Security validation
- Resource usage analysis

### Training Guidelines
```rust
/// ML model training configuration
pub struct TrainingConfig {
    /// Maximum resource usage
    pub resource_limits: ResourceLimits,
    /// Security validation parameters
    pub security_params: SecurityParams,
}
```

## Temporal Workflow Guidelines

### Workflow Standards
- Idempotent operations
- Error handling patterns
- State management
- Performance optimization

### Security Workflows
```rust
/// Security response workflow
#[workflow]
pub async fn security_response_workflow(
    ctx: WorkflowContext,
    threat: ThreatInfo,
) -> Result<Response> {
    // Implement security response logic
}
```

## Performance Requirements

### Resource Limits
- CPU usage < 5%
- Memory footprint < 100MB
- Latency < 1ms for critical paths
- Throughput requirements

### Optimization Guidelines
- Profile-guided optimization
- Cache optimization
- Memory allocation strategies
- Async I/O patterns

## License Compliance

### Requirements
- License compatibility check
- Third-party audit
- Security review of dependencies
- Documentation of licenses

### Dependency Management
```toml
# Cargo.toml
[dependencies]
tokio = { version = "1.32", features = ["full"] }  # MIT
burn = { version = "0.8", features = ["secure"] }  # Apache-2.0
```

For questions or concerns, please contact the security team or open a discussion.