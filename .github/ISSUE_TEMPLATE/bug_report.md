---
name: Bug Report
about: Create a detailed bug report to help improve the AI Guardian system
title: '[BUG][Component] Brief description'
labels: bug
assignees: ''
---

## Bug Description
### Title
<!-- Provide a clear and concise title that includes the affected component -->

### Description
<!-- Provide a detailed description of the bug including expected vs actual behavior -->

### Steps to Reproduce
1. <!-- Detailed step-by-step instructions -->
2. <!-- Include system state and actions taken -->
3. <!-- Document observed results -->

## Environment Details
### Component
<!-- Select the primary affected component -->
- [ ] Kernel Module
- [ ] ML Engine
- [ ] Security Service
- [ ] Temporal Workflow
- [ ] Storage System
- [ ] Monitoring System
- [ ] Other (please specify)

### Version Information
- System Version: <!-- e.g., v1.2.3 -->
- Component Version: <!-- e.g., ml-engine-v0.8.2 -->
- Commit Hash: <!-- e.g., a1b2c3d -->

### Platform Details
- FreeBSD Version: <!-- e.g., 13.2-RELEASE -->
- Hardware Specifications:
  - CPU: <!-- e.g., 4 cores -->
  - Memory: <!-- e.g., 8GB -->
  - GPU (if applicable): <!-- e.g., Model XYZ -->
- Relevant Configurations: <!-- Any specific system configurations -->

## Impact Assessment
### Severity
- [ ] Critical - System crash, data loss, security breach
- [ ] High - Major functionality broken
- [ ] Medium - Non-critical feature affected
- [ ] Low - Minor inconvenience

### Security Impact
<!-- Required if bug affects security components or data protection -->
- Potential Threats: <!-- List any security implications -->
- Data Exposure Risk: <!-- Describe any data security concerns -->
- Authentication Impact: <!-- Note any authentication/authorization issues -->

### Performance Impact
<!-- Include quantitative metrics if performance is affected -->
- Response Time: <!-- e.g., increased by 200ms -->
- Resource Usage: <!-- e.g., memory leak of 50MB/hour -->
- System Load: <!-- e.g., CPU usage increased by 25% -->

### ML Impact
<!-- Required for ML component issues -->
- Model Accuracy: <!-- e.g., decreased by 5% -->
- Inference Time: <!-- e.g., increased by 100ms -->
- Training Impact: <!-- Any effects on model training -->

## Additional Information
### Logs
<details>
<summary>Relevant System Logs</summary>

```
<!-- Insert sanitized system logs here -->
```
</details>

### Metrics
<details>
<summary>Performance Metrics</summary>

```
<!-- Insert relevant metrics data here -->
```
</details>

### Screenshots
<!-- Add links to relevant screenshots or diagrams -->

### Workaround
<!-- Describe any temporary workaround or mitigation steps if known -->

## Checklist
- [ ] I have searched for similar bugs before creating this report
- [ ] I have included all required information above
- [ ] I have sanitized all logs and removed sensitive information
- [ ] I have included relevant metrics and measurements
- [ ] I have specified the exact versions and commit hashes