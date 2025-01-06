{{/*
Expand the name of the chart with FreeBSD compatibility
*/}}
{{- define "guardian.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a fully qualified app name with FreeBSD and gaming console compatibility.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "guardian.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "guardian.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels with enhanced security metadata for FreeBSD and gaming console environment
*/}}
{{- define "guardian.labels" -}}
helm.sh/chart: {{ include "guardian.chart" . }}
{{ include "guardian.selectorLabels" . }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
security.guardian.io/freebsd-version: {{ .Values.global.freebsd.version | default "13.0" | quote }}
security.guardian.io/capsicum-enabled: {{ .Values.global.security.capsicum.enabled | default "true" | quote }}
security.guardian.io/tpm-enabled: {{ .Values.global.security.tpm.enabled | default "true" | quote }}
security.guardian.io/secure-level: {{ .Values.global.freebsd.sysctls.kern\.securelevel | default "2" | quote }}
platform.guardian.io/type: "gaming-console"
{{- end }}

{{/*
Selector labels with security context
*/}}
{{- define "guardian.selectorLabels" -}}
app.kubernetes.io/name: {{ include "guardian.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
security.guardian.io/component-type: {{ .Values.componentType | default "core" }}
{{- end }}

{{/*
Create the name of the service account with security context
*/}}
{{- define "guardian.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "guardian.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
FreeBSD security capabilities configuration
*/}}
{{- define "guardian.securityCapabilities" -}}
{{- if .Values.global.security.capsicum.enabled }}
capabilities:
{{- range .Values.global.security.capsicum.capabilities }}
  - {{ . }}
{{- end }}
{{- end }}
{{- end }}

{{/*
TPM configuration for secure boot and attestation
*/}}
{{- define "guardian.tpmConfig" -}}
{{- if .Values.global.security.tpm.enabled }}
tpm:
  enabled: true
  devicePath: {{ .Values.global.security.tpm.devicePath | default "/dev/tpm0" }}
{{- end }}
{{- end }}

{{/*
ZFS dataset configuration for secure storage
*/}}
{{- define "guardian.zfsConfig" -}}
{{- if .Values.backend.zfs.enabled }}
zfs:
  dataset: {{ .Values.backend.zfs.dataset }}
  compression: {{ .Values.backend.zfs.compression }}
  encryption: {{ .Values.backend.zfs.encryption }}
{{- end }}
{{- end }}

{{/*
Security context configuration with FreeBSD enhancements
*/}}
{{- define "guardian.securityContext" -}}
securityContext:
  runAsUser: {{ .Values.global.security.runAsUser }}
  runAsGroup: {{ .Values.global.security.runAsGroup }}
  fsGroup: {{ .Values.global.security.fsGroup }}
  runAsNonRoot: {{ .Values.global.security.runAsNonRoot }}
  readOnlyRootFilesystem: {{ .Values.global.security.readOnlyRootFilesystem }}
  seccompProfile:
    type: {{ .Values.global.security.seccompProfile.type }}
{{- if .Values.global.security.capsicum.enabled }}
  {{- include "guardian.securityCapabilities" . | nindent 2 }}
{{- end }}
{{- end }}

{{/*
Resource requirements helper
*/}}
{{- define "guardian.resources" -}}
{{- if .Values.resources }}
resources:
  {{- toYaml .Values.resources | nindent 2 }}
{{- end }}
{{- end }}

{{/*
Health check configuration helper
*/}}
{{- define "guardian.healthCheck" -}}
{{- if .Values.healthCheck.enabled }}
livenessProbe:
  httpGet:
    path: {{ .Values.healthCheck.path }}
    port: http
  initialDelaySeconds: {{ .Values.healthCheck.initialDelaySeconds }}
  periodSeconds: {{ .Values.healthCheck.periodSeconds }}
  timeoutSeconds: {{ .Values.healthCheck.timeoutSeconds }}
  failureThreshold: {{ .Values.healthCheck.failureThreshold }}
  successThreshold: {{ .Values.healthCheck.successThreshold }}
readinessProbe:
  httpGet:
    path: {{ .Values.healthCheck.path }}
    port: http
  initialDelaySeconds: {{ .Values.healthCheck.initialDelaySeconds }}
  periodSeconds: {{ .Values.healthCheck.periodSeconds }}
  timeoutSeconds: {{ .Values.healthCheck.timeoutSeconds }}
  failureThreshold: {{ .Values.healthCheck.failureThreshold }}
  successThreshold: {{ .Values.healthCheck.successThreshold }}
{{- end }}
{{- end }}