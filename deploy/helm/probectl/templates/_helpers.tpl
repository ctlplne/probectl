{{/* Expand the chart name. */}}
{{- define "probectl.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/* Fully qualified app name. */}}
{{- define "probectl.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/* Common labels. */}}
{{- define "probectl.labels" -}}
app.kubernetes.io/name: {{ include "probectl.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
{{- end -}}

{{/* Selector labels. */}}
{{- define "probectl.selectorLabels" -}}
app.kubernetes.io/name: {{ include "probectl.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{/* The image reference (tag falls back to appVersion). */}}
{{- define "probectl.image" -}}
{{- $tag := .Values.image.tag | default .Chart.AppVersion -}}
{{- printf "%s:%s" .Values.image.repository $tag -}}
{{- end -}}

{{/* The Secret name to read sensitive env from. */}}
{{- define "probectl.secretName" -}}
{{- if .Values.secrets.existingSecret -}}
{{- .Values.secrets.existingSecret -}}
{{- else -}}
{{- printf "%s-secrets" (include "probectl.fullname" .) -}}
{{- end -}}
{{- end -}}

{{/* ServiceAccount name. */}}
{{- define "probectl.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "probectl.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{/* Named Service/container port for the control listener transport. */}}
{{- define "probectl.servicePortName" -}}
{{- if .Values.control.tls.enabled -}}https{{- else -}}http{{- end -}}
{{- end -}}

{{/* Kubernetes HTTP probe scheme for the rendered control listener. */}}
{{- define "probectl.probeScheme" -}}
{{- if .Values.control.tls.enabled -}}HTTPS{{- else -}}HTTP{{- end -}}
{{- end -}}

{{/* Prometheus ServiceMonitor scheme for the rendered control listener. */}}
{{- define "probectl.serviceScheme" -}}
{{- if .Values.control.tls.enabled -}}https{{- else -}}http{{- end -}}
{{- end -}}
