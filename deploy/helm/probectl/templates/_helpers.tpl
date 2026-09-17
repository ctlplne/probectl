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

{{/*
DPR-085: the control plane's OWN selector. The chart's browser-agent DaemonSet
and BGP-analyzer Job carry the same name/instance labels, so anything that
selected by "probectl.selectorLabels" alone — the API Service, the
PodDisruptionBudget, the control NetworkPolicy — also selected those pods: the
budget counted agent pods as control replicas and the control policy's egress
allow-all was unioned onto the browser agent's tight policy. The Deployment's
spec.selector is immutable and stays name/instance; every other control-owned
selector uses this one, and the control pod template carries the component.
*/}}
{{- define "probectl.controlSelectorLabels" -}}
{{ include "probectl.selectorLabels" . }}
app.kubernetes.io/component: control
{{- end -}}

{{/* The immutable control-plane image reference. */}}
{{- define "probectl.image" -}}
{{- $digest := required "image.digest is required: use the sha256 digest from the signed release or approved mirror" .Values.image.digest -}}
{{- if not (regexMatch "^sha256:[0-9a-f]{64}$" $digest) -}}
{{- fail "image.digest must be sha256 followed by exactly 64 lowercase hexadecimal characters" -}}
{{- end -}}
{{- printf "%s@%s" .Values.image.repository $digest -}}
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

{{/*
DPR-046: agent listener values with defaults, so `helm upgrade --reuse-values
--set control.agentListener.enabled=true` works without restating the block.
*/}}
{{- define "probectl.agentListener.port" -}}
{{- int (default 9443 .Values.control.agentListener.port) -}}
{{- end -}}
{{- define "probectl.agentListener.caMountPath" -}}
{{- default "/etc/probectl/agent-ca" (dig "ca" "mountPath" "" .Values.control.agentListener) -}}
{{- end -}}
{{- define "probectl.agentListener.caKey" -}}
{{- default "agent-ca.crt" (dig "ca" "key" "" .Values.control.agentListener) -}}
{{- end -}}
{{- define "probectl.agentListener.caSecret" -}}
{{- dig "ca" "existingSecret" "" .Values.control.agentListener -}}
{{- end -}}
{{- define "probectl.agentListener.caFile" -}}
{{- printf "%s/%s" (include "probectl.agentListener.caMountPath" .) (include "probectl.agentListener.caKey" .) -}}
{{- end -}}
{{- define "probectl.agentListener.serviceType" -}}
{{- default "ClusterIP" (dig "service" "type" "" .Values.control.agentListener) -}}
{{- end -}}
