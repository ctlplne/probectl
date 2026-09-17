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

{{/* DPR-108: TLS posture for the chart's own datastore Jobs (§7.12). The dump
     and the restore carry the whole tenant database across the pod network, so
     they connect at least as strictly as the control plane does. An empty
     sslmode resolves to verify-full when a deployment trust bundle is mounted
     into the Job, and to require otherwise (encrypted, server unverified —
     the strongest posture available without a CA to verify against). */}}
{{- define "probectl.trustBundlePath" -}}
{{- printf "%s/%s" .Values.control.trustBundle.mountPath .Values.control.trustBundle.key -}}
{{- end -}}

{{- define "probectl.backupPGSSLMode" -}}
{{- if .Values.backup.postgres.sslmode -}}
{{- .Values.backup.postgres.sslmode -}}
{{- else if .Values.control.trustBundle.existingConfigMap -}}
verify-full
{{- else -}}
require
{{- end -}}
{{- end -}}

{{- define "probectl.restorePGSSLMode" -}}
{{- if .Values.restore.sslmode -}}
{{- .Values.restore.sslmode -}}
{{- else if .Values.control.trustBundle.existingConfigMap -}}
verify-full
{{- else -}}
require
{{- end -}}
{{- end -}}

{{/* `helm upgrade --reuse-values` carries the previous release's values and
     drops new chart defaults (DPR-090), so an ABSENT secure flag must mean on:
     an upgrade from a release that predates this must not keep talking
     plaintext to ClickHouse. Empty output means plaintext, which an operator
     has to ask for explicitly. */}}
{{- define "probectl.backupCHSecure" -}}
{{- if or (not (hasKey .Values.backup.clickhouse "secure")) .Values.backup.clickhouse.secure -}}true{{- end -}}
{{- end -}}

{{- define "probectl.restoreCHSecure" -}}
{{- if or (not (hasKey .Values.restore.clickhouse "secure")) .Values.restore.clickhouse.secure -}}true{{- end -}}
{{- end -}}

{{- define "probectl.backupCHPort" -}}
{{- if .Values.backup.clickhouse.port -}}
{{- .Values.backup.clickhouse.port -}}
{{- else if eq (include "probectl.backupCHSecure" .) "true" -}}
9440
{{- else -}}
9000
{{- end -}}
{{- end -}}

{{- define "probectl.restoreCHPort" -}}
{{- if .Values.restore.clickhouse.port -}}
{{- .Values.restore.clickhouse.port -}}
{{- else if eq (include "probectl.restoreCHSecure" .) "true" -}}
9440
{{- else -}}
9000
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

{{/*
probectl.jobContainerSecurityContext (DPR-088): the container hardening every
backup CronJob and restore Job container carries — the same posture as the
control-plane container. These pods write only to their mounted volumes, so
the root filesystem stays read-only; the pod-level uid/gid stays per image.
*/}}
{{- define "probectl.jobContainerSecurityContext" -}}
allowPrivilegeEscalation: false
readOnlyRootFilesystem: true
capabilities:
  drop: ["ALL"]
{{- end }}
