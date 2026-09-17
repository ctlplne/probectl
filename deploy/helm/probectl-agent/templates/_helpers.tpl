{{- define "probectl-agent.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "probectl-agent.fullname" -}}
{{- printf "%s-%s" .Release.Name (include "probectl-agent.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "probectl-agent.labels" -}}
app.kubernetes.io/name: {{ include "probectl-agent.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/part-of: probectl
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "probectl-agent.selectorLabels" -}}
app.kubernetes.io/name: {{ include "probectl-agent.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{/*
DPR-051: the registered collector identity is REQUIRED. Without it the control
plane rejects every batch (TENANT-101), so rendering refuses instead of
shipping a DaemonSet that can never deliver data.
*/}}
{{- define "probectl-agent.agentID" -}}
{{- required "agentID is required: the collector id this tenant registered for these nodes (register-collector -plane ebpf, POST /v1/collectors/register, or Admin & Settings > Agents > Register collector). The control plane verifies every batch's (tenant, agent_id) pair against the tenant's registry (TENANT-101) and rejects unregistered identities." .Values.agentID -}}
{{- end -}}
