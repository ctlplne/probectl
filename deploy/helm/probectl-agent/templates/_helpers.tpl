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
