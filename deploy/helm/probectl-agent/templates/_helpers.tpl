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

{{/*
RTO-12: the image-integrity ImageValidatingPolicy spec (policies.kyverno.io/v1,
GA since Kyverno 1.17), one definition shared by the rendered object and its
probectl.dev/policy-sha256 readiness-gate annotation. It replaces the
kyverno.io/v1 ClusterPolicy verifyImages rule that Kyverno 1.19 deprecates, with
the same semantics: Deny (or, with acceptedRisk, Audit) through
validationActions; failurePolicy Fail so an unreachable Kyverno refuses, never
admits; a digest required (verifyDigest) and a signature from the one attestor
required (required + the validation) for every matching container,
initContainer and ephemeral container image.

matchImageReferences: an ImageValidatingPolicy glob is compared with the RAW
image string, while the ClusterPolicy compared Docker-normalized references
(`ctlplne/x` is `docker.io/ctlplne/x`). The globs keep the raw form, and the CEL
entry matches the same patterns against the normalized reference, so a bare
Docker Hub path is verified exactly as before.
*/}}
{{- define "probectl-agent.imageIntegrityRefMatch" -}}
{{- $patterns := list -}}
{{- range .refs -}}
{{- $patterns = append $patterns (printf "r'^%s$'" (regexQuoteMeta . | replace "\\*" ".*")) -}}
{{- end -}}
{{- printf "[%s].exists(p, ((ref.contains('/') && (ref.split('/')[0].contains('.') || ref.split('/')[0].contains(':') || ref.split('/')[0] == 'localhost')) ? ref : 'docker.io/' + (ref.contains('/') ? '' : 'library/') + ref).matches(p))" (join ", " $patterns) -}}
{{- end -}}

{{- define "probectl-agent.imageIntegritySpec" -}}
{{- $policy := .policy -}}
validationActions:
  - {{ ternary "Deny" "Audit" (eq $policy.failureAction "Enforce") }}
failurePolicy: Fail
evaluation:
  background:
    enabled: {{ $policy.background }}
matchConstraints:
  resourceRules:
    - apiGroups: [""]
      apiVersions: ["v1"]
      operations: ["CREATE", "UPDATE"]
      resources: ["pods"]
matchImageReferences:
  {{- range .refs }}
  - glob: {{ . | quote }}
  {{- end }}
  - expression: {{ include "probectl-agent.imageIntegrityRefMatch" . | quote }}
validationConfigurations:
  required: true
  mutateDigest: false
  verifyDigest: true
attestors:
  - name: probectl
    cosign:
      {{- if $policy.publicKey }}
      key:
        data: {{ $policy.publicKey | quote }}
      {{- if $policy.ignoreTlog }}
      ctlog:
        insecureIgnoreTlog: true
        insecureIgnoreSCT: true
      {{- else if $policy.rekorURL }}
      ctlog:
        url: {{ $policy.rekorURL | quote }}
      {{- end }}
      {{- else }}
      keyless:
        identities:
          - issuer: {{ $policy.issuer | quote }}
            subjectRegExp: {{ $policy.subjectRegExp | quote }}
      {{- if $policy.rekorURL }}
      ctlog:
        url: {{ $policy.rekorURL | quote }}
      {{- end }}
      {{- end }}
validations:
  - expression: >-
      (images.containers + images.initContainers + images.ephemeralContainers).all(i, verifyImageSignatures(i, [attestors.probectl]) > 0)
    messageExpression: >-
      'probectl agent image signature not verified by the configured attestor (SUPPLY-001): ' + (images.containers + images.initContainers + images.ephemeralContainers).filter(i, verifyImageSignatures(i, [attestors.probectl]) == 0).join(', ')
{{- end -}}
