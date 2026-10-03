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

{{/* DPR-117: the OTLP receiver. It serves TLS with the control listener's own
     certificate, so it cannot be enabled without it (§7.12). */}}
{{- define "probectl.otlp" -}}
{{- (.Values.control.otlp | default dict) | toJson -}}
{{- end -}}

{{- define "probectl.otlp.enabled" -}}
{{- if (.Values.control.otlp | default dict).enabled -}}
{{- if not .Values.control.tls.enabled -}}
{{- fail "control.otlp.enabled requires control.tls.enabled: the OTLP receiver serves TLS with the control listener's certificate and there is no plaintext ingest (§7 guardrail 12)" -}}
{{- end -}}
{{- if and (not (.Values.control.otlp.httpPort | int)) (not (.Values.control.otlp.grpcPort | int)) -}}
{{- fail "control.otlp.enabled needs at least one of control.otlp.httpPort / control.otlp.grpcPort" -}}
{{- end -}}
true
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
RTO-14: regulated (strict) profile preflight. The strict overlay sets
PROBECTL_DEPLOYMENT_PROFILE=regulated, which makes the control plane validate a
whole production-like surface at startup (internal/config validateConfig:
verified-TLS Postgres, durable bus/stores, WORM/SIEM audit watermarks). Those
inputs are operator- and environment-specific, so the chart cannot ship sane
defaults for them — but it CAN refuse to render until every one is supplied, in
ONE message, instead of leaving the operator to discover them as a Helm schema
error, a cascade of one-at-a-time template failures, and finally a crash-looping
pod ("deployed" then CrashLoopBackOff). A secret-provided value (the DSN, keys,
WORM signing key inside secrets.existingSecret) is validated at startup, not
here, because the chart cannot read a Secret's contents; this guard requires the
Secret to be named. Fires only for the regulated profile; every other profile is
untouched. See deploy/helm/probectl/values-strict.yaml and docs/hardening.md.
*/}}
{{- define "probectl.regulatedPreflight" -}}
{{- $extraEnv := .Values.control.extraEnv | default dict -}}
{{- $profile := printf "%v" (default "single" (get $extraEnv "PROBECTL_DEPLOYMENT_PROFILE")) -}}
{{- if eq $profile "regulated" -}}
{{- $missing := list -}}
{{- $tls := .Values.control.tls | default dict -}}
{{- $ingress := .Values.ingress | default dict -}}
{{- $backendTLS := $ingress.backendTLS | default dict -}}
{{- $secrets := .Values.secrets | default dict -}}
{{- $worm := (.Values.audit | default dict).worm | default dict -}}
{{- if not (regexMatch "^sha256:[0-9a-f]{64}$" (printf "%v" (default "" .Values.image.digest))) -}}
{{- $missing = append $missing "--set-string image.digest=sha256:<64-hex>  (the signed release/mirror digest; SUPPLY-deb3c967)" -}}
{{- end -}}
{{- if not (and $tls.enabled (trim (printf "%v" (default "" $tls.existingSecret)))) -}}
{{- $missing = append $missing "--set control.tls.existingSecret=<secret>  (operator TLS cert/key for the HTTPS listener; CONFIG-aa08042e)" -}}
{{- end -}}
{{- if $ingress.enabled -}}
{{- if not (trim (printf "%v" (default "" $backendTLS.trustSecret))) -}}
{{- $missing = append $missing "--set ingress.backendTLS.trustSecret=<secret>  (ingress-nginx proxy-ssl CA for the verified backend; CRYPTO-bced5da5)" -}}
{{- end -}}
{{- if not (trim (printf "%v" (default "" $backendTLS.serverName))) -}}
{{- $missing = append $missing "--set ingress.backendTLS.serverName=<name>  (a SAN in the control listener certificate; CRYPTO-bced5da5)" -}}
{{- end -}}
{{- if not .Values.control.trustedProxies -}}
{{- $missing = append $missing "--set 'control.trustedProxies={<ingress CIDR>}'  (the forwarded-client trust for the auth throttle; AUTHZ-04)" -}}
{{- end -}}
{{- end -}}
{{- if not (trim (printf "%v" (default "" $secrets.existingSecret))) -}}
{{- $missing = append $missing "--set secrets.existingSecret=<secret>  (the operator-managed runtime Secret holding PROBECTL_DATABASE_URL with sslmode=verify-ca|verify-full, PROBECTL_ENVELOPE_KEY, PROBECTL_SESSION_HMAC_KEY and PROBECTL_WORM_SIGNING_KEY; WIRE-001/PRIVACY-001)" -}}
{{- end -}}
{{- if not $worm.enabled -}}
{{- $missing = append $missing "--set audit.worm.enabled=true  (signed WORM audit export watermark; PRIVACY-001)" -}}
{{- end -}}
{{- if not (trim (printf "%v" (default "" $worm.existingClaim))) -}}
{{- $missing = append $missing "--set-string audit.worm.existingClaim=<claim>  (a WORM/object-lock PVC for the signed audit segments; DPR-116)" -}}
{{- end -}}
{{- if ne (printf "%v" (default "" (get $extraEnv "PROBECTL_SIEM_ENABLED"))) "true" -}}
{{- $missing = append $missing "--set-string control.extraEnv.PROBECTL_SIEM_ENABLED=true  (tenant audit rows prune only below the SIEM watermark; PRIVACY-001)" -}}
{{- end -}}
{{- if not (trim (printf "%v" (default "" (get $extraEnv "PROBECTL_SIEM_ENDPOINT")))) -}}
{{- $missing = append $missing "--set-string control.extraEnv.PROBECTL_SIEM_ENDPOINT=https://<siem>/ingest  (the SIEM export endpoint; PRIVACY-001)" -}}
{{- end -}}
{{- $busMode := printf "%v" (default "memory" (get $extraEnv "PROBECTL_BUS_MODE")) -}}
{{- if not (or (eq $busMode "kafka") (eq $busMode "nats")) -}}
{{- $missing = append $missing "--set-string control.extraEnv.PROBECTL_BUS_MODE=kafka|nats  (a durable shared bus; an in-memory bus is refused for this profile; PLAT-02/DPR-029)" -}}
{{- end -}}
{{- if not (trim (printf "%v" (default "" (get $extraEnv "PROBECTL_BUS_BROKERS")))) -}}
{{- $missing = append $missing "--set-string control.extraEnv.PROBECTL_BUS_BROKERS=<host:port[,...]>  (the shared bus endpoints; PLAT-02)" -}}
{{- end -}}
{{- if ne (printf "%v" (default "" (get $extraEnv "PROBECTL_BUS_TLS_ENABLED"))) "true" -}}
{{- $missing = append $missing "--set-string control.extraEnv.PROBECTL_BUS_TLS_ENABLED=true  (a networked bus without TLS is refused; U-010)" -}}
{{- end -}}
{{- if ne (printf "%v" (default "memory" (get $extraEnv "PROBECTL_TSDB_MODE"))) "prometheus" -}}
{{- $missing = append $missing "--set-string control.extraEnv.PROBECTL_TSDB_MODE=prometheus  (a durable shared TSDB; an in-memory TSDB is refused; PLAT-02)" -}}
{{- end -}}
{{- if not (trim (printf "%v" (default "" (get $extraEnv "PROBECTL_TSDB_URL")))) -}}
{{- $missing = append $missing "--set-string control.extraEnv.PROBECTL_TSDB_URL=https://<prometheus>  (the shared TSDB remote-write/query endpoint; PLAT-02)" -}}
{{- end -}}
{{- range $se := list "PROBECTL_PATHSTORE" "PROBECTL_FLOWSTORE" "PROBECTL_OTELSTORE" "PROBECTL_EBPFSTORE" "PROBECTL_ENDPOINTSTORE" -}}
{{- $modeKey := printf "%s_MODE" $se -}}
{{- $urlKey := printf "%s_URL" $se -}}
{{- if ne (printf "%v" (default "memory" (get $extraEnv $modeKey))) "clickhouse" -}}
{{- $missing = append $missing (printf "--set-string control.extraEnv.%s=clickhouse  (a durable shared store per plane; an in-memory store is refused; PLAT-02)" $modeKey) -}}
{{- end -}}
{{- if not (trim (printf "%v" (default "" (get $extraEnv $urlKey)))) -}}
{{- $missing = append $missing (printf "--set-string control.extraEnv.%s=https://<clickhouse>:8443  (the shared ClickHouse endpoint; PLAT-02)" $urlKey) -}}
{{- end -}}
{{- end -}}
{{- if gt (len $missing) 0 -}}
{{- fail (printf "PROBECTL_DEPLOYMENT_PROFILE=regulated (the strict/regulated profile, deploy/helm/probectl/values-strict.yaml) cannot be installed without operator-supplied values. The control plane validates ALL of these at startup, so the chart fails here, before deploy, rather than letting a pod crash-loop. Supply every value below (see values-strict.yaml and docs/hardening.md), then re-run:\n  %s" (join "\n  " $missing)) -}}
{{- end -}}
{{- end -}}
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
