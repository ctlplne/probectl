#!/usr/bin/env bash
# Helm hardening gate (S35, F29): render the chart and assert the secure-by-default
# invariants hold. This is a security surface — a regression here (a dropped
# securityContext, a re-introduced default credential, a missing NetworkPolicy in
# the large profile) must fail CI. Requires `helm` on PATH.
set -euo pipefail

CHART="${CHART:-deploy/helm/probectl}"
# A throwaway base64 32-byte key just to let rendering proceed.
KEY="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

fail() {
  echo "helm hardening gate: FAIL — $*" >&2
  exit 1
}

render() {
  helm template probectl "$CHART" "$@" \
    --set ingress.host=h.example.com \
    --set ingress.tlsSecretName=probectl-tls \
    --set secrets.envelopeKey="$KEY" \
    --set database.url="postgres://probectl:s3cret-not-default@db:5432/probectl?sslmode=require"
}

need() { grep -q -- "$1" <<<"$2" || fail "$3"; }

bash scripts/check_clickhouse_restore_contract.sh

# 1. No default credentials: rendering without an envelope key (and no
#    existingSecret) must FAIL closed.
if helm template probectl "$CHART" \
  --set ingress.host=h.example.com --set ingress.tlsSecretName=probectl-tls >/dev/null 2>&1; then
  fail "chart rendered with no secrets.envelopeKey — that would be a default credential"
fi

# 1b. OPS-001: no default DATABASE credential. Rendering with NO database.url must
#     fail closed, and rendering WITH the shipped dev credential (probectl:probectl)
#     must fail too — an operator who forgets to override must never materialize a
#     known password into a Kubernetes Secret.
if helm template probectl "$CHART" \
  --set ingress.host=h.example.com --set ingress.tlsSecretName=probectl-tls \
  --set secrets.envelopeKey="$KEY" >/dev/null 2>&1; then
  fail "chart rendered with no database.url — that would be a blank/default DB credential (OPS-001)"
fi
if helm template probectl "$CHART" \
  --set ingress.host=h.example.com --set ingress.tlsSecretName=probectl-tls \
  --set secrets.envelopeKey="$KEY" \
  --set database.url="postgres://probectl:probectl@db:5432/probectl?sslmode=require" >/dev/null 2>&1; then
  fail "chart rendered with the dev credential probectl:probectl (OPS-001)"
fi
# The rendered manifests must never carry the dev credential.
if grep -q "probectl:probectl@" <<<"$(render)"; then
  fail "rendered manifests contain the dev credential probectl:probectl (OPS-001)"
fi
# 1c. Static: no values file may SHIP the dev credential as a default — a render
#     override can't paper over a committed default, so catch it in source.
if grep -rnE 'probectl:probectl@' "$CHART"/values*.yaml 2>/dev/null; then
  fail "a values file ships the dev credential probectl:probectl as a default (OPS-001)"
fi

# 2. Default profile: the hardened pod posture + HTTPS-by-default.
base="$(render)"
need "runAsNonRoot: true"              "$base" "missing runAsNonRoot"
need "readOnlyRootFilesystem: true"    "$base" "root filesystem not read-only"
need "allowPrivilegeEscalation: false" "$base" "privilege escalation not disabled"
need "runAsUser: 65532"                "$base" "non-root uid not pinned"
need "drop:"                           "$base" "capabilities not dropped"
need "automountServiceAccountToken: false" "$base" "service-account token automount not disabled"
need "path: /readyz"                   "$base" "missing /readyz readiness probe (S34 drain)"
need "path: /healthz"                  "$base" "missing /healthz liveness probe"
# OPS-009: HSTS is delivered by the APPLICATION (PROBECTL_HSTS_ENABLED), not via
# a configuration-snippet annotation that modern ingress-nginx disables by
# default. Assert the app-HSTS env is rendered on; and that the ingress does NOT
# fall back to a snippet-delivered header (which would silently vanish).
need 'PROBECTL_HSTS_ENABLED: "true"'   "$base" "app HSTS not enabled (HTTPS-by-default, OPS-009)"
need "PROBECTL_HSTS_MAX_AGE"           "$base" "app HSTS max-age not set (OPS-009)"
if grep -q "configuration-snippet" <<<"$base" && grep -q "Strict-Transport-Security" <<<"$base"; then
  fail "HSTS delivered via configuration-snippet — disabled by default in ingress-nginx >=1.9 (OPS-009)"
fi
need "kind: NetworkPolicy"             "$base" "default profile missing NetworkPolicy (default-on, U-086)"
base_np="$(awk '/kind: NetworkPolicy/,/^---/' <<<"$base")"
need "from:"                           "$base_np" "default profile NetworkPolicy has no ingress source selector (WIRE-002)"
need "ingress-nginx"                   "$base_np" "default profile NetworkPolicy does not restrict API ingress to the ingress controller (WIRE-002)"
grep -q "ALL" <<<"$base" || fail "capabilities drop ALL not present"
if helm template probectl "$CHART" \
  --set ingress.host=h.example.com --set ingress.tlsSecretName=probectl-tls \
  --set secrets.envelopeKey="$KEY" \
  --set database.url="postgres://probectl:s3cret-not-default@db:5432/probectl?sslmode=require" \
  --set-json 'networkPolicy.ingressFrom=[]' >/dev/null 2>&1; then
  fail "chart rendered with NetworkPolicy enabled and empty ingressFrom (WIRE-002)"
fi

# 3. Large profile: NetworkPolicy + PodDisruptionBudget + HPA all present.
large="$(render -f "$CHART/values-large.yaml")"
need "kind: NetworkPolicy"          "$large" "large profile missing NetworkPolicy"
need "kind: PodDisruptionBudget"    "$large" "large profile missing PodDisruptionBudget"
need "kind: HorizontalPodAutoscaler" "$large" "large profile missing HorizontalPodAutoscaler"

# 3a. STRICT profile (OPS-004): full default-deny — a NAMED ingress selector
#     and an explicit egress allow-list, with NO allow-all holes. Plus the
#     regulated-profile ops surfaces (OPS-005/009): ServiceMonitor + backups.
strict="$(render -f "$CHART/values-strict.yaml")"
need "kind: NetworkPolicy"          "$strict" "strict profile missing NetworkPolicy"
need "ingress-nginx"                "$strict" "strict profile: ingress selector hole not closed (HOLE 1)"
need "port: 5432"                   "$strict" "strict profile: datastore egress allow-list missing (HOLE 2)"
# The default profile's allow-all egress rule ("- {}") must NOT survive in strict.
strict_np="$(awk '/kind: NetworkPolicy/,/^---/' <<<"$strict")"
grep -qE '^[[:space:]]*-[[:space:]]*\{\}[[:space:]]*$' <<<"$strict_np" \
  && fail "strict profile still has an allow-all egress rule (a HOLE) — default-deny not achieved"
need "kind: ServiceMonitor"         "$strict" "strict profile missing ServiceMonitor (OPS-005)"
need "kind: CronJob"                "$strict" "strict profile missing backup CronJob (OPS-009)"

# 3b. /metrics + backup are chart-managed and gated. Default profile must
#     NOT ship the operator-CRD ServiceMonitor or the opt-in CronJobs.
grep -q "kind: ServiceMonitor" <<<"$base" && fail "ServiceMonitor must be OFF by default (Prometheus-Operator CRD gate)"
grep -q "kind: CronJob" <<<"$base" && fail "backup CronJobs must be OFF by default (backup.enabled)"
need "kind: CronJob" "$(render --set backup.enabled=true)" "backup.enabled=true must render the backup CronJobs (OPS-009)"
need "kind: ServiceMonitor" "$(render --set metrics.serviceMonitor.enabled=true)" "metrics.serviceMonitor.enabled=true must render the ServiceMonitor (OPS-005)"

# 4. Medium + multi-tenant profiles ship a PodDisruptionBudget (zero-downtime, S34).
for f in values-medium.yaml values-multitenant.yaml; do
  need "kind: PodDisruptionBudget" "$(render -f "$CHART/$f")" "$f missing PodDisruptionBudget"
done

# 5. Every profile lints clean — EVERY values-*.yaml in the chart, so a new
# profile can never ship un-linted by being forgotten here (the strict and
# multiregion profiles once were).
for f in values.yaml $(cd "$CHART" && ls values-*.yaml); do
  helm lint "$CHART" -f "$CHART/$f" \
    --set ingress.host=h.example.com --set ingress.tlsSecretName=probectl-tls \
    --set secrets.envelopeKey="$KEY" \
    --set database.url="postgres://probectl:s3cret-not-default@db:5432/probectl?sslmode=require" \
    >/dev/null || fail "$f failed helm lint"
done

echo "helm hardening gate: OK (default + every values-* profile)"

# ── Agent chart (U-016): the eBPF agent's privilege contract is EXPLICIT ────
AGENT="${AGENT_CHART:-deploy/helm/probectl-agent}"
AGENT_IMAGE_TAG="0.4.0@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
helm lint "$AGENT" --set tenantID=gate --set 'bus.brokers={kafka:9093}' --set-string image.tag="$AGENT_IMAGE_TAG" >/dev/null \
  || fail "agent chart does not lint"

arender() { helm template agent "$AGENT" --set tenantID=gate --set 'bus.brokers={kafka:9093}' --set-string image.tag="$AGENT_IMAGE_TAG" "$@"; }
agent="$(arender)"
need "kind: DaemonSet"                  "$agent" "agent: not a DaemonSet"
need "@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" "$agent" "agent: digest-pinned image did not render"
need 'drop: \["ALL"\]'                  "$agent" "agent: capabilities not dropped to ALL"
need '"BPF", "PERFMON"'                 "$agent" "agent: minimal capability pair not declared"
need "seccompProfile"                   "$agent" "agent: no seccomp profile"
# EBPF-003: the strict default-deny profile is the DEFAULT for this privileged
# agent — not RuntimeDefault — and the chart installs it onto the node itself.
need "type: Localhost"                  "$agent" "agent: seccomp not Localhost by default (EBPF-003)"
need "localhostProfile: probectl/seccomp.json" "$agent" "agent: strict seccomp profile path missing"
need "install-seccomp-profile"          "$agent" "agent: no initContainer installing the strict seccomp profile (EBPF-003)"
need "kind: ConfigMap"                  "$agent" "agent: bundled seccomp ConfigMap missing"
grep -q "type: RuntimeDefault" <<<"$agent" && fail "agent: RuntimeDefault in the DEFAULT profile — strict Localhost is the hardened default (EBPF-003)"
# The opt-out portable baseline still renders cleanly.
need "type: RuntimeDefault" "$(arender --set seccomp.type=RuntimeDefault)" "agent: RuntimeDefault opt-out broken"
need "readOnlyRootFilesystem: true"     "$agent" "agent: root filesystem not read-only"
need "allowPrivilegeEscalation: false"  "$agent" "agent: privilege escalation not disabled"
need "automountServiceAccountToken: false" "$agent" "agent: SA token automounted"
need "/sys/kernel/btf/vmlinux"          "$agent" "agent: BTF host mount missing"
need "limits:"                          "$agent" "agent: no resource limits"
# OPS-001: the DaemonSet ships real liveness + readiness probes.
need "livenessProbe:"                   "$agent" "agent: no liveness probe (OPS-001)"
need "readinessProbe:"                  "$agent" "agent: no readiness probe (OPS-001)"
need "path: /healthz"                   "$agent" "agent: liveness probe not wired to /healthz"
need "path: /readyz"                    "$agent" "agent: readiness probe not wired to /readyz"
grep -q "SYS_ADMIN" <<<"$agent" && fail "agent: SYS_ADMIN in the DEFAULT profile (legacy mode only)"
# EBPF-002: L7 capture must render the full runtime contract, and enabled
# capture without scope must fail at template time.
if helm template agent "$AGENT" --set tenantID=gate --set 'bus.brokers={kafka:9093}' \
     --set-string image.tag="$AGENT_IMAGE_TAG" \
     --set l7Capture.enabled=true \
     --set l7Capture.consentTenant=gate >/dev/null 2>&1; then
  fail "agent chart rendered L7 capture without l7Capture.scope (EBPF-002)"
fi
l7="$(arender --set l7Capture.enabled=true --set l7Capture.consentTenant=gate \
       --set-json 'l7Capture.scope=["exe:/usr/bin/nginx"]' \
       --set l7Capture.redaction=length --set l7Capture.kernelWindow=0)"
need "l7_capture_scope:"                "$l7" "agent: L7 scope not rendered (EBPF-002)"
need "exe:/usr/bin/nginx"               "$l7" "agent: L7 scoped workload not rendered (EBPF-002)"
need "l7_capture_redaction: \"length\"" "$l7" "agent: L7 redaction not rendered (EBPF-002)"
need "l7_capture_kernel_window: 0"      "$l7" "agent: L7 kernel window not rendered (EBPF-002)"

# EBPF-004: legacy SYS_ADMIN is fenced behind an explicit acknowledgement.
if helm template agent "$AGENT" --set tenantID=gate --set 'bus.brokers={kafka:9093}' \
     --set-string image.tag="$AGENT_IMAGE_TAG" --set capabilityMode=legacy >/dev/null 2>&1; then
  fail "agent chart rendered legacy SYS_ADMIN without legacyKernelRingBufferAck (EBPF-004)"
fi
legacy="$(arender --set capabilityMode=legacy --set legacyKernelRingBufferAck=i-confirm-runtime-ring-buffer-support)"
need "SYS_ADMIN" "$legacy" "agent: acknowledged legacy mode missing SYS_ADMIN"

# fail-closed rendering: no tenant, or plaintext kafka without the explicit
# dev override, must refuse (guardrail 1 / U-010).
if helm template agent "$AGENT" --set-string image.tag="$AGENT_IMAGE_TAG" >/dev/null 2>&1; then
  fail "agent chart rendered WITHOUT a tenantID"
fi
if helm template agent "$AGENT" --set tenantID=t --set 'bus.brokers={k:9093}' --set-string image.tag="0.4.0" >/dev/null 2>&1; then
  fail "agent chart rendered a privileged tag-only image without image.allowTagOnly=true (RED-003)"
fi
need "probectl-ebpf-agent:0.4.0" "$(arender --set image.allowTagOnly=true --set-string image.tag=0.4.0)" "agent: tag-only break-glass render failed"
if helm template agent "$AGENT" --set tenantID=t --set 'bus.brokers={k:9092}' \
     --set-string image.tag="$AGENT_IMAGE_TAG" --set bus.tls.enabled=false >/dev/null 2>&1; then
  fail "agent chart rendered plaintext kafka without bus.allowPlaintext"
fi

echo "helm hardening gate: OK (control plane + agent charts)"
