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
    --set secrets.envelopeKey="$KEY"
}

need() { grep -q -- "$1" <<<"$2" || fail "$3"; }

# 1. No default credentials: rendering without an envelope key (and no
#    existingSecret) must FAIL closed.
if helm template probectl "$CHART" \
  --set ingress.host=h.example.com --set ingress.tlsSecretName=probectl-tls >/dev/null 2>&1; then
  fail "chart rendered with no secrets.envelopeKey — that would be a default credential"
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
grep -q "ALL" <<<"$base" || fail "capabilities drop ALL not present"

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
npblock="$(awk '/kind: NetworkPolicy/,/^---/' <<<"$strict")"
grep -qE '^[[:space:]]*-[[:space:]]*\{\}[[:space:]]*$' <<<"$npblock" \
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
    --set secrets.envelopeKey="$KEY" >/dev/null || fail "$f failed helm lint"
done

echo "helm hardening gate: OK (default + every values-* profile)"

# ── Agent chart (U-016): the eBPF agent's privilege contract is EXPLICIT ────
AGENT="${AGENT_CHART:-deploy/helm/probectl-agent}"
helm lint "$AGENT" --set tenantID=gate --set 'bus.brokers={kafka:9093}' >/dev/null \
  || fail "agent chart does not lint"

arender() { helm template agent "$AGENT" --set tenantID=gate --set 'bus.brokers={kafka:9093}' "$@"; }
agent="$(arender)"
need "kind: DaemonSet"                  "$agent" "agent: not a DaemonSet"
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

# legacy kernels get exactly the documented fallback
need "SYS_ADMIN" "$(arender --set capabilityMode=legacy)" "agent: legacy mode missing SYS_ADMIN"

# fail-closed rendering: no tenant, or plaintext kafka without the explicit
# dev override, must refuse (guardrail 1 / U-010).
if helm template agent "$AGENT" >/dev/null 2>&1; then
  fail "agent chart rendered WITHOUT a tenantID"
fi
if helm template agent "$AGENT" --set tenantID=t --set 'bus.brokers={k:9092}' \
     --set bus.tls.enabled=false >/dev/null 2>&1; then
  fail "agent chart rendered plaintext kafka without bus.allowPlaintext"
fi

echo "helm hardening gate: OK (control plane + agent charts)"
