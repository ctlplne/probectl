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
need "Strict-Transport-Security"       "$base" "HSTS not set (HTTPS-by-default)"
grep -q "ALL" <<<"$base" || fail "capabilities drop ALL not present"

# 3. Large profile: NetworkPolicy + PodDisruptionBudget + HPA all present.
large="$(render -f "$CHART/values-large.yaml")"
need "kind: NetworkPolicy"          "$large" "large profile missing NetworkPolicy"
need "kind: PodDisruptionBudget"    "$large" "large profile missing PodDisruptionBudget"
need "kind: HorizontalPodAutoscaler" "$large" "large profile missing HorizontalPodAutoscaler"

# 4. Medium + multi-tenant profiles ship a PodDisruptionBudget (zero-downtime, S34).
for f in values-medium.yaml values-multitenant.yaml; do
  need "kind: PodDisruptionBudget" "$(render -f "$CHART/$f")" "$f missing PodDisruptionBudget"
done

# 5. Every profile lints clean.
for f in values.yaml values-small.yaml values-medium.yaml values-large.yaml values-multitenant.yaml; do
  helm lint "$CHART" -f "$CHART/$f" \
    --set ingress.host=h.example.com --set ingress.tlsSecretName=probectl-tls \
    --set secrets.envelopeKey="$KEY" >/dev/null || fail "$f failed helm lint"
done

echo "helm hardening gate: OK (default + small/medium/large/multitenant)"

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
need "readOnlyRootFilesystem: true"     "$agent" "agent: root filesystem not read-only"
need "allowPrivilegeEscalation: false"  "$agent" "agent: privilege escalation not disabled"
need "automountServiceAccountToken: false" "$agent" "agent: SA token automounted"
need "/sys/kernel/btf/vmlinux"          "$agent" "agent: BTF host mount missing"
need "limits:"                          "$agent" "agent: no resource limits"
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
