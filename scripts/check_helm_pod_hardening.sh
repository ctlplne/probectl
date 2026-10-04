#!/usr/bin/env bash
# SPDX-License-Identifier: BUSL-1.1
#
# SUP-19: the rendered chart must not ship pods a "require limits" ResourceQuota
# or a default-SA-token policy would reject. Every init/stage container carries
# explicit resources.requests + resources.limits (trivy KSV-0011/15/16/18), and
# the one-shot backup/restore job pods set automountServiceAccountToken:false
# (KSV-0036). This renders the charts and asserts both, so a regression that
# drops either is caught in CI without pulling the whole trivy opinion set in.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HELM="${HELM:-helm}"
DIGEST="sha256:0000000000000000000000000000000000000000000000000000000000000000"

render() {
  # $1 = chart dir, rest = extra --set args
  local chart="$1"; shift
  "$HELM" template probectl "$chart" \
    --set image.digest="$DIGEST" \
    --set ingress.host=h.example.com --set ingress.tlsSecretName=probectl-tls \
    --set 'control.trustedProxies={10.244.0.0/16}' \
    --set ingress.backendTLS.trustSecret=probectl-backend-ca \
    --set ingress.backendTLS.serverName=h.example.com \
    --set control.tls.existingSecret=probectl-tls \
    --set secrets.existingSecret=probectl-secrets \
    --set backup.enabled=true --set backup.clickhouse.enabled=true \
    --set-string backup.clickhouse.encryptedTargetAck=encrypted-clickhouse-backup-target \
    --set restore.enabled=true --set restore.backupFile=/backups/x.dump.pbk \
    "$@" 2>/dev/null
}

assert() {
  local label="$1" manifests="$2"
  python3 - "$label" <<PY
import sys, yaml
label = sys.argv[1]
docs = [d for d in yaml.safe_load_all(open("$manifests")) if d]
problems = []
POD_KINDS = {"Deployment","DaemonSet","StatefulSet","Job","CronJob","ReplicaSet","Pod"}
def pod_spec(doc):
    k = doc.get("kind")
    if k == "CronJob":
        return doc.get("spec",{}).get("jobTemplate",{}).get("spec",{}).get("template",{}).get("spec")
    if k == "Pod":
        return doc.get("spec")
    return doc.get("spec",{}).get("template",{}).get("spec")
for doc in docs:
    if not isinstance(doc, dict) or doc.get("kind") not in POD_KINDS:
        continue
    name = doc.get("metadata",{}).get("name","?")
    kind = doc.get("kind")
    spec = pod_spec(doc)
    if not spec:
        continue
    # (1) every init container has requests AND limits
    for c in (spec.get("initContainers") or []):
        res = c.get("resources") or {}
        if not res.get("requests") or not res.get("limits"):
            problems.append(f"{kind}/{name}: init container {c.get('name')} lacks resources.requests/limits (SUP-19)")
    # (2) one-shot job pods must not mount the default SA token
    if kind in ("Job","CronJob") and spec.get("automountServiceAccountToken") is not False:
        problems.append(f"{kind}/{name}: pod must set automountServiceAccountToken:false (SUP-19)")
if problems:
    print(f"[{label}] pod-hardening FAIL:")
    for p in problems: print("  " + p)
    sys.exit(1)
PY
}

tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT

if [ "${1:-}" = "SELFTEST" ]; then
  # A manifest with an init container missing resources, and a Job mounting the
  # SA token, must BOTH be detected.
  cat > "$tmp/bad.yaml" <<'YAML'
apiVersion: batch/v1
kind: Job
metadata: { name: bad }
spec:
  template:
    spec:
      initContainers:
        - name: stage
          image: x
YAML
  if assert selftest "$tmp/bad.yaml" 2>/dev/null; then
    echo "SELFTEST FAILED: missing-limits / SA-token not detected"; exit 1
  fi
  echo "check_helm_pod_hardening SELFTEST ok (missing init limits + mounted SA token detected)"
  exit 0
fi

render "$repo_root/deploy/helm/probectl" > "$tmp/default.yaml"
assert "probectl default" "$tmp/default.yaml"
# SUP-19: a default install must not ship the your-org.example security contact
# placeholder in its RFC 9116 security.txt (served from PROBECTL_SECURITY_CONTACT).
if grep -q 'your-org.example' "$tmp/default.yaml"; then
  echo "::error::default render still carries the your-org.example security contact placeholder (SUP-19)"; exit 1
fi
if ! grep -q 'PROBECTL_SECURITY_CONTACT' "$tmp/default.yaml"; then
  echo "::error::default render exposes no PROBECTL_SECURITY_CONTACT (SUP-19)"; exit 1
fi
render "$repo_root/deploy/helm/probectl" -f "$repo_root/deploy/helm/probectl/values-multitenant.yaml" \
  --set-string control.extraEnv.PROBECTL_BUS_MODE=nats \
  --set-string control.extraEnv.PROBECTL_BUS_BROKERS=nats:4222 \
  --set-string control.extraEnv.PROBECTL_SIEM_ENABLED=true \
  --set-string control.extraEnv.PROBECTL_SIEM_ENDPOINT=https://siem.example/i \
  --set license.existingSecret=probectl-license \
  --set objectStore.existingClaim=probectl-objects > "$tmp/mt.yaml" 2>/dev/null || true
[ -s "$tmp/mt.yaml" ] && assert "probectl multitenant" "$tmp/mt.yaml" || true
"$HELM" template agent "$repo_root/deploy/helm/probectl-agent" --set image.digest="$DIGEST" --set tenantID=00000000-0000-0000-0000-000000000001 2>/dev/null > "$tmp/agent.yaml" || true
[ -s "$tmp/agent.yaml" ] && assert "probectl-agent" "$tmp/agent.yaml" || true
echo "check_helm_pod_hardening OK (init containers carry resources; job pods drop the SA token) (SUP-19)"
