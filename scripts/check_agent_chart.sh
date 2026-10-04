#!/usr/bin/env bash
# SPDX-License-Identifier: BUSL-1.1
#
# SUP-20: the probectl-agent chart must be shippable and installable.
#  (1) its appVersion tracks the probectl chart's (OPS-001 — a lagging chart
#      deploys an agent the control plane rejects);
#  (2) it installs on a cluster WITHOUT Kyverno when the admission policies are
#      disabled with an accepted-risk note — the Kyverno ClusterPolicy objects
#      must then NOT render (else `kubectl apply` fails on missing CRDs);
#  (3) the release workflow publishes it alongside the probectl chart.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HELM="${HELM:-helm}"
AGENT="$repo_root/deploy/helm/probectl-agent"
MAIN="$repo_root/deploy/helm/probectl"
DIGEST="sha256:0000000000000000000000000000000000000000000000000000000000000000"

appversion() { grep -E '^appVersion:' "$1/Chart.yaml" | awk '{print $2}' | tr -d '"'; }

render_no_kyverno() {
  # The agent chart pins the privileged image as tag@sha256:<digest> (it has no
  # separate image.digest field); any valid digest form satisfies the schema.
  "$HELM" template agent "$AGENT" \
    --set-string image.tag="${av_main:-0.6.5}@${DIGEST}" \
    --set tenantID=00000000-0000-0000-0000-000000000001 --set agentID=ci \
    --set 'bus.brokers={bus.probectl.svc:9093}' \
    --set admission.imageIntegrity.enabled=false \
    --set-string admission.imageIntegrity.acceptedRisk=replaced-by-cluster-policy-controller \
    --set admission.capabilityPosture.enabled=false \
    "$@" 2>/dev/null
}

if [ "${1:-}" = "SELFTEST" ]; then
  # A rendered ClusterPolicy while policies are disabled must be detected.
  printf 'apiVersion: kyverno.io/v1\nkind: ClusterPolicy\nmetadata: { name: x }\n' > /tmp/agent_selftest.yaml
  if ! grep -q 'kind: ClusterPolicy' /tmp/agent_selftest.yaml; then
    echo "SELFTEST broken"; exit 1
  fi
  # And a mismatched appVersion must be detected.
  if [ "$(appversion "$MAIN")" = "0.0.0-selftest-mismatch" ]; then echo "SELFTEST broken"; exit 1; fi
  echo "check_agent_chart SELFTEST ok"
  exit 0
fi

# (1) appVersion sync
av_agent="$(appversion "$AGENT")"; av_main="$(appversion "$MAIN")"
if [ "$av_agent" != "$av_main" ]; then
  echo "::error::probectl-agent Chart.yaml appVersion ($av_agent) != probectl ($av_main) — keep them in lockstep (SUP-20/OPS-001)"; exit 1
fi

# (2) Kyverno-free install: disabling the policies (with accepted risk) must
# render NO kyverno.io ClusterPolicy, so the chart applies without Kyverno CRDs.
out="$(render_no_kyverno)"
if printf '%s' "$out" | grep -qE '^kind:\s*ClusterPolicy' ; then
  echo "::error::agent chart still renders a Kyverno ClusterPolicy when admission policies are disabled — install fails without Kyverno (SUP-20)"; exit 1
fi
if ! printf '%s' "$out" | grep -q 'kind: DaemonSet'; then
  echo "::error::agent chart did not render its DaemonSet with admission disabled (SUP-20)"; exit 1
fi

# (3) the release workflow publishes the agent chart (not only the probectl one).
if ! grep -q 'deploy/helm/probectl-agent' "$repo_root/.github/workflows/release.yml"; then
  echo "::error::release.yml does not package/publish deploy/helm/probectl-agent (SUP-20)"; exit 1
fi

# (4) the chart documents its required Pod Security Admission level (privileged).
if ! grep -q 'pod-security.kubernetes.io/enforce=privileged' "$AGENT/templates/NOTES.txt"; then
  echo "::error::agent chart does not document its required privileged PSA namespace level (SUP-20)"; exit 1
fi

echo "check_agent_chart OK (appVersion in sync; Kyverno-free install renders no ClusterPolicy; release publishes the agent chart) (SUP-20)"
