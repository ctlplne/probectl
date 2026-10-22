#!/usr/bin/env bash
# SPDX-License-Identifier: BUSL-1.1
#
# SUP-20: the probectl-agent chart must be shippable and installable.
#  (1) its appVersion tracks the probectl chart's (OPS-001 — a lagging chart
#      deploys an agent the control plane rejects);
#  (2) it installs on a cluster WITHOUT Kyverno when the admission policies are
#      disabled with an accepted-risk note — no Kyverno policy object
#      (ImageValidatingPolicy / ValidatingPolicy / ClusterPolicy) may then
#      render (else `kubectl apply` fails on missing CRDs);
#  (3) the release workflow publishes it alongside the probectl chart;
#  (5) RTO-12: the image-integrity policy is a policies.kyverno.io/v1
#      ImageValidatingPolicy (Kyverno 1.19 deprecates kyverno.io/v1
#      ClusterPolicy) that derives its matchImageReferences from
#      image.repository (a mirror is verified too, a registry-less repository is
#      refused), denies (validationActions [Deny]), fails closed, requires a
#      digest and a signature, and the install-order readiness gate is live
#      whenever the cluster serves policies.kyverno.io/v1; a Kyverno too old to
#      serve it is refused; the standalone deploy/admission manifest is the
#      chart's default spec; the capability-posture policy is a ValidatingPolicy
#      that audits. SELFTEST plants each defect in a copy of the chart and
#      requires the check to catch it.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HELM="${HELM:-helm}"
AGENT="$repo_root/deploy/helm/probectl-agent"
MAIN="$repo_root/deploy/helm/probectl"
DIGEST="sha256:0000000000000000000000000000000000000000000000000000000000000000"

KYVERNO_KINDS='^kind:[[:space:]]*(ClusterPolicy|ImageValidatingPolicy|ValidatingPolicy)$'

appversion() { grep -E '^appVersion:' "$1/Chart.yaml" | awk '{print $2}' | tr -d '"'; }

render_no_kyverno() {
  # The agent chart pins the privileged image as tag@sha256:<digest> (it has no
  # separate image.digest field); any valid digest form satisfies the schema.
  "$HELM" template agent "$AGENT" \
    --set-string image.tag="${av_main:-0.6.6}@${DIGEST}" \
    --set tenantID=00000000-0000-0000-0000-000000000001 --set agentID=ci \
    --set 'bus.brokers={bus.probectl.svc:9093}' \
    --set admission.imageIntegrity.enabled=false \
    --set-string admission.imageIntegrity.acceptedRisk=replaced-by-cluster-policy-controller \
    --set admission.capabilityPosture.enabled=false \
    "$@" 2>/dev/null
}

# RTO-12 render contract for the chart at $1. Prints the first violation and
# returns 1, so SELFTEST can assert each planted defect is caught.
IVP_API=policies.kyverno.io/v1/ImageValidatingPolicy
# doc_of KIND — the rendered document(s) of that kind, from stdin.
doc_of() {
  awk -v k="kind: $1" '/^---/{ if (keep) printf "%s", buf; buf=""; keep=0; next }
    { buf = buf $0 "\n" } $0 == k { keep=1 } END { if (keep) printf "%s", buf }'
}
# spec_of — from `spec:` to the end, comment lines dropped (stdin).
spec_of() { sed -n '/^spec:$/,$p' | grep -Ev '^[[:space:]]*#'; }
rto12_checks() {
  local chart="$1" out mirror ivp vp
  local base=(template agent "$chart" --set-string image.tag="0.6.6@${DIGEST}"
    --set tenantID=00000000-0000-0000-0000-000000000001 --set agentID=ci
    --set 'bus.brokers={bus.probectl.svc:9093}')
  out="$("$HELM" "${base[@]}" 2>&1)" || { echo "default render failed: $out"; return 1; }
  ivp="$(doc_of ImageValidatingPolicy <<<"$out")"
  [ -n "$ivp" ] || { echo "no ImageValidatingPolicy rendered"; return 1; }
  grep -qx 'apiVersion: policies.kyverno.io/v1' <<<"$ivp" || { echo "image-integrity policy is not policies.kyverno.io/v1"; return 1; }
  if grep -Eq '^kind: ClusterPolicy$' <<<"$out"; then echo "a deprecated kyverno.io/v1 ClusterPolicy is still rendered"; return 1; fi
  grep -Fqx -- '    - glob: "ghcr.io/ctlplne/probectl-ebpf-agent*"' <<<"$ivp" || { echo "default matchImageReferences not derived from image.repository"; return 1; }
  grep -E '^    - expression: ' <<<"$ivp" | grep -F "r'^ghcr\\\\.io/ctlplne/probectl-ebpf-agent.*\$'" | grep -Fq "'docker.io/' +" \
    || { echo "no normalized-reference match for the derived pattern (a bare Docker Hub path would go unverified)"; return 1; }
  [ "$(grep -A1 -x '  validationActions:' <<<"$ivp" | tail -1)" = '    - Deny' ] || { echo "image-integrity policy does not deny (validationActions [Deny])"; return 1; }
  grep -qx '  failurePolicy: Fail' <<<"$ivp" || { echo "image-integrity policy does not fail closed (failurePolicy: Fail)"; return 1; }
  grep -qx '    required: true' <<<"$ivp" && grep -qx '    verifyDigest: true' <<<"$ivp" \
    || { echo "signature (required) or digest (verifyDigest) not enforced"; return 1; }
  grep -A2 -x '  validations:' <<<"$ivp" | grep -F 'images.containers + images.initContainers + images.ephemeralContainers' | grep -Fq 'verifyImageSignatures(i, [attestors.probectl]) > 0' \
    || { echo "the validation does not verify every matching image's signature (initContainers included)"; return 1; }
  if grep -q 'validationFailureAction' <<<"$out"; then echo "deprecated validationFailureAction rendered"; return 1; fi
  grep -q 'probectl.dev/policy-sha256:' <<<"$ivp" || { echo "policy-sha256 readiness annotation missing"; return 1; }
  vp="$(doc_of ValidatingPolicy <<<"$out")"
  grep -qx 'apiVersion: policies.kyverno.io/v1' <<<"$vp" && [ "$(grep -A1 -x '  validationActions:' <<<"$vp" | tail -1)" = '    - Audit' ] \
    || { echo "capability-posture policy is not a policies.kyverno.io/v1 ValidatingPolicy that audits"; return 1; }
  # The standalone GitOps manifest must be the chart's default spec, exactly.
  [ "$(spec_of < "${STANDALONE:-$repo_root/deploy/admission/probectl-agent-image-integrity.kyverno.yaml}")" = "$(spec_of <<<"$ivp")" ] \
    || { echo "deploy/admission standalone policy drifted from the chart's default spec"; return 1; }
  mirror="$("$HELM" "${base[@]}" --set-string image.repository=registry.corp.example:5443/mirror/probectl-ebpf-agent 2>&1)" \
    || { echo "mirror render failed: $mirror"; return 1; }
  grep -Fq -- '- glob: "registry.corp.example:5443/mirror/probectl-ebpf-agent*"' <<<"$mirror" || { echo "a mirrored image.repository is not in matchImageReferences (mirror bypass)"; return 1; }
  if [ "$(grep 'policy-sha256' <<<"$out")" = "$(grep 'policy-sha256' <<<"$mirror")" ]; then echo "policy-sha256 does not change with the verified repository"; return 1; fi
  if "$HELM" "${base[@]}" --set-string image.repository=ctlplne/probectl-ebpf-agent >/dev/null 2>&1; then
    echo "a repository without a registry host rendered (the derived pattern would not match the reference Kyverno sees)"; return 1
  fi
  if "$HELM" "${base[@]}" --api-versions "$IVP_API" >/dev/null 2>&1; then
    echo "readiness gate inactive: rendered against a policies.kyverno.io/v1 cluster with no live Ready policy"; return 1
  fi
  if "$HELM" "${base[@]}" --api-versions kyverno.io/v1/ClusterPolicy >/dev/null 2>&1; then
    echo "rendered against a Kyverno that serves ClusterPolicy but not ImageValidatingPolicy (too old to enforce it)"; return 1
  fi
  "$HELM" "${base[@]}" --api-versions "$IVP_API" --set admission.imageIntegrity.readinessGate=external \
    --set-string admission.imageIntegrity.externalOrdering=argocd-sync-wave >/dev/null 2>&1 \
    || { echo "readinessGate=external with externalOrdering did not render"; return 1; }
  if "$HELM" "${base[@]}" --set admission.imageIntegrity.readinessGate=external >/dev/null 2>&1; then
    echo "readinessGate=external rendered without externalOrdering"; return 1
  fi
  if "$HELM" "${base[@]}" --set admission.imageIntegrity.validationFailureAction=Audit >/dev/null 2>&1; then
    echo "the renamed validationFailureAction key was silently accepted"; return 1
  fi
  if "$HELM" "${base[@]}" --set 'admission.imageIntegrity.imageReferences={x}' >/dev/null 2>&1; then
    echo "the removed imageReferences key was silently accepted"; return 1
  fi
  if "$HELM" "${base[@]}" --set admission.imageIntegrity.ignoreTlog=true >/dev/null 2>&1; then
    echo "ignoreTlog rendered for the keyless attestor"; return 1
  fi
  if "$HELM" "${base[@]}" --set-string admission.imageIntegrity.publicKey=not-a-pem >/dev/null 2>&1; then
    echo "a non-PEM publicKey rendered"; return 1
  fi
  out="$("$HELM" "${base[@]}" --set-string 'admission.imageIntegrity.publicKey=-----BEGIN PUBLIC KEY-----
placeholder
-----END PUBLIC KEY-----' --set admission.imageIntegrity.ignoreTlog=true 2>&1)" || { echo "publicKey render failed: $out"; return 1; }
  ivp="$(doc_of ImageValidatingPolicy <<<"$out")"
  grep -Fq 'data: "-----BEGIN PUBLIC KEY-----' <<<"$ivp" && grep -qx '          insecureIgnoreTlog: true' <<<"$ivp" \
    || { echo "publicKey attestor (with insecureIgnoreTlog) not rendered"; return 1; }
  if grep -q 'keyless:' <<<"$ivp"; then echo "publicKey did not replace the keyless attestor"; return 1; fi
  return 0
}

# plant <sed-expression> <file-under-templates> — a chart copy with one defect.
plant() {
  local dir; dir="$(mktemp -d)"
  cp -R "$AGENT" "$dir/chart"
  sed -i.bak -e "$1" "$dir/chart/templates/$2" && rm -f "$dir/chart/templates/$2.bak"
  if cmp -s "$AGENT/templates/$2" "$dir/chart/templates/$2"; then echo "SELFTEST broken: planting '$1' changed nothing"; exit 1; fi
  printf '%s' "$dir/chart"
}

if [ "${1:-}" = "SELFTEST" ]; then
  # RTO-12: the real chart passes, and each planted defect is caught.
  why="$(rto12_checks "$AGENT")" || { echo "SELFTEST broken: the real chart fails the RTO-12 checks: $why"; exit 1; }
  # One planted defect per line: <template><TAB><sed expression><TAB><label>.
  while IFS="$(printf '\t')" read -r file expr label; do
    [ -n "$file" ] || continue
    planted="$(plant "$expr" "$file")"
    if why="$(rto12_checks "$planted")"; then
      echo "SELFTEST broken: planted defect '$label' was NOT caught"; rm -rf "$(dirname "$planted")"; exit 1
    fi
    echo "  planted '$label' -> caught: $why"
    rm -rf "$(dirname "$planted")"
  done <<'PLANTS'
image-integrity-policy.yaml	s/(printf "%s\*" $repo)/"ghcr.io\/ctlplne\/probectl-ebpf-agent*"/	fixed matchImageReferences (the pre-RTO-12 mirror bypass)
image-integrity-policy.yaml	s/(\.Capabilities\.APIVersions\.Has "policies\.kyverno\.io\/v1\/ImageValidatingPolicy") -}}$/false -}}/	readiness gate removed (the pre-RTO-12 install order)
image-integrity-policy.yaml	s/(not (\.Capabilities\.APIVersions\.Has "policies\.kyverno\.io\/v1\/ImageValidatingPolicy"))/false/	a Kyverno too old for ImageValidatingPolicy accepted
image-integrity-policy.yaml	s/{{- if not (regexMatch /{{- if and false (regexMatch /	registry-host check removed
image-integrity-policy.yaml	s/^kind: ImageValidatingPolicy$/kind: ClusterPolicy/	deprecated ClusterPolicy kind
_helpers.tpl	s/{{ ternary "Deny" "Audit" (eq $policy.failureAction "Enforce") }}/Audit/	image-integrity downgraded to Audit
_helpers.tpl	s/^failurePolicy: Fail$/failurePolicy: Ignore/	failurePolicy Ignore
_helpers.tpl	s/^  verifyDigest: true$/  verifyDigest: false/	digest no longer required
_helpers.tpl	s/images.containers + images.initContainers + images.ephemeralContainers).all/images.containers).all/	initContainer images not verified
_helpers.tpl	s/^  - expression: {{ include "probectl-agent.imageIntegrityRefMatch" . | quote }}$/  - glob: "unused"/	normalized-reference match removed
capability-posture-policy.yaml	s/^kind: ValidatingPolicy$/kind: ClusterPolicy/	capability-posture back on the deprecated kind
image-integrity-policy.yaml	s/{{- if hasKey $policy "imageReferences" -}}/{{- if false -}}/	removed imageReferences key silently accepted
PLANTS

  # A standalone manifest that drifts from the chart's spec must be detected.
  drift="$(mktemp)"
  sed 's/images.containers + images.initContainers + images.ephemeralContainers).all/images.containers).all/' \
    "$repo_root/deploy/admission/probectl-agent-image-integrity.kyverno.yaml" > "$drift"
  if why="$(STANDALONE="$drift" rto12_checks "$AGENT")"; then echo "SELFTEST broken: a drifted standalone manifest was NOT caught"; rm -f "$drift"; exit 1; fi
  echo "  planted 'standalone manifest drifted from the chart' -> caught: $why"
  rm -f "$drift"
  # A rendered Kyverno policy while policies are disabled must be detected.
  for k in ClusterPolicy ImageValidatingPolicy ValidatingPolicy; do
    printf 'kind: %s\n' "$k" | grep -qE "$KYVERNO_KINDS" || { echo "SELFTEST broken: kind $k not matched"; exit 1; }
  done
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
# render NO Kyverno policy object, so the chart applies without Kyverno CRDs.
out="$(render_no_kyverno)"
if printf '%s' "$out" | grep -qE "$KYVERNO_KINDS" ; then
  echo "::error::agent chart still renders a Kyverno policy when admission policies are disabled — install fails without Kyverno (SUP-20)"; exit 1
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

# (5) RTO-12 image-integrity render contract.
why="$(rto12_checks "$AGENT")" || { echo "::error::agent chart image-integrity policy: $why (RTO-12)"; exit 1; }

echo "check_agent_chart OK (appVersion in sync; Kyverno-free install renders no Kyverno policy; release publishes the agent chart; image-integrity ImageValidatingPolicy derived, denying, fail-closed, ordering-gated; capability posture ValidatingPolicy audits) (SUP-20/RTO-12)"
