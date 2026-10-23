#!/usr/bin/env bash
# SPDX-License-Identifier: BUSL-1.1
#
# Use of this source code is governed by the Business Source License 1.1
# in the LICENSE file at the root of this repository; on its Change Date
# each version converts to the Mozilla Public License 2.0.

# kyverno_admission_smoke.sh (RTO-12) — prove on a REAL Kubernetes cluster that
# the probectl-agent chart's image-integrity ImageValidatingPolicy
# (policies.kyverno.io/v1; Kyverno 1.19 deprecates the kyverno.io/v1
# ClusterPolicy the chart used to render) admits only a digest-pinned,
# correctly signed agent image, and that the chart refuses to install its
# DaemonSet before that policy is live and Ready.
#
#   scripts/kyverno_admission_smoke.sh            # local or CI; needs docker, kind, kubectl, helm, openssl
#   KYVERNO_SMOKE_KEEP=1 scripts/kyverno_admission_smoke.sh   # keep the cluster for debugging
#
# What it builds (everything throwaway, generated at run time, never committed):
#   - a kind cluster on its own docker network, node image pinned by digest;
#   - a TLS registry:2 on that network (a run-time CA; Kyverno trusts it);
#   - stand-in agent images made with crane, signed with a cosign key pair
#     generated for this run (no transparency-log upload: the run is offline
#     from Sigstore's point of view, so the policy is rendered with
#     publicKey + ignoreTlog — the air-gapped-mirror configuration);
#   - one RUNNABLE agent image: the real probectl-ebpf-agent binary built in a
#     pinned golang container, signed the same way (the chart runs it for its
#     seccomp installer initContainer and its admission-check CronJob);
#   - Kyverno from a pinned chart (version + sha256) with digest-pinned images.
#
# Legs (each asserts the admission result AND the policy's message):
#   P0  Kyverno accepts the shipped policies          -> no deprecation warning
#   G0  helm install before the policy exists         -> chart refuses, nothing created
#   A1  two-step install, signed digest               -> DaemonSet + pod admitted
#   H1  live policy status                            -> the fields the Argo CD health check reads
#   D1  upgrade to an unsigned digest                 -> denied (no signature)
#   D2  upgrade to a digest signed by another key     -> denied (signature mismatch)
#   D3  pod with a mutable tag of the SIGNED image     -> denied (missing digest)
#   D4  pod with an unsigned digest, outside the chart -> denied (policy is cluster-wide)
#   G1  upgrade to a mirror repository, policy stale  -> chart refuses (policy-sha256 differs)
#   D5  mirror repository, unsigned digest            -> denied (derived imageReferences)
#   A2  mirror repository, signed digest              -> admitted
#   S1  seccomp installer, runnable signed agent image -> initContainer exit 0, profile on the node
#   S2  unsigned image as the installer initContainer  -> denied (initContainers are verified)
#   W0  admission-check CronJob, Kyverno verifying     -> Job Complete (observe-only check passes)
#   D6  Kyverno not answering, signed digest          -> denied (failurePolicy Fail)
#   W1  Kyverno scaled to zero (webhooks gone)        -> admission-check Job FAILED, names the webhook
#   G2  Kyverno scaled to zero (webhooks gone)        -> chart refuses (policy alone is not enough)
#
# Not proven here: admitting a REAL keyless-signed release digest from GHCR —
# that needs the release packages to be anonymously readable (GHCR public).
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
AGENT_CHART="$repo_root/deploy/helm/probectl-agent"
HELM="${HELM:-helm}"
KIND="${KIND:-kind}"
KUBECTL="${KUBECTL:-kubectl}"
CLUSTER="${KYVERNO_SMOKE_CLUSTER:-probectl-qa-beta-kyverno}"
KEEP="${KYVERNO_SMOKE_KEEP:-0}"
NET="$CLUSTER-net"
REG="$CLUSTER-registry"
REGHOST="$REG:5000"
NS="probectl-qa-beta-agent"
REL="probectl-agent"
POLICY="probectl-agent-image-integrity"
AGENT_PODS="app.kubernetes.io/name=probectl-agent,app.kubernetes.io/instance=$REL"
CHECK_CRONJOB="$REL-probectl-agent-admission-check"
# The ImageValidatingPolicy's denial for an unsigned / other-key image (it
# names the image; Kyverno does not tell the two apart in its answer).
NOTSIGNED="image signature not verified by the configured attestor"

# ── pins (bump together; every image by digest, every download by sha256) ──
KIND_NODE_IMAGE="kindest/node:v1.37.0@sha256:a1ed56cfb0e7b93589bdf97c8cd566405a265939e3620fc4f5de89adff580ae5" # kind v0.33.0 release notes
KYVERNO_CHART_URL="https://kyverno.github.io/kyverno/kyverno-3.9.1.tgz"                                           # Kyverno v1.19.1
KYVERNO_CHART_SHA256="7b7fe51a431b5b133b0ce7eb9dcb222b6a37fb967c163223cf480054ad14d752"                            # = index.yaml digest
KYVERNO_TAG="v1.19.1@sha256:b31d8511ae5fd6010e2a01ea72ebae08eb82fa51d91af14a1d9fe989949b4edb"
KYVERNOPRE_TAG="v1.19.1@sha256:c25c47461f06f2845a48c319ae86fbbc1730a7b9ed5b701889c9dc1f9ee94b09"
# registry:2, cosign v2.5.3, crane v0.22.1 and golang 1.26.10 (the toolchain
# go.mod pins; same digest as deploy/docker/Dockerfile.ebpf) are pinned by digest as literals
# in their `docker run` lines below (the supply-pins gate reads those lines).

for tool in docker "$KIND" "$KUBECTL" "$HELM" openssl; do
  command -v "$tool" >/dev/null 2>&1 || { echo "kyverno smoke: $tool is required" >&2; exit 2; }
done

work="$(mktemp -d "${TMPDIR:-/tmp}/probectl-qa-beta-kyverno.XXXXXX")"
KUBECONFIG="$work/kubeconfig"; export KUBECONFIG

cleanup() {
  local rc=$?
  if [ "$KEEP" = 1 ]; then
    echo "kyverno smoke: KEEP=1 — cluster $CLUSTER, registry $REG and $work left in place" >&2
    exit "$rc"
  fi
  "$KIND" delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true
  docker rm -f "$REG" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
  rm -rf "$work"
  exit "$rc"
}
trap cleanup EXIT

pass=0
ok() { pass=$((pass + 1)); printf 'ok   %-4s %s\n' "$1" "$2"; }
die() { printf 'FAIL %s\n' "$*" >&2; exit 1; }
# want_denied LEG WHAT LOGFILE PATTERN... — the command already failed; its
# output must carry the policy name and every PATTERN (the denial's reason).
want_denied() {
  local leg="$1" what="$2" log="$3"; shift 3
  grep -q "Policy $POLICY failed: " "$log" || { cat "$log" >&2; die "$leg $what: refused, but not by $POLICY"; }
  local p
  for p in "$@"; do
    grep -Eq "$p" "$log" || { cat "$log" >&2; die "$leg $what: denial does not say /$p/"; }
  done
  ok "$leg" "$what -> DENIED: $(grep -o "Policy $POLICY failed: .*" "$log" | head -1 | cut -c1-240)"
}

# ── 1. cluster + TLS registry ──────────────────────────────────────────────
cd "$work"
"$KIND" delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true
docker rm -f "$REG" >/dev/null 2>&1 || true
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 \
  -subj "/CN=$CLUSTER-ca" -keyout ca.key -out ca.crt 2>/dev/null
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj "/CN=$REG" \
  -keyout reg.key -out reg.csr 2>/dev/null
printf 'subjectAltName=DNS:%s\nextendedKeyUsage=serverAuth\n' "$REG" > reg.ext
openssl x509 -req -in reg.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 1 -out reg.crt -extfile reg.ext 2>/dev/null
chmod 0644 reg.key
# Kyverno's CA bundle REPLACES its system bundle, so keep the public roots in it.
sysbundle=""
for f in /etc/ssl/certs/ca-certificates.crt /etc/pki/tls/certs/ca-bundle.crt /etc/ssl/cert.pem; do
  [ -s "$f" ] && { sysbundle="$f"; break; }
done
[ -n "$sysbundle" ] || die "no system CA bundle found"
cat "$sysbundle" ca.crt > bundle.crt

echo "== kind cluster $CLUSTER ($KIND_NODE_IMAGE) on network $NET"
KIND_EXPERIMENTAL_DOCKER_NETWORK="$NET" "$KIND" create cluster --name "$CLUSTER" \
  --image "$KIND_NODE_IMAGE" --kubeconfig "$KUBECONFIG" --wait 120s >/dev/null
docker run -d --name "$REG" --network "$NET" -v "$work:/certs:ro" \
  -e REGISTRY_HTTP_ADDR=0.0.0.0:5000 \
  -e REGISTRY_HTTP_TLS_CERTIFICATE=/certs/reg.crt -e REGISTRY_HTTP_TLS_KEY=/certs/reg.key \
  registry:2@sha256:a3d8aaa63ed8681a604f1dea0aa03f100d5895b6a58ace528858a7b332415373 >/dev/null

# crane/cosign run in pinned containers on the cluster's network.
mkdir -p home
crane() { docker run --rm --network "$NET" -v "$work:$work" -w "$work" --user "$(id -u):$(id -g)" \
  -e SSL_CERT_FILE="$work/bundle.crt" -e HOME="$work/home" \
  gcr.io/go-containerregistry/crane:v0.22.1@sha256:1f968817b95790bed063f71175aa6b8ff879fa17064020415f3e18bb6e6a36e1 "$@"; }
cosign() { docker run --rm --network "$NET" -v "$work:$work" -w "$work" --user "$(id -u):$(id -g)" \
  -e SSL_CERT_FILE="$work/bundle.crt" -e HOME="$work/home" -e COSIGN_PASSWORD= \
  ghcr.io/sigstore/cosign/cosign:v2.5.3@sha256:f1946d0f30fc8e3777b02f2201e02efdba9fe38f4918162f937052fac98e083f "$@"; }

# ── 2. stand-in images, signed with run-time keys ──────────────────────────
echo "== stand-in images in $REGHOST, signed with run-time cosign keys"
cosign generate-key-pair --output-key-prefix "$work/trusted" >/dev/null 2>&1
cosign generate-key-pair --output-key-prefix "$work/other" >/dev/null 2>&1
grep -q 'BEGIN PUBLIC KEY' trusted.pub || die "cosign did not write a public key"
for _ in $(seq 1 30); do crane catalog "$REGHOST" >/dev/null 2>&1 && break; sleep 1; done
mkimage() { # repo tag content -> digest-pinned ref on stdout
  mkdir -p "layer-$2"; printf 'probectl-qa-beta kyverno smoke: %s\n' "$3" > "layer-$2/README"
  tar -C "layer-$2" -cf "layer-$2.tar" README
  crane append -f "$work/layer-$2.tar" -t "$REGHOST/$1:$2" >/dev/null 2>&1
  printf '%s:%s@%s' "$REGHOST/$1" "$2" "$(crane digest "$REGHOST/$1:$2")"
}
UP="ctlplne/probectl-ebpf-agent"; MIRROR="mirror/probectl-ebpf-agent"
signed="$(mkimage "$UP" smoke-signed signed)"
unsigned="$(mkimage "$UP" smoke-unsigned unsigned)"
otherkey="$(mkimage "$UP" smoke-otherkey other-key)"
m_unsigned="$(mkimage "$MIRROR" smoke-unsigned mirror-unsigned)"
m_signed="$(mkimage "$MIRROR" smoke-signed mirror-signed)"
# cosign signs repo@digest: drop the tag, keep the registry host and port.
sign_ref() { local ref="$2" repo digest; repo="${ref%@*}"; repo="${repo%:*}"; digest="${ref#*@}"
  cosign sign --yes --key "$work/$1.key" --tlog-upload=false "$repo@$digest" >/dev/null 2>&1 || die "cosign sign $ref"; }
sign_ref trusted "$signed"
sign_ref other "$otherkey"
sign_ref trusted "$m_signed"
tagof() { local r="${1#"$REGHOST"/}"; printf '%s' "${r#*:}"; }   # "<tag>@sha256:<d>"

# A RUNNABLE agent image for the legs that execute the chart's own use of the
# agent binary (the admission-check CronJob): the real probectl-ebpf-agent,
# default build (no eBPF objects; nothing here loads a program), static, on an
# empty base, in the mirror repository, signed with the trusted key.
arch="$(docker exec "$CLUSTER-control-plane" uname -m)"
case "$arch" in x86_64) arch=amd64 ;; aarch64 | arm64) arch=arm64 ;; *) die "unsupported node arch $arch" ;; esac
mkdir -p agentroot/usr/local/bin gocache gomod
docker run --rm -v "$repo_root:/src:ro" -v "$work:$work" -w /src --user "$(id -u):$(id -g)" \
  -e HOME="$work/home" -e GOCACHE="$work/gocache" -e GOMODCACHE="$work/gomod" -e GOWORK=off -e GOTOOLCHAIN=local \
  -e CGO_ENABLED=0 -e GOOS=linux -e GOARCH="$arch" -e GOFLAGS=-buildvcs=false \
  golang:1.26.10-bookworm@sha256:632dff7351799a5a9954a48dc06670ade72ee44e8c351cdc0e5a57af2fea21af \
  go build -trimpath -o "$work/agentroot/usr/local/bin/app" ./cmd/probectl-ebpf-agent > build.log 2>&1 \
  || { cat build.log >&2; die "build the probectl-ebpf-agent binary"; }
tar -C agentroot -cf agent.tar usr
crane append --oci-empty-base -f "$work/agent.tar" -t "$REGHOST/$MIRROR:smoke-agent-layer" >/dev/null 2>&1 || die "crane append agent"
crane mutate --set-platform "linux/$arch" --entrypoint /usr/local/bin/app -t "$REGHOST/$MIRROR:smoke-agent" \
  "$REGHOST/$MIRROR:smoke-agent-layer" >/dev/null 2>&1 || die "crane mutate agent"
m_agent="$REGHOST/$MIRROR:smoke-agent@$(crane digest "$REGHOST/$MIRROR:smoke-agent")"
sign_ref trusted "$m_agent"

# ── 3. Kyverno (pinned chart, digest-pinned images, trusts the run-time CA) ──
echo "== Kyverno $KYVERNO_TAG (chart sha256-verified)"
# The bundle rides as a node file: inline chart data would push the Helm release
# Secret past its 1 MiB limit. Kyverno mounts it over its system bundle.
docker exec "$CLUSTER-control-plane" mkdir -p /etc/probectl-qa-beta
docker cp "$work/bundle.crt" "$CLUSTER-control-plane:/etc/probectl-qa-beta/ca-bundle.crt" >/dev/null
curl -fsSL -o kyverno.tgz "$KYVERNO_CHART_URL"
got="$(openssl dgst -sha256 -r kyverno.tgz | cut -d' ' -f1)"
[ "$got" = "$KYVERNO_CHART_SHA256" ] || die "Kyverno chart digest $got != pinned $KYVERNO_CHART_SHA256"
"$HELM" install kyverno "$work/kyverno.tgz" -n kyverno --create-namespace --wait --timeout 10m \
  --set admissionController.replicas=1 \
  --set backgroundController.enabled=false --set cleanupController.enabled=false \
  --set reportsController.enabled=false \
  --set webhooksCleanup.enabled=false --set crds.migration.enabled=false \
  --set-string admissionController.container.image.tag="$KYVERNO_TAG" \
  --set-string admissionController.initContainer.image.tag="$KYVERNOPRE_TAG" \
  --set-json 'global.caCertificates.volume={"hostPath":{"path":"/etc/probectl-qa-beta/ca-bundle.crt","type":"File"}}' >/dev/null
"$KUBECTL" -n kyverno rollout status deploy/kyverno-admission-controller --timeout=5m >/dev/null
# A Ready rollout is not yet a reachable webhook: the Service endpoint and the
# webhook registration lag the pod (CI run 39794445141 saw "connection
# refused" on the policy webhook right after rollout). Wait until a server-side
# dry run of the shipped policy reaches Kyverno; retry ONLY on webhook
# connectivity errors, so a real rejection still fails P0 below.
webhook_ready=0
for _ in $(seq 1 60); do
  if "$KUBECTL" apply --dry-run=server -f "$repo_root/deploy/admission/probectl-agent-image-integrity.kyverno.yaml" >wh.log 2>&1; then
    webhook_ready=1
    break
  fi
  grep -qE 'failed calling webhook|connection refused|no endpoints available|context deadline exceeded' wh.log || break
  sleep 2
done
[ "$webhook_ready" -eq 1 ] || { cat wh.log >&2; die "Kyverno's policy webhook never became reachable (or rejected the policy)"; }

"$KUBECTL" create namespace "$NS" >/dev/null
"$KUBECTL" label namespace "$NS" pod-security.kubernetes.io/enforce=privileged \
  pod-security.kubernetes.io/enforce-version=latest >/dev/null
"$KUBECTL" create namespace probectl-qa-beta-other >/dev/null

# The chart values a mirror/air-gapped install uses: its registry, its key.
cat > values.yaml <<EOF
tenantID: probectl-qa-beta-kyverno
agentID: probectl-qa-beta-kyverno
bus:
  brokers: ["kafka.probectl-qa-beta.invalid:9093"]
# The stand-in images are not runnable; the seccomp installer (which runs the
# agent image itself) is switched on for the RUNNABLE agent image only (S1).
seccomp:
  type: RuntimeDefault
  installProfile: false
admission:
  imageIntegrity:
    ignoreTlog: true
EOF
chartargs() { # repo tag
  printf '%s\n' -n "$NS" -f "$work/values.yaml" --set-file "admission.imageIntegrity.publicKey=$work/trusted.pub" \
    --set-string "image.repository=$REGHOST/$1" --set-string "image.tag=$2"
}
run_helm() { # verb repo tag [extra helm args...]  (bash 3.2: no mapfile)
  local verb="$1" repo="$2" tag="$3" args=() a
  shift 3
  while IFS= read -r a; do args+=("$a"); done < <(chartargs "$repo" "$tag")
  "$HELM" "$verb" "$REL" "$AGENT_CHART" "${args[@]}" "$@"
}
run_template() { # repo tag -> the release's two policies, as rendered
  local args=() a
  while IFS= read -r a; do args+=("$a"); done < <(chartargs "$1" "$2")
  "$HELM" template "$REL" "$AGENT_CHART" "${args[@]}" \
    --show-only templates/image-integrity-policy.yaml --show-only templates/capability-posture-policy.yaml
}
# Step 1 of the documented install: apply this release's policy, wait Ready.
# Server-side apply as field manager "helm", so Helm 4's own server-side apply
# owns the fields it then adopts (another manager would conflict on
# .spec.rules, which Kyverno defaults); Helm 3 patches it in place either way.
# (a re-applied policy with changed matchImageReferences needs no new webhook
# rules, and the legs below prove the updated rules are what admission
# enforces.)
apply_policy() { # repo tag
  local args=() a
  while IFS= read -r a; do args+=("$a"); done < <(chartargs "$1" "$2")
  "$HELM" template "$REL" "$AGENT_CHART" "${args[@]}" --show-only templates/image-integrity-policy.yaml \
    | "$KUBECTL" apply --server-side --force-conflicts --field-manager=helm -f - >/dev/null
  "$KUBECTL" wait --for=jsonpath='{.status.conditionStatus.ready}'=true "imagevalidatingpolicy/$POLICY" --timeout=120s >/dev/null \
    || { "$KUBECTL" get imagevalidatingpolicy "$POLICY" -o yaml >&2; die "policy $POLICY never became Ready"; }
}
pod_yaml() { # name namespace image
  cat <<EOF
apiVersion: v1
kind: Pod
metadata: {name: $1, namespace: $2}
spec:
  containers:
    - name: agent
      image: $3
EOF
}

# ── 4. the legs ────────────────────────────────────────────────────────────
echo "== legs"
# P0: Kyverno ACCEPTS the shipped policies (server-side dry run through its
# policy webhook) with no deprecation warning — the kyverno.io/v1 ClusterPolicy
# warning is gone with the kind.
{ cat "$repo_root/deploy/admission/probectl-agent-image-integrity.kyverno.yaml"; echo "---"
  run_template "$UP" "$(tagof "$signed")"; } | "$KUBECTL" apply --dry-run=server -f - > p0.log 2>&1 \
  || { cat p0.log >&2; die "P0 Kyverno rejected a shipped policy"; }
if grep -Eqi 'deprecat|validationFailureAction' p0.log; then cat p0.log >&2; die "P0 Kyverno warned about a deprecated kind or field"; fi
[ "$(grep -c '^imagevalidatingpolicy.policies.kyverno.io/.* created (server dry run)' p0.log)" -eq 2 ] \
  && [ "$(grep -c '^validatingpolicy.policies.kyverno.io/.* created (server dry run)' p0.log)" -eq 1 ] \
  || { cat p0.log >&2; die "P0 expected 2 ImageValidatingPolicies + 1 ValidatingPolicy accepted"; }
ok P0 "standalone + chart policies (2 ImageValidatingPolicy, 1 ValidatingPolicy) -> ACCEPTED by Kyverno, no deprecation warning"
if run_helm install "$UP" "$(tagof "$signed")" > g0.log 2>&1; then
  cat g0.log >&2; die "G0 helm install succeeded with no image-integrity policy in the cluster"
fi
grep -q "is not in the cluster, so the agent's first pods would be admitted unverified" g0.log || { cat g0.log >&2; die "G0: refused for the wrong reason"; }
"$KUBECTL" -n "$NS" get daemonset -o name | grep -q . && die "G0: a DaemonSet was created despite the refusal"
ok G0 "install before the policy -> REFUSED by the chart, no DaemonSet: $(grep -o 'image-integrity ImageValidatingPolicy.*unverified' g0.log | head -1)"

apply_policy "$UP" "$(tagof "$signed")"
run_helm install "$UP" "$(tagof "$signed")" > a1.log 2>&1 || { cat a1.log >&2; die "A1 signed install was refused"; }
for _ in $(seq 1 60); do
  img="$("$KUBECTL" -n "$NS" get pods -l "$AGENT_PODS" -o jsonpath='{.items[0].spec.containers[?(@.name=="agent")].image}' 2>/dev/null || true)"
  [ -n "$img" ] && break; sleep 1
done
[ "$img" = "$signed" ] || die "A1: no agent pod admitted with $signed (got '$img')"
owner="$("$KUBECTL" get imagevalidatingpolicy "$POLICY" -o jsonpath='{.metadata.annotations.meta\.helm\.sh/release-name}')"
[ "$owner" = "$REL" ] || die "A1: the release did not adopt the step-1 policy"
ok A1 "two-step install, signed digest -> ADMITTED: pod runs $signed"

# H1: the live policy's status carries exactly what the shipped Argo CD health
# check (deploy/gitops/argocd/argocd-cm-kyverno-health.yaml) reads: it is
# Healthy only for conditionStatus.ready=true AND WebhookConfigured=True.
"$KUBECTL" get imagevalidatingpolicy "$POLICY" -o yaml > live-ivpol.yaml
h1="$("$KUBECTL" get imagevalidatingpolicy "$POLICY" -o jsonpath='{.status.conditionStatus.ready}{" "}{.status.conditionStatus.conditions[?(@.type=="WebhookConfigured")].status}')"
[ "$h1" = "true True" ] || { cat live-ivpol.yaml >&2; die "H1: live status is '$h1', not the 'ready WebhookConfigured' pair the Argo CD health check reads"; }
grep -Fq 'if cs.ready == true and webhookConfigured then' "$repo_root/deploy/gitops/argocd/argocd-cm-kyverno-health.yaml" \
  || die "H1: the shipped Argo CD health check no longer requires both"
ok H1 "live ImageValidatingPolicy status: conditionStatus.ready=true, WebhookConfigured=True -> what the Argo CD health check requires"

if run_helm upgrade "$UP" "$(tagof "$unsigned")" > d1.log 2>&1; then cat d1.log >&2; die "D1 unsigned digest admitted"; fi
want_denied D1 "upgrade to an unsigned digest" d1.log "$NOTSIGNED" "${unsigned#*@}"
[ "$("$KUBECTL" -n "$NS" get ds -l "app.kubernetes.io/instance=$REL" -o jsonpath='{.items[0].spec.template.spec.containers[0].image}')" = "$signed" ] \
  || die "D1: the DaemonSet template changed despite the denial"

if run_helm upgrade "$UP" "$(tagof "$otherkey")" > d2.log 2>&1; then cat d2.log >&2; die "D2 other-key digest admitted"; fi
want_denied D2 "upgrade to a digest signed by another key" d2.log "$NOTSIGNED" "${otherkey#*@}"

tag_only="${signed%@*}"
if pod_yaml d3 probectl-qa-beta-other "$tag_only" | "$KUBECTL" apply -f - > d3.log 2>&1; then cat d3.log >&2; die "D3 mutable tag admitted"; fi
want_denied D3 "pod with a mutable tag of the signed image" d3.log 'does not have a digest'

if pod_yaml d4 probectl-qa-beta-other "$unsigned" | "$KUBECTL" apply -f - > d4.log 2>&1; then cat d4.log >&2; die "D4 unsigned pod outside the chart admitted"; fi
want_denied D4 "pod outside the chart, unsigned digest" d4.log "$NOTSIGNED" "${unsigned#*@}"

if run_helm upgrade "$MIRROR" "$(tagof "$m_signed")" > g1.log 2>&1; then cat g1.log >&2; die "G1 upgrade to a new repository ran under the stale policy"; fi
grep -q "is not the policy this release renders" g1.log || { cat g1.log >&2; die "G1: refused for the wrong reason"; }
ok G1 "upgrade to a mirror repository before re-applying the policy -> REFUSED by the chart (policy-sha256 differs)"

apply_policy "$MIRROR" "$(tagof "$m_signed")"
if run_helm upgrade "$MIRROR" "$(tagof "$m_unsigned")" > d5.log 2>&1; then cat d5.log >&2; die "D5 unsigned mirror digest admitted"; fi
want_denied D5 "mirror repository $MIRROR, unsigned digest" d5.log "$MIRROR@sha256" "$NOTSIGNED"

run_helm upgrade "$MIRROR" "$(tagof "$m_signed")" > a2.log 2>&1 || { cat a2.log >&2; die "A2 signed mirror digest refused"; }
for _ in $(seq 1 60); do
  imgs="$("$KUBECTL" -n "$NS" get pods -l "$AGENT_PODS" -o jsonpath='{range .items[*]}{.spec.containers[0].image}{"\n"}{end}' 2>/dev/null || true)"
  grep -qxF "$m_signed" <<<"$imgs" && break; sleep 1
done
grep -qxF "$m_signed" <<<"$imgs" || die "A2: no agent pod admitted with $m_signed"
ok A2 "mirror repository, signed digest -> ADMITTED: pod runs $m_signed"

# The release now runs the RUNNABLE signed agent image (same repository, so the
# policy is unchanged), with the chart's default strict Localhost seccomp
# profile and its installer initContainer — which, since RTO-12, runs the agent
# image itself (no busybox). The admission-check CronJob uses it too.
SECCOMP_ON=(--set seccomp.type=Localhost --set seccomp.installProfile=true)
run_helm upgrade "$MIRROR" "$(tagof "$m_agent")" "${SECCOMP_ON[@]}" > up-agent.log 2>&1 || { cat up-agent.log >&2; die "upgrade to the runnable agent image refused"; }
# S1: the installer ran the verified agent image and put the chart's profile on the node.
init_state=""
for _ in $(seq 1 120); do
  init_state="$("$KUBECTL" -n "$NS" get pods -l "$AGENT_PODS" -o jsonpath='{range .items[*]}{.spec.initContainers[0].image}{" rc="}{.status.initContainerStatuses[0].state.terminated.exitCode}{.status.initContainerStatuses[0].lastState.terminated.exitCode}{"\n"}{end}' 2>/dev/null | grep -F "$m_agent rc=" | head -1 || true)"
  [ "$init_state" = "$m_agent rc=0" ] && break; sleep 1
done
[ "$init_state" = "$m_agent rc=0" ] || { "$KUBECTL" -n "$NS" get pods -l "$AGENT_PODS" -o yaml >&2; die "S1: the install-seccomp-profile initContainer did not complete from $m_agent (got '$init_state')"; }
docker exec "$CLUSTER-control-plane" cat /var/lib/kubelet/seccomp/probectl/seccomp.json > node-seccomp.json || die "S1: no profile on the node"
cmp -s node-seccomp.json "$AGENT_CHART/files/seccomp.json" || die "S1: the node's profile differs from the chart's bundled profile"
ok S1 "seccomp installer initContainer runs the signed agent image ($m_agent), exit 0 -> the chart's strict profile is on the node"
# S2: an unsigned image in the initContainer slot is denied, even beside a signed agent.
cat > s2.yaml <<S2POD
apiVersion: v1
kind: Pod
metadata: {name: s2, namespace: probectl-qa-beta-other}
spec:
  initContainers:
    - name: install-seccomp-profile
      image: $unsigned
  containers:
    - name: agent
      image: $signed
S2POD
if "$KUBECTL" apply -f s2.yaml > s2.log 2>&1; then cat s2.log >&2; die "S2 an unsigned installer initContainer was admitted"; fi
want_denied S2 "unsigned image as the seccomp installer initContainer (signed agent beside it)" s2.log "$NOTSIGNED" "${unsigned#*@}"
# run_check JOB -> the Job's final condition (Complete|Failed); its log in JOB.log.
run_check() {
  "$KUBECTL" -n "$NS" create job "$1" --from="cronjob/$CHECK_CRONJOB" >/dev/null || die "$1: create a Job from cronjob/$CHECK_CRONJOB"
  local cond=""
  for _ in $(seq 1 120); do
    cond="$("$KUBECTL" -n "$NS" get job "$1" -o jsonpath='{range .status.conditions[?(@.status=="True")]}{.type}{"\n"}{end}' 2>/dev/null | grep -Ex 'Complete|Failed' | head -1 || true)"
    [ -n "$cond" ] && break; sleep 1
  done
  "$KUBECTL" -n "$NS" logs "job/$1" > "$1.log" 2>&1 || true
  printf '%s' "$cond"
}
# W0: while Kyverno verifies, the observe-only check passes.
[ "$(run_check w0)" = Complete ] || { cat w0.log >&2; die "W0: the admission check did not pass while Kyverno was verifying"; }
grep -q '"msg":"kyverno admission check ok"' w0.log || { cat w0.log >&2; die "W0: no ok line in the check's log"; }
ok W0 "admission-check CronJob (signed agent image, get-only RBAC) while Kyverno verifies -> Job Complete"

# failurePolicy Fail: a registered Kyverno that cannot answer (hung, crashed
# without a graceful shutdown, partitioned) refuses even the SIGNED image —
# never "admit". Freeze the admission controller with SIGSTOP; a Service-level
# trick would not do, the API server keeps its established webhook connection.
kyv() { docker exec "$CLUSTER-control-plane" sh -c "kill -$1 \$(pgrep -f '^/ko-app/kyverno ')"; }
kyv STOP
if pod_yaml d6 probectl-qa-beta-other "$signed" | "$KUBECTL" apply -f - > d6.log 2>&1; then kyv CONT; cat d6.log >&2; die "D6 pod admitted while Kyverno could not answer"; fi
kyv CONT
grep -Eq 'failed calling webhook "ivpol\.validate\.kyverno\.svc-fail' d6.log || { cat d6.log >&2; die "D6: refused, but not by the unanswered Kyverno ImageValidatingPolicy webhook"; }
ok D6 "Kyverno not answering, signed digest -> DENIED (failurePolicy Fail): $(grep -Eo 'failed calling webhook "[^"]+".*' d6.log | head -1 | cut -c1-160)"

# Kyverno scaled to zero DELETES its webhooks (Kyverno's design: nothing is
# verified cluster-wide after that) while the policy still reads Ready. The
# chart's readiness gate checks the webhooks too, so it refuses to roll out.
"$KUBECTL" -n kyverno scale deploy/kyverno-admission-controller --replicas=0 >/dev/null
ivpol_webhooks() { "$KUBECTL" get validatingwebhookconfiguration kyverno-resource-validating-webhook-cfg \
  -o jsonpath='{.webhooks[*].name}' 2>/dev/null | tr ' ' '\n' | grep -c '^ivpol\.validate\.kyverno\.svc-fail' || true; }
for _ in $(seq 1 120); do
  [ "$(ivpol_webhooks)" -eq 0 ] && break
  sleep 1
done
[ "$(ivpol_webhooks)" -eq 0 ] || die "G2: Kyverno at zero replicas still has its ImageValidatingPolicy webhook"
[ "$("$KUBECTL" get imagevalidatingpolicy "$POLICY" -o jsonpath='{.status.conditionStatus.ready}')" = true ] \
  || die "G2: expected the policy to still read Ready with no webhook (the state the gate exists for)"
# W1: the continuous detection fires — the next check FAILS, naming the gap.
[ "$(run_check w1)" = Failed ] || { cat w1.log >&2; die "W1: the admission check did not fail with Kyverno's webhooks gone"; }
grep -q 'kyverno admission check FAILED' w1.log && grep -Eq "ValidatingWebhookConfiguration kyverno-resource-validating-webhook-cfg (is missing|has no failurePolicy=Fail webhook serving ImageValidatingPolicy $POLICY)" w1.log \
  || { cat w1.log >&2; die "W1: the failed check does not name the missing webhook"; }
ok W1 "Kyverno scaled to zero -> admission-check Job FAILED: $(grep -Eo "Kyverno's ValidatingWebhookConfiguration [^\"]*" w1.log | head -1 | cut -c1-160)"
if run_helm upgrade "$MIRROR" "$(tagof "$m_agent")" "${SECCOMP_ON[@]}" > g2.log 2>&1; then cat g2.log >&2; die "G2 chart rolled out while Kyverno had no webhooks"; fi
grep -q "has no failurePolicy=Fail webhook serving ImageValidatingPolicy $POLICY" g2.log || { cat g2.log >&2; die "G2: refused for the wrong reason"; }
ok G2 "Kyverno scaled to zero (webhooks removed, policy still Ready) -> REFUSED by the chart"

[ "$pass" -eq 17 ] || die "only $pass of 17 legs asserted"
echo "KYVERNO ADMISSION SMOKE: OK ($pass legs; Kyverno $KYVERNO_TAG on kind $KIND_NODE_IMAGE)"
