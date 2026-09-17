#!/usr/bin/env bash
# Helm hardening gate (S35, F29): render the chart and assert the secure-by-default
# invariants hold. This is a security surface — a regression here (a dropped
# securityContext, a re-introduced default credential, a missing NetworkPolicy in
# the large profile) must fail CI. Requires `helm` on PATH.
set -euo pipefail

CHART="${CHART:-deploy/helm/probectl}"
AGENT_CHART="${AGENT_CHART:-deploy/helm/probectl-agent}"
CI_WORKFLOW=".github/workflows/ci.yml"
ANSIBLE_AGENT_TASKS="deploy/ansible/roles/probectl_agents/tasks/main.yml"
ANSIBLE_AGENT_DEFAULTS="deploy/ansible/roles/probectl_agents/defaults/main.yml"
# A throwaway base64 32-byte key just to let rendering proceed.
KEY="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
# A throwaway hex 32-byte key for keyed session-token hashing.
SESSION_KEY="000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
# Throwaway name only: Helm checks that an operator-owned TLS Secret is named;
# Kubernetes resolves the actual Secret at install time.
CONTROL_TLS_SECRET="probectl-control-tls"
# Throwaway ingress-nginx proxy-ssl trust contract. The real Secret is
# operator-managed and contains tls.crt, tls.key, and ca.crt; the expected name
# must match the serving certificate.
BACKEND_TLS_SECRET="probectl-backend-ca"
BACKEND_TLS_SERVER_NAME="probectl-control.probectl.svc"
# Throwaway immutable digest for render-only tests.
CONTROL_IMAGE_DIGEST="sha256:0000000000000000000000000000000000000000000000000000000000000000"
# Throwaway names for operator-created shared runtime state. Kubernetes resolves
# the actual Secret/PVC at install time; render tests assert the references.
RUNTIME_SECRET="probectl-provider-runtime"
OBJECTSTORE_CLAIM="probectl-provider-objects-rwx"
OBJECTSTORE_MOUNT="/var/lib/probectl/objects"

fail() {
  echo "helm hardening gate: FAIL — $*" >&2
  exit 1
}

render() {
  helm template probectl "$CHART" \
    --set ingress.host=h.example.com \
    --set ingress.tlsSecretName=probectl-tls \
    --set ingress.backendTLS.trustSecret="$BACKEND_TLS_SECRET" \
    --set ingress.backendTLS.serverName="$BACKEND_TLS_SERVER_NAME" \
    --set control.tls.existingSecret="$CONTROL_TLS_SECRET" \
    --set image.digest="$CONTROL_IMAGE_DIGEST" \
    --set secrets.existingSecret="$RUNTIME_SECRET" \
    --set database.url="postgres://probectl:s3cret-not-default@db:5432/probectl?sslmode=require" \
    --set objectStore.enabled=true \
    --set-string objectStore.mountPath="$OBJECTSTORE_MOUNT" \
    --set-string objectStore.existingClaim="$OBJECTSTORE_CLAIM" \
    --set-string control.extraEnv.PROBECTL_AUDIT_WORM_DIR="$OBJECTSTORE_MOUNT/audit-worm" \
    --set-string control.extraEnv.PROBECTL_SIEM_ENABLED="true" \
    --set-string control.extraEnv.PROBECTL_SIEM_ENDPOINT="https://siem.example/ingest" \
    "$@"
}

render_agent() {
  helm template probectl-agent "$AGENT_CHART" "$@" \
    --set-string tenantID=t-hardening \
    --set-string image.tag="0.0.0@sha256:0000000000000000000000000000000000000000000000000000000000000000" \
    --set-json 'bus.brokers=["kafka.probectl.svc:9093"]'
}

need() { grep -q -- "$1" <<<"$2" || fail "$3"; }
need_fixed() { grep -Fq -- "$1" <<<"$2" || fail "$3"; }
need_file() { grep -q -- "$1" "$2" || fail "$3"; }

need_digest_pinned_control_images() {
  local label="$1"
  local body="$2"
  local minimum="$3"
  local refs count

  refs="$(grep -E '^[[:space:]]*image: ghcr.io/ctlplne/probectl-control' <<<"$body" || true)"
  count="$(grep -c . <<<"$refs" || true)"
  [ "$count" -ge "$minimum" ] \
    || fail "$label rendered $count primary control image references; expected at least $minimum"
  if grep -vF "@$CONTROL_IMAGE_DIGEST" <<<"$refs" >/dev/null; then
    fail "$label rendered a non-digest primary control image (SUPPLY-deb3c967)"
  fi
}

control_stager_blocks() {
  awk '
    function leading_spaces(line, trimmed) {
      trimmed = line
      sub(/^ */, "", trimmed)
      return length(line) - length(trimmed)
    }
    {
      trimmed = $0
      sub(/^[[:space:]]*/, "", trimmed)
      if (capturing && trimmed != "" && trimmed !~ /^#/ && leading_spaces($0) <= base_indent) {
        capturing = 0
      }
      if (!capturing && trimmed == "- name: stage-probectl") {
        capturing = 1
        base_indent = leading_spaces($0)
      }
      if (capturing) {
        print
      }
    }
  '
}

need_shellless_control_stagers() {
  local label="$1"
  local body="$2"
  local expected="$3"
  local blocks stage_count command_count args_count

  blocks="$(control_stager_blocks <<<"$body")"
  stage_count="$(grep -F -c -- '- name: stage-probectl' <<<"$blocks" || true)"
  command_count="$(grep -F -c -- 'command: ["/usr/local/bin/app"]' <<<"$blocks" || true)"
  args_count="$(grep -F -c -- 'args: ["stage-binary", ' <<<"$blocks" || true)"
  [ "$stage_count" -eq "$expected" ] \
    || fail "$label rendered $stage_count stage-probectl init containers; expected $expected"
  [ "$command_count" -eq "$expected" ] \
    || fail "$label stage-probectl containers must directly execute /usr/local/bin/app"
  [ "$args_count" -eq "$expected" ] \
    || fail "$label stage-probectl containers must use the app-native stage-binary helper"
  if grep -Fq '/bin/sh' <<<"$blocks"; then
    fail "$label stage-probectl invokes /bin/sh from the shell-free distroless control image (CONFIG-03870cbe)"
  fi
}

# OPS-005: the Ansible role's final health proof must not regress to local
# systemd-only liveness. It must fail closed unless the operator supplies the
# tenant-scoped control-plane API endpoint, an agent.read token, and the expected
# agent id, then query /v1/agents/{id} for id/version/status/last_seen_at.
need_file "probectl_verify_registry_heartbeat: true" "$ANSIBLE_AGENT_DEFAULTS" "Ansible registry heartbeat verification is not default-on (OPS-005)"
need_file "probectl_control_api_url" "$ANSIBLE_AGENT_DEFAULTS" "Ansible role has no control-plane API URL variable (OPS-005)"
need_file "probectl_control_api_token" "$ANSIBLE_AGENT_DEFAULTS" "Ansible role has no control-plane API token variable (OPS-005)"
need_file "probectl_registry_agent_id" "$ANSIBLE_AGENT_DEFAULTS" "Ansible role has no expected registry agent id variable (OPS-005)"
need_file "probectl_control_api_url" "$ANSIBLE_AGENT_TASKS" "Ansible role does not require the control-plane API URL (OPS-005)"
need_file "probectl_control_api_token" "$ANSIBLE_AGENT_TASKS" "Ansible role does not require the control-plane API token (OPS-005)"
need_file "probectl_registry_agent_id" "$ANSIBLE_AGENT_TASKS" "Ansible role does not require the expected agent id (OPS-005)"
need_file "ansible.builtin.uri" "$ANSIBLE_AGENT_TASKS" "Ansible role does not query the control-plane registry (OPS-005)"
need_file "/v1/agents/{{ probectl_registry_agent_id }}" "$ANSIBLE_AGENT_TASKS" "Ansible role does not query the expected agent registry row (OPS-005)"
need_file "agent_version" "$ANSIBLE_AGENT_TASKS" "Ansible registry verification does not check agent_version (OPS-005)"
need_file "last_seen_at" "$ANSIBLE_AGENT_TASKS" "Ansible registry verification does not check heartbeat last_seen_at (OPS-005)"
need_file "no_log: true" "$ANSIBLE_AGENT_TASKS" "Ansible registry verification could log the bearer token (OPS-005)"
local_line="$(grep -n 'Verify local agent service liveness' "$ANSIBLE_AGENT_TASKS" | head -n1 | cut -d: -f1 || true)"
registry_line="$(grep -n 'Read the tenant-scoped agent registry heartbeat' "$ANSIBLE_AGENT_TASKS" | head -n1 | cut -d: -f1 || true)"
if [[ -z "$local_line" || -z "$registry_line" || "$registry_line" -le "$local_line" ]]; then
  fail "Ansible registry heartbeat proof must run after the local liveness precheck (OPS-005)"
fi

# DPR-006: a licensed (Enterprise/MSP) install has a first-class chart path —
# the offline-signed file arrives from an operator-created Secret, mounted
# read-only, and PROBECTL_LICENSE_FILE points at it. Community renders no
# license plumbing at all, and extraEnv cannot smuggle a different path in.
licensed="$(render --set license.existingSecret=probectl-license)"
need_fixed 'name: PROBECTL_LICENSE_FILE' "$licensed" "licensed render must set PROBECTL_LICENSE_FILE (DPR-006)"
need_fixed 'value: "/etc/probectl/license/license.json"' "$licensed" "licensed render must point PROBECTL_LICENSE_FILE at the mounted Secret key (DPR-006)"
need_fixed 'secretName: "probectl-license"' "$licensed" "licensed render must mount the operator-created license Secret (DPR-006)"
license_mount="$(grep -A2 -F -- '- name: license' <<<"$licensed" | grep -F 'mountPath: "/etc/probectl/license"' || true)"
[ -n "$license_mount" ] || fail "licensed render must mount the license Secret at /etc/probectl/license (DPR-006)"
grep -A3 -F -- '- name: license' <<<"$licensed" | grep -Fq 'readOnly: true' \
  || fail "the license mount must be read-only (DPR-006)"
community="$(render)"
if grep -Fq 'PROBECTL_LICENSE_FILE' <<<"$community"; then
  fail "Community render must carry no license plumbing (DPR-006)"
fi
if render --set-string control.extraEnv.PROBECTL_LICENSE_FILE=/tmp/x >/dev/null 2>&1; then
  fail "control.extraEnv.PROBECTL_LICENSE_FILE must be rejected as reserved (DPR-006)"
fi

# OPS-003: kubeconform must render the same fail-closed chart shape the hardening
# gate renders. The chart requires envelope, session-HMAC, and database DSN
# values; CI cannot omit two of them and still claim Kubernetes manifest proof.
need_file "PROBECTL_HELM_TEST_ENVELOPE_KEY" "$CI_WORKFLOW" "CI kubeconform render must set the dummy envelope key (OPS-003)"
need_file "PROBECTL_HELM_TEST_SESSION_HMAC_KEY" "$CI_WORKFLOW" "CI kubeconform render must set the dummy session-HMAC key (OPS-003)"
need_file "PROBECTL_HELM_TEST_DATABASE_URL" "$CI_WORKFLOW" "CI kubeconform render must set the dummy database URL (OPS-003)"
need_file "PROBECTL_HELM_TEST_IMAGE_DIGEST" "$CI_WORKFLOW" "CI kubeconform render must set the immutable control image digest (SUPPLY-deb3c967)"
need_file "control.tls.existingSecret" "$CI_WORKFLOW" "CI kubeconform render must name the required control-listener TLS Secret (CONFIG-aa08042e)"
need_file "ingress.backendTLS.trustSecret" "$CI_WORKFLOW" "CI kubeconform render must name the backend CA Secret (CRYPTO-bced5da5)"
need_file "ingress.backendTLS.serverName" "$CI_WORKFLOW" "CI kubeconform render must name the expected backend certificate identity (CRYPTO-bced5da5)"
need_file "image.digest" "$CI_WORKFLOW" "CI kubeconform render must pass image.digest to Helm (SUPPLY-deb3c967)"
need_file "secrets.sessionHMACKey" "$CI_WORKFLOW" "CI kubeconform render must pass secrets.sessionHMACKey to helm template (OPS-003)"
need_file "database.url" "$CI_WORKFLOW" "CI kubeconform render must pass database.url to helm template (OPS-003)"

# CONFIG-dc29d726: the annotation alone does not make verified backend TLS
# deployable. Keep every operator surface aligned with ingress-nginx's complete
# proxy-ssl-secret data contract, and retain one copy/pasteable creation example.
for contract_file in \
  deploy/helm/README.md \
  deploy/helm/probectl/values.yaml \
  deploy/gitops/argocd/application.yaml \
  deploy/gitops/flux/helmrelease.yaml \
  deploy/terraform/modules/probectl/variables.tf \
  deploy/terraform/README.md \
  docs/iac-gitops.md
do
  need_file "tls\\.crt.*tls\\.key.*ca\\.crt" "$contract_file" \
    "$contract_file omits the complete ingress-nginx proxy-ssl Secret contract (CONFIG-dc29d726)"
done
need_file "--from-file=tls.crt=ingress-client.crt" deploy/helm/README.md \
  "Helm README lacks the backend proxy-ssl client certificate creation step (CONFIG-dc29d726)"
need_file "--from-file=tls.key=ingress-client.key" deploy/helm/README.md \
  "Helm README lacks the backend proxy-ssl client key creation step (CONFIG-dc29d726)"
need_file "--from-file=ca.crt=control-listener-ca.crt" deploy/helm/README.md \
  "Helm README lacks the backend proxy-ssl CA creation step (CONFIG-dc29d726)"

bash scripts/check_clickhouse_restore_contract.sh

# W1: the optional analyzer must remain listener-free, tenant-configured,
# immutable-image pinned, and default-deny on ingress/egress. Exercise the
# disabled-by-default branch AND the enabled render so this component cannot
# silently rot behind a values flag.
if render --set bgpAnalyzer.enabled=true \
  --set bgpAnalyzer.configSecret=bgp-config \
  --set bgpAnalyzer.source=mrt \
  --set bgpAnalyzer.sourceFile=/fixtures/routes.mrt \
  --set bgpAnalyzer.image.digest=sha256:0000000000000000000000000000000000000000000000000000000000000000 \
  --set-string bgpAnalyzer.extraEnv.PROBECTL_BUS_BROKERS=kafka.probectl.svc:9093 \
  >/dev/null 2>&1; then
  fail "BGP analyzer rendered without an explicit egress allow-list (W1)"
fi
analyzer_render="$(render \
  --set bgpAnalyzer.enabled=true \
  --set bgpAnalyzer.configSecret=bgp-config \
  --set bgpAnalyzer.source=mrt \
  --set bgpAnalyzer.sourceFile=/fixtures/routes.mrt \
  --set bgpAnalyzer.image.digest=sha256:0000000000000000000000000000000000000000000000000000000000000000 \
  --set-string bgpAnalyzer.extraEnv.PROBECTL_BUS_BROKERS=kafka.probectl.svc:9093 \
  --set-json 'bgpAnalyzer.networkPolicy.egressTo=[{"to":[{"ipBlock":{"cidr":"10.0.0.0/8"}}],"ports":[{"protocol":"TCP","port":9093}]}]')"
need_fixed "name: probectl-bgp-analyzer" "$analyzer_render" "BGP analyzer Deployment/NetworkPolicy did not render (W1)"
need_fixed "ghcr.io/ctlplne/probectl-bgp-analyzer@sha256:0000000000000000000000000000000000000000000000000000000000000000" "$analyzer_render" "BGP analyzer image is not digest-pinned (W1)"
need_fixed "automountServiceAccountToken: false" "$analyzer_render" "BGP analyzer received a Kubernetes API token (W1)"
need_fixed "PROBECTL_BGP_ANALYZER_CONFIG" "$analyzer_render" "BGP analyzer has no tenant config binding (W1)"
need_fixed "ingress: []" "$analyzer_render" "BGP analyzer NetworkPolicy admits inbound traffic despite having no listener (W1)"

# W2: the rendered-browser agent is a listener-free, tenant-bound DaemonSet.
# Exercise the enabled branch and require explicit egress rather than letting a
# Chromium workload inherit the control plane's allow-all fallback.
if render --set browserAgent.enabled=true \
  --set browserAgent.configSecret=browser-agent-config \
  --set browserAgent.image.digest=sha256:0000000000000000000000000000000000000000000000000000000000000000 \
  >/dev/null 2>&1; then
  fail "browser agent rendered without an explicit egress allow-list (W2)"
fi
browser_render="$(render \
  --set browserAgent.enabled=true \
  --set browserAgent.configSecret=browser-agent-config \
  --set browserAgent.image.digest=sha256:0000000000000000000000000000000000000000000000000000000000000000 \
  --set-json 'browserAgent.networkPolicy.egressTo=[{"to":[{"ipBlock":{"cidr":"203.0.113.0/24"}}],"ports":[{"protocol":"TCP","port":443}]}]')"
need_fixed "kind: DaemonSet" "$browser_render" "browser agent DaemonSet did not render (W2)"
need_fixed "name: probectl-browser-agent" "$browser_render" "browser agent workload/NetworkPolicy is missing (W2)"
need_fixed "ghcr.io/ctlplne/probectl-browser-agent@sha256:0000000000000000000000000000000000000000000000000000000000000000" "$browser_render" "browser agent image is not digest-pinned (W2)"
need_fixed "automountServiceAccountToken: false" "$browser_render" "browser agent received a Kubernetes API token (W2)"
need_fixed "readOnlyRootFilesystem: true" "$browser_render" "browser agent root filesystem is writable (W2)"
need_fixed "PROBECTL_AGENT_BROWSER_WORKER_PATH" "$browser_render" "browser agent is not pinned to the packaged worker (W2)"
need_fixed "ingress: []" "$browser_render" "browser agent NetworkPolicy admits inbound traffic (W2)"

# EBPF-001: every shipped eBPF config generator must include the schema version
# accepted by the strict agent loader. The agent should keep failing closed on
# missing/unknown config, while Helm/install/e2e never generate an old headerless
# file that dies before startup.
agent_base="$(render_agent)"
agent_config="$(awk '/ebpf-agent.yaml: \|/,/^---/' <<<"$agent_base")"
need_fixed "apiVersion: probectl.io/ebpf-agent/v1" "$agent_config" "probectl-agent Helm ConfigMap omitted eBPF apiVersion (EBPF-001)"
need_file "apiVersion: probectl.io/ebpf-agent/v1" "deploy/agent/install.sh" "install.sh generated eBPF config omitted apiVersion (EBPF-001)"
need_file "apiVersion: probectl.io/ebpf-agent/v1" "test/e2e/e2e_test.go" "e2e fixture generated eBPF config omitted apiVersion (EBPF-001)"

# 1. No default credentials: rendering without required secret material (and no
#    existingSecret) must FAIL closed.
if helm template probectl "$CHART" \
  --set ingress.host=h.example.com --set ingress.tlsSecretName=probectl-tls \
  --set ingress.backendTLS.trustSecret="$BACKEND_TLS_SECRET" \
  --set ingress.backendTLS.serverName="$BACKEND_TLS_SERVER_NAME" \
  --set control.tls.existingSecret="$CONTROL_TLS_SECRET" \
  --set image.digest="$CONTROL_IMAGE_DIGEST" >/dev/null 2>&1; then
  fail "chart rendered with no secrets.envelopeKey — that would be a default credential"
fi

# 1a. CONFIG-aa08042e: the pod listener is HTTPS by default and its certificate
#     is operator-owned. A complete application configuration without the
#     serving-certificate Secret must fail during rendering, before any pod can
#     start or expose a plaintext fallback.
if helm template probectl "$CHART" \
  --set ingress.host=h.example.com --set ingress.tlsSecretName=probectl-tls \
  --set ingress.backendTLS.trustSecret="$BACKEND_TLS_SECRET" \
  --set ingress.backendTLS.serverName="$BACKEND_TLS_SERVER_NAME" \
  --set image.digest="$CONTROL_IMAGE_DIGEST" \
  --set secrets.envelopeKey="$KEY" \
  --set secrets.sessionHMACKey="$SESSION_KEY" \
  --set database.url="postgres://probectl:s3cret-not-default@db:5432/probectl?sslmode=require" >/dev/null 2>&1; then
  fail "chart rendered without control.tls.existingSecret (CONFIG-aa08042e)"
fi

# 1b. OPS-001: no default DATABASE credential. Rendering with NO database.url must
#     fail closed, and rendering WITH the shipped dev credential (probectl:probectl)
#     must fail too — an operator who forgets to override must never materialize a
#     known password into a Kubernetes Secret.
if helm template probectl "$CHART" \
  --set ingress.host=h.example.com --set ingress.tlsSecretName=probectl-tls \
  --set ingress.backendTLS.trustSecret="$BACKEND_TLS_SECRET" \
  --set ingress.backendTLS.serverName="$BACKEND_TLS_SERVER_NAME" \
  --set control.tls.existingSecret="$CONTROL_TLS_SECRET" \
  --set image.digest="$CONTROL_IMAGE_DIGEST" \
  --set secrets.envelopeKey="$KEY" >/dev/null 2>&1; then
  fail "chart rendered with no database.url — that would be a blank/default DB credential (OPS-001)"
fi
if helm template probectl "$CHART" \
  --set ingress.host=h.example.com --set ingress.tlsSecretName=probectl-tls \
  --set ingress.backendTLS.trustSecret="$BACKEND_TLS_SECRET" \
  --set ingress.backendTLS.serverName="$BACKEND_TLS_SERVER_NAME" \
  --set control.tls.existingSecret="$CONTROL_TLS_SECRET" \
  --set image.digest="$CONTROL_IMAGE_DIGEST" \
  --set secrets.envelopeKey="$KEY" \
  --set database.url="postgres://probectl:s3cret-not-default@db:5432/probectl?sslmode=require" >/dev/null 2>&1; then
  fail "chart rendered with no secrets.sessionHMACKey — production sessions would lose keyed hashing (KEYS-002/OPS-006)"
fi
if helm template probectl "$CHART" \
  --set ingress.host=h.example.com --set ingress.tlsSecretName=probectl-tls \
  --set ingress.backendTLS.trustSecret="$BACKEND_TLS_SECRET" \
  --set ingress.backendTLS.serverName="$BACKEND_TLS_SERVER_NAME" \
  --set control.tls.existingSecret="$CONTROL_TLS_SECRET" \
  --set image.digest="$CONTROL_IMAGE_DIGEST" \
  --set secrets.envelopeKey="$KEY" \
  --set secrets.sessionHMACKey="not-a-32-byte-hex-key" \
  --set database.url="postgres://probectl:s3cret-not-default@db:5432/probectl?sslmode=require" >/dev/null 2>&1; then
  fail "chart rendered an invalid secrets.sessionHMACKey (KEYS-002/OPS-006)"
fi
if helm template probectl "$CHART" \
  --set ingress.host=h.example.com --set ingress.tlsSecretName=probectl-tls \
  --set ingress.backendTLS.trustSecret="$BACKEND_TLS_SECRET" \
  --set ingress.backendTLS.serverName="$BACKEND_TLS_SERVER_NAME" \
  --set control.tls.existingSecret="$CONTROL_TLS_SECRET" \
  --set image.digest="$CONTROL_IMAGE_DIGEST" \
  --set secrets.envelopeKey="$KEY" \
  --set secrets.sessionHMACKey="$SESSION_KEY" \
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
# CONFIG-aa08042e: the default Service, container, probes, ingress backend, and
# application config must all describe one HTTPS listener. This is intentionally
# repeated here rather than inferred from a single values flag.
base_svc="$(awk '/kind: Service$/,/^---/' <<<"$base")"
base_dep="$(awk '/kind: Deployment$/,/^---/' <<<"$base")"
base_cm="$(awk '/kind: ConfigMap$/,/^---/' <<<"$base")"
base_ing="$(awk '/kind: Ingress$/,/^---/' <<<"$base")"
need "name: https" "$base_svc" "default Service does not expose a named https port (CONFIG-aa08042e)"
need "targetPort: https" "$base_svc" "default Service does not target the https listener (CONFIG-aa08042e)"
need "name: https" "$base_dep" "default Deployment has no named https listener (CONFIG-aa08042e)"
need "scheme: HTTPS" "$base_dep" "default health probes are not HTTPS (CONFIG-aa08042e)"
need_fixed 'PROBECTL_ALLOW_PLAINTEXT_HTTP: "false"' "$base_cm" "default ConfigMap permits plaintext HTTP (CONFIG-aa08042e)"
need "PROBECTL_TLS_CERT_FILE" "$base_cm" "default ConfigMap lacks the TLS certificate path (CONFIG-aa08042e)"
need "PROBECTL_TLS_KEY_FILE" "$base_cm" "default ConfigMap lacks the TLS key path (CONFIG-aa08042e)"
need_fixed "secretName: \"$CONTROL_TLS_SECRET\"" "$base_dep" "default Deployment does not mount the required TLS Secret (CONFIG-aa08042e)"
need_fixed 'nginx.ingress.kubernetes.io/backend-protocol: "HTTPS"' "$base_ing" "default ingress backend is not HTTPS (CONFIG-aa08042e)"
need_fixed 'nginx.ingress.kubernetes.io/proxy-ssl-verify: "on"' "$base_ing" "default ingress does not verify the backend certificate (CRYPTO-bced5da5)"
need_fixed "nginx.ingress.kubernetes.io/proxy-ssl-secret: \"default/$BACKEND_TLS_SECRET\"" "$base_ing" "default ingress does not use the backend CA Secret (CRYPTO-bced5da5)"
need_fixed 'nginx.ingress.kubernetes.io/proxy-ssl-server-name: "on"' "$base_ing" "default ingress does not send SNI to the verified backend (CRYPTO-bced5da5)"
need_fixed "nginx.ingress.kubernetes.io/proxy-ssl-name: \"$BACKEND_TLS_SERVER_NAME\"" "$base_ing" "default ingress does not verify the expected backend name (CRYPTO-bced5da5)"
need "name: https" "$base_ing" "default ingress does not route to the https Service port (CONFIG-aa08042e)"
# CRYPTO-bced5da5: HTTPS without CA/name verification is not an authenticated
# channel. Both trust inputs are mandatory, and generic annotations cannot turn
# the chart-owned verification controls off.
if helm template probectl "$CHART" \
  --set ingress.host=h.example.com --set ingress.tlsSecretName=probectl-tls \
  --set control.tls.existingSecret="$CONTROL_TLS_SECRET" \
  --set image.digest="$CONTROL_IMAGE_DIGEST" \
  --set secrets.envelopeKey="$KEY" \
  --set secrets.sessionHMACKey="$SESSION_KEY" \
  --set database.url="postgres://probectl:s3cret-not-default@db:5432/probectl?sslmode=require" >/dev/null 2>&1; then
  fail "chart rendered an HTTPS backend without ingress.backendTLS trust/name (CRYPTO-bced5da5)"
fi
if render --set ingress.backendTLS.trustSecret= >/dev/null 2>&1; then
  fail "chart rendered an HTTPS backend without a CA Secret (CRYPTO-bced5da5)"
fi
if render --set ingress.backendTLS.serverName= >/dev/null 2>&1; then
  fail "chart rendered an HTTPS backend without an expected certificate name (CRYPTO-bced5da5)"
fi
for reserved_annotation in \
  nginx.ingress.kubernetes.io/ssl-redirect \
  nginx.ingress.kubernetes.io/force-ssl-redirect \
  nginx.ingress.kubernetes.io/backend-protocol \
  nginx.ingress.kubernetes.io/proxy-ssl-verify \
  nginx.ingress.kubernetes.io/proxy-ssl-secret \
  nginx.ingress.kubernetes.io/proxy-ssl-server-name \
  nginx.ingress.kubernetes.io/proxy-ssl-name; do
  escaped_annotation="${reserved_annotation//./\\.}"
  if render --set-string "ingress.annotations.${escaped_annotation}=planted-override" >/dev/null 2>&1; then
    fail "chart accepted reserved ingress annotation $reserved_annotation (CRYPTO-bced5da5)"
  fi
done
# CONFIG-11b3ac1d: generic extraEnv remains useful for optional subsystems, but
# it must never replace a key whose authoritative value comes from a typed chart
# value or the chart Secret.
for reserved_env in \
  PROBECTL_REQUIRE_AT_REST_ENCRYPTION PROBECTL_PUBLIC_TLS \
  PROBECTL_ALLOW_PLAINTEXT_HTTP PROBECTL_HTTP_ADDR \
  PROBECTL_TLS_CERT_FILE PROBECTL_TLS_KEY_FILE \
  PROBECTL_HSTS_ENABLED PROBECTL_HSTS_MAX_AGE \
  PROBECTL_LOG_FORMAT PROBECTL_LOG_LEVEL PROBECTL_AUTH_MODE \
  PROBECTL_SECURITY_CONTACT PROBECTL_OBJECTSTORE_DIR \
  PROBECTL_OIDC_ISSUER PROBECTL_OIDC_CLIENT_ID PROBECTL_OIDC_REDIRECT_URL \
  PROBECTL_ENVELOPE_KEY PROBECTL_SESSION_HMAC_KEY PROBECTL_DATABASE_URL \
  PROBECTL_OIDC_CLIENT_SECRET PROBECTL_WORM_SIGNING_KEY \
  PROBECTL_IR_UNLOCK_KEY PROBECTL_OBJECTSTORE_MODE PROBECTL_OBJECTSTORE_DIR \
  PROBECTL_OBJECTSTORE_S3_ENDPOINT PROBECTL_OBJECTSTORE_S3_BUCKET \
  PROBECTL_OBJECTSTORE_S3_REGION PROBECTL_OBJECTSTORE_S3_ACCESS_KEY \
  PROBECTL_OBJECTSTORE_S3_SECRET_KEY PROBECTL_OBJECTSTORE_S3_SESSION_TOKEN \
  PROBECTL_OBJECTSTORE_S3_PREFIX; do
  if render --show-only templates/configmap.yaml \
    --set-string "control.extraEnv.${reserved_env}=planted-override" >/dev/null 2>&1; then
    fail "chart accepted reserved control.extraEnv.${reserved_env} (CONFIG-11b3ac1d)"
  fi
done
ordinary_cm="$(render --show-only templates/configmap.yaml \
  --set-string control.extraEnv.PROBECTL_BUS_MODE=memory \
  --set-string control.extraEnv.PROBECTL_REGION=local)"
duplicate_env="$(
  awk '/^  PROBECTL_[A-Z0-9_]+:/ { key=$1; sub(/:$/, "", key); count[key]++ }
       END { for (key in count) if (count[key] != 1) print key }' <<<"$ordinary_cm"
)"
[ -z "$duplicate_env" ] \
  || fail "ConfigMap rendered duplicate environment keys: $duplicate_env (CONFIG-11b3ac1d)"
need_fixed 'PROBECTL_BUS_MODE: "memory"' "$ordinary_cm" "ordinary control.extraEnv key was not preserved (CONFIG-11b3ac1d)"
need_fixed 'PROBECTL_REGION: "local"' "$ordinary_cm" "second ordinary control.extraEnv key was not preserved (CONFIG-11b3ac1d)"
# BL-026: durable S3/MinIO mode renders only non-secret coordinates into the
# ConfigMap, assumes signing material comes from the runtime Secret, and does
# not mount the filesystem fallback volume.
s3_args=(
  --set objectStore.mode=s3
  --set-string objectStore.s3.endpoint=https://minio.example
  --set-string objectStore.s3.bucket=probectl-artifacts
  --set-string objectStore.s3.region=us-east-1
  --set-string objectStore.s3.accessKey=AKID
  --set-string objectStore.s3.prefix=probectl
  --set-string control.extraEnv.PROBECTL_AUDIT_WORM_DIR=
)
s3_cm="$(render --show-only templates/configmap.yaml "${s3_args[@]}")"
s3_deploy="$(render --show-only templates/deployment.yaml "${s3_args[@]}")"
need_fixed 'PROBECTL_OBJECTSTORE_MODE: "s3"' "$s3_cm" "S3 object-store mode did not render"
need_fixed 'PROBECTL_OBJECTSTORE_S3_ENDPOINT: "https://minio.example"' "$s3_cm" "S3 endpoint did not render"
if grep -q 'PROBECTL_OBJECTSTORE_S3_SECRET_KEY\|PROBECTL_OBJECTSTORE_S3_SESSION_TOKEN' <<<"$s3_cm"; then
  fail "S3 object-store secret material was rendered into ConfigMap"
fi
if grep -q 'name: tenant-objects' <<<"$s3_deploy"; then
  fail "S3 object-store mode mounted the filesystem fallback volume"
fi
# SUPPLY-deb3c967: migration and server must resolve to the signed digest, while
# the old tag-only input and malformed digests must fail before rendering.
need_digest_pinned_control_images "default chart" "$base" 2
if helm template probectl "$CHART" \
  --set ingress.host=h.example.com --set ingress.tlsSecretName=probectl-tls \
  --set ingress.backendTLS.trustSecret="$BACKEND_TLS_SECRET" \
  --set ingress.backendTLS.serverName="$BACKEND_TLS_SERVER_NAME" \
  --set control.tls.existingSecret="$CONTROL_TLS_SECRET" \
  --set-string image.tag=0.6.0 \
  --set secrets.envelopeKey="$KEY" \
  --set secrets.sessionHMACKey="$SESSION_KEY" \
  --set database.url="postgres://probectl:s3cret-not-default@db:5432/probectl?sslmode=require" >/dev/null 2>&1; then
  fail "chart rendered a tag-only primary control image (SUPPLY-deb3c967)"
fi
if helm template probectl "$CHART" \
  --set ingress.host=h.example.com --set ingress.tlsSecretName=probectl-tls \
  --set ingress.backendTLS.trustSecret="$BACKEND_TLS_SECRET" \
  --set ingress.backendTLS.serverName="$BACKEND_TLS_SERVER_NAME" \
  --set control.tls.existingSecret="$CONTROL_TLS_SECRET" \
  --set image.digest="$CONTROL_IMAGE_DIGEST" \
  --set-string image.tag=0.6.0 \
  --set secrets.envelopeKey="$KEY" \
  --set secrets.sessionHMACKey="$SESSION_KEY" \
  --set database.url="postgres://probectl:s3cret-not-default@db:5432/probectl?sslmode=require" >/dev/null 2>&1; then
  fail "chart accepted obsolete image.tag alongside image.digest; migrate values with --reset-values (SUPPLY-deb3c967)"
fi
if helm template probectl "$CHART" \
  --set ingress.host=h.example.com --set ingress.tlsSecretName=probectl-tls \
  --set ingress.backendTLS.trustSecret="$BACKEND_TLS_SECRET" \
  --set ingress.backendTLS.serverName="$BACKEND_TLS_SERVER_NAME" \
  --set control.tls.existingSecret="$CONTROL_TLS_SECRET" \
  --set image.digest=sha256:1234 \
  --set secrets.envelopeKey="$KEY" \
  --set secrets.sessionHMACKey="$SESSION_KEY" \
  --set database.url="postgres://probectl:s3cret-not-default@db:5432/probectl?sslmode=require" >/dev/null 2>&1; then
  fail "chart rendered a malformed primary control image digest (SUPPLY-deb3c967)"
fi
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
  --set ingress.backendTLS.trustSecret="$BACKEND_TLS_SECRET" \
  --set ingress.backendTLS.serverName="$BACKEND_TLS_SERVER_NAME" \
  --set control.tls.existingSecret="$CONTROL_TLS_SECRET" \
  --set image.digest="$CONTROL_IMAGE_DIGEST" \
  --set secrets.envelopeKey="$KEY" \
  --set secrets.sessionHMACKey="$SESSION_KEY" \
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
need "port: 8443"                   "$strict" "strict profile: ClickHouse HTTPS egress missing (WIRE-010)"
need "port: 9440"                   "$strict" "strict profile: ClickHouse native TLS egress missing (WIRE-010)"
need "port: 9093"                   "$strict" "strict profile: Kafka TLS egress missing (WIRE-010)"
for plain_port in 8123 9000 9092 9009; do
  grep -qE "port: ${plain_port}([[:space:]]|$)" <<<"$strict" \
    && fail "strict profile still permits plaintext datastore/broker egress port ${plain_port} (WIRE-010)"
done
# The default profile's allow-all egress rule ("- {}") must NOT survive in strict.
strict_np="$(awk '/kind: NetworkPolicy/,/^---/' <<<"$strict")"
grep -qE '^[[:space:]]*-[[:space:]]*\{\}[[:space:]]*$' <<<"$strict_np" \
  && fail "strict profile still has an allow-all egress rule (a HOLE) — default-deny not achieved"
need "kind: ServiceMonitor"         "$strict" "strict profile missing ServiceMonitor (OPS-005)"
# RUNOPS-004/WIRE-003: the strict ServiceMonitor asks Prometheus to use HTTPS.
# Prove that this is not just a scrape setting: the Service target, container
# listener, probes, ConfigMap TLS env, mounted Secret, and ingress backend all
# render as the same HTTPS transport. The negative assertions make the regulated
# profile fail closed if it drifts back to plaintext.
strict_svc="$(awk '/kind: Service$/,/^---/' <<<"$strict")"
strict_dep="$(awk '/kind: Deployment$/,/^---/' <<<"$strict")"
strict_cm="$(awk '/kind: ConfigMap$/,/^---/' <<<"$strict")"
strict_sm="$(awk '/kind: ServiceMonitor$/,/^---/' <<<"$strict")"
strict_ing="$(awk '/kind: Ingress$/,/^---/' <<<"$strict")"
need_fixed 'PROBECTL_DEPLOYMENT_PROFILE: "regulated"' "$strict_cm" "strict/regulated profile did not render PROBECTL_DEPLOYMENT_PROFILE=regulated (RUNOPS-003)"
need "name: https" "$strict_svc" "strict Service does not expose a named https port (RUNOPS-004)"
need "targetPort: https" "$strict_svc" "strict Service https port does not target the https container listener (RUNOPS-004)"
need "name: https" "$strict_dep" "strict Deployment does not expose a named https container port (RUNOPS-004)"
need "scheme: HTTPS" "$strict_dep" "strict Deployment probes do not use HTTPS against the HTTPS listener (RUNOPS-004)"
need_fixed "PROBECTL_ALLOW_PLAINTEXT_HTTP: \"false\"" "$strict_cm" "strict ConfigMap still permits plaintext HTTP (RUNOPS-004)"
if grep -q 'PROBECTL_ALLOW_PLAINTEXT_HTTP: "true"' <<<"$strict_cm"; then
  fail "strict/regulated profile rendered PROBECTL_ALLOW_PLAINTEXT_HTTP=true (WIRE-003)"
fi
need "PROBECTL_TLS_CERT_FILE" "$strict_cm" "strict ConfigMap missing TLS cert env (RUNOPS-004)"
need "PROBECTL_TLS_KEY_FILE" "$strict_cm" "strict ConfigMap missing TLS key env (RUNOPS-004)"
need "control-tls" "$strict_dep" "strict Deployment does not mount the control TLS secret (RUNOPS-004)"
need "port: https" "$strict_sm" "strict ServiceMonitor endpoint does not select the https Service port (RUNOPS-004)"
need "scheme: https" "$strict_sm" "strict ServiceMonitor endpoint does not scrape with HTTPS (RUNOPS-004)"
if grep -qE '^[[:space:]]*scheme:[[:space:]]*http[[:space:]]*$' <<<"$strict_sm"; then
  fail "strict/regulated ServiceMonitor rendered scheme=http (WIRE-003)"
fi
need_fixed 'nginx.ingress.kubernetes.io/backend-protocol: "HTTPS"' "$strict_ing" "strict ingress does not use HTTPS to the backend Service (RUNOPS-004)"
need_fixed 'nginx.ingress.kubernetes.io/proxy-ssl-verify: "on"' "$strict_ing" "strict ingress does not verify the backend certificate (CRYPTO-bced5da5)"
need_fixed "nginx.ingress.kubernetes.io/proxy-ssl-secret: \"default/$BACKEND_TLS_SECRET\"" "$strict_ing" "strict ingress does not use the backend CA Secret (CRYPTO-bced5da5)"
need_fixed "nginx.ingress.kubernetes.io/proxy-ssl-name: \"$BACKEND_TLS_SERVER_NAME\"" "$strict_ing" "strict ingress does not verify the backend name (CRYPTO-bced5da5)"
need "name: https" "$strict_ing" "strict ingress backend does not route to the https Service port (RUNOPS-004)"
if render -f "$CHART/values-strict.yaml" --set control.tls.enabled=false >/dev/null 2>&1; then
  fail "strict ServiceMonitor rendered an HTTPS scrape without an HTTPS control listener (RUNOPS-004)"
fi
need "kind: PrometheusRule"         "$strict" "strict profile missing self-alert PrometheusRule (OPS-004)"
need "alert: ProbectlSelfMetricsMissing" "$strict" "strict profile missing self-metrics-missing alert (OPS-004)"
need "alert: ProbectlWritesPaused"  "$strict" "strict profile missing cluster writes-paused alert (OPS-004)"
need "alert: ProbectlDLQGrowth"     "$strict" "strict profile missing DLQ growth alert (RUNOPS-003)"
need "alert: ProbectlBusShedOrHandlerErrors" "$strict" "strict profile missing bus shed/handler-error alert (RUNOPS-003)"
need "alert: ProbectlClickHouseWriteOrBreakerFailures" "$strict" "strict profile missing ClickHouse write/breaker alert (RUNOPS-003)"
need "alert: ProbectlAgentDarkFleet" "$strict" "strict profile missing dark-fleet alert (RUNOPS-003)"
need "alert: ProbectlFairnessShedOrRejected" "$strict" "strict profile missing fairness shed/reject alert (RUNOPS-003)"
need "alert: ProbectlWORMExportGap" "$strict" "strict profile missing WORM export gap alert (RUNOPS-003)"
need "alert: ProbectlWORMSignatureFailures" "$strict" "strict profile missing WORM signature/chain verification alert (RUNOPS-003)"
need "kind: CronJob"                "$strict" "strict profile missing backup CronJob (OPS-009)"
if [ "$(grep -c '^kind: CronJob$' <<<"$strict")" -ne 3 ]; then
  fail "strict profile must render exactly Postgres + ClickHouse + object-store backup CronJobs (H8)"
fi

# 3b. /metrics + backup are chart-managed and gated. Default profile must
#     NOT ship the operator-CRD ServiceMonitor or the opt-in CronJobs.
grep -q "kind: ServiceMonitor" <<<"$base" && fail "ServiceMonitor must be OFF by default (Prometheus-Operator CRD gate)"
grep -q "kind: PrometheusRule" <<<"$base" && fail "PrometheusRule must be OFF by default (Prometheus-Operator CRD gate)"
grep -q "kind: CronJob" <<<"$base" && fail "backup CronJobs must be OFF by default (backup.enabled)"
if render --set backup.enabled=true >/dev/null 2>&1; then
  fail "chart rendered ClickHouse backup without backup.clickhouse.encryptedTargetAck (RED-004)"
fi
backup_render="$(render --set backup.enabled=true --set backup.clickhouse.encryptedTargetAck=encrypted-clickhouse-backup-target)"
need_digest_pinned_control_images "backup chart" "$backup_render" 5
need "kind: CronJob" "$backup_render" "backup.enabled=true must render the backup CronJobs (OPS-009)"
if [ "$(grep -c '^kind: CronJob$' <<<"$backup_render")" -ne 3 ]; then
  fail "backup.enabled=true must render exactly three backup CronJobs (Postgres + ClickHouse + object store, H8)"
fi
need_shellless_control_stagers "backup CronJobs" "$backup_render" 3
if [ "$(grep -F -c 'args: ["stage-binary", "/tools/probectl-control"]' <<<"$backup_render" || true)" -ne 3 ]; then
  fail "all three backup stage-probectl containers must stage /tools/probectl-control"
fi
need ".dump.pbk" "$backup_render" "default Postgres backup must render sealed .dump.pbk artifact (RUNOPS-002)"
need "backup-seal" "$backup_render" "default Postgres backup must stream through backup-seal (RUNOPS-002)"
need "backup.clickhouse.encryptedTargetAck=encrypted-clickhouse-backup-target" "$backup_render" "ClickHouse backup render must carry exact encrypted-target ack (RED-004)"
need 'name}.pbk' "$backup_render" "default ClickHouse backup must render sealed .zip.pbk artifact (CRYPTO-001)"
need "rm -f.*server_backup_path.*name" "$backup_render" "ClickHouse backup must remove raw staging zip after sealing (CRYPTO-001)"
need_fixed "probectl-objectstore-backup" "$backup_render" "object-store backup CronJob is missing (H8)"
need_fixed ".tar.pbk" "$backup_render" "default object-store backup must render a sealed .tar.pbk artifact (H8)"
need_fixed "claimName: \"probectl-objects\"" "$backup_render" "object-store backup must read the operator-supplied source PVC (H8)"
need_fixed "readOnly: true" "$backup_render" "object-store source PVC must be mounted read-only (H8)"
need_fixed "refusing symlink/special object-store entry" "$backup_render" "object-store backup must reject symlinks/special files before archiving (H8)"
if render --set backup.enabled=true --set backup.clickhouse.encryptedTargetAck=encrypted-clickhouse-backup-target --set backup.objectStore.sourceClaim='' >/dev/null 2>&1; then
  fail "chart rendered object-store backup without backup.objectStore.sourceClaim (H8)"
fi
if render --set backup.enabled=true --set backup.clickhouse.encryptedTargetAck=encrypted-clickhouse-backup-target --set backup.encryption.enabled=false >/dev/null 2>&1; then
  fail "chart rendered plaintext Postgres backup without backup.plaintextAck (RUNOPS-002)"
fi
if render --set backup.enabled=true --set backup.clickhouse.encryptedTargetAck=encrypted-clickhouse-backup-target --set backup.encryption.enabled=false --set backup.plaintextAck=allow-plain >/dev/null 2>&1; then
  fail "chart rendered plaintext Postgres backup with misspelled backup.plaintextAck (RUNOPS-002)"
fi
plaintext_backup="$(render --set backup.enabled=true --set backup.clickhouse.encryptedTargetAck=encrypted-clickhouse-backup-target --set backup.encryption.enabled=false --set backup.plaintextAck=allow-plaintext-tenant-backup)"
need ".dump" "$plaintext_backup" "plaintext break-glass render must write .dump artifact (RUNOPS-002)"
need "WARNING writing PLAINTEXT tenant backup" "$plaintext_backup" "plaintext break-glass render must emit warning (RUNOPS-002)"
need "WARNING writing PLAINTEXT object-store/WORM backup" "$plaintext_backup" "plaintext object-store break-glass render must emit warning (H8)"
need "backup.plaintextAck=allow-plaintext-tenant-backup" "$plaintext_backup" "plaintext break-glass render must be searchable by exact ack (RUNOPS-002)"
default_sm="$(render --set metrics.serviceMonitor.enabled=true)"
need "kind: ServiceMonitor" "$default_sm" "metrics.serviceMonitor.enabled=true must render the ServiceMonitor (OPS-005)"
need "port: https" "$default_sm" "default ServiceMonitor must target the default https Service port (CONFIG-aa08042e)"
need "scheme: https" "$default_sm" "default ServiceMonitor must scrape the HTTPS control listener (CONFIG-aa08042e)"
if render --set metrics.serviceMonitor.enabled=true --set metrics.serviceMonitor.scheme=http >/dev/null 2>&1; then
  fail "chart rendered an HTTP ServiceMonitor against the default HTTPS listener (CONFIG-aa08042e)"
fi
need "alert: ProbectlHighGoroutines" "$(render --set metrics.prometheusRule.enabled=true)" "metrics.prometheusRule.enabled=true must render self-alert rules (OPS-004)"
need "alert: ProbectlWORMExportGap" "$(render --set metrics.prometheusRule.enabled=true)" "metrics.prometheusRule.enabled=true must render RUNOPS WORM alert (RUNOPS-003)"

# CONFIG-03870cbe: restore Jobs use the same shell-free distroless control image
# for staging. Render both restore paths so this opt-in surface cannot hide a
# /bin/sh dependency behind its values gates.
restore_render="$(render \
  --set restore.enabled=true \
  --set restore.backupFile=postgres-probectl-test.dump.pbk \
  --set restore.clickhouse.enabled=true \
  --set restore.clickhouse.backupFile=clickhouse-probectl-test.zip.pbk)"
need_digest_pinned_control_images "restore chart" "$restore_render" 4
need_shellless_control_stagers "restore Jobs" "$restore_render" 2
if [ "$(grep -F -c 'args: ["stage-binary", "/shared/probectl-control"]' <<<"$restore_render" || true)" -ne 1 ]; then
  fail "Postgres restore must stage /shared/probectl-control"
fi
if [ "$(grep -F -c 'args: ["stage-binary", "/tools/probectl-control"]' <<<"$restore_render" || true)" -ne 1 ]; then
  fail "ClickHouse restore must stage /tools/probectl-control"
fi

# 3c. CONFIG-09e06212: enabling WORM export always means one persistent claim
# mounted at a canonical path. HA additionally means one externally managed
# signing key shared through the runtime Secret; a per-pod key file is invalid.
if render --set objectStore.enabled=false >/dev/null 2>&1; then
  fail "chart rendered PROBECTL_AUDIT_WORM_DIR without objectStore.enabled=true (CONFIG-09e06212)"
fi
if render --set objectStore.enabled=true --set-string objectStore.existingClaim= >/dev/null 2>&1; then
  fail "chart rendered WORM export onto objectStore emptyDir (CONFIG-09e06212)"
fi
if render --set replicaCount=3 \
    --set-string control.extraEnv.PROBECTL_WORM_SIGNING_KEY_FILE="$OBJECTSTORE_MOUNT/audit-worm/worm-ed25519.pem" \
    >/dev/null 2>&1; then
  fail "chart rendered multi-replica WORM with a pod-local signing-key file (CONFIG-09e06212)"
fi
if render --set replicaCount=1 --set autoscaling.enabled=true \
    --set autoscaling.minReplicas=1 --set autoscaling.maxReplicas=3 \
    --set-string secrets.existingSecret= \
    --set-string control.extraEnv.PROBECTL_WORM_SIGNING_KEY_FILE="$OBJECTSTORE_MOUNT/audit-worm/worm-ed25519.pem" \
    >/dev/null 2>&1; then
  fail "chart rendered autoscaled WORM with no shared Secret and a pod-local signing-key file (CONFIG-09e06212)"
fi
if render --set replicaCount=3 --set-string secrets.existingSecret= >/dev/null 2>&1; then
  fail "chart rendered multi-replica WORM without secrets.existingSecret (CONFIG-09e06212)"
fi
if render --set-string control.extraEnv.PROBECTL_AUDIT_WORM_DIR=/var/lib/probectl/audit-worm >/dev/null 2>&1; then
  fail "chart rendered WORM directory outside objectStore.mountPath (CONFIG-09e06212)"
fi
if render --set-string control.extraEnv.PROBECTL_AUDIT_WORM_DIR="$OBJECTSTORE_MOUNT/../escape" >/dev/null 2>&1; then
  fail "chart rendered a traversal-bearing WORM directory (CONFIG-09e06212)"
fi
if render --set-string control.extraEnv.PROBECTL_AUDIT_WORM_DIR=audit-worm >/dev/null 2>&1; then
  fail "chart rendered a relative WORM directory (CONFIG-09e06212)"
fi

ha_worm="$(render --set replicaCount=3)"
ha_worm_dep="$(awk '/kind: Deployment$/,/^---/' <<<"$ha_worm")"
ha_worm_cm="$(awk '/kind: ConfigMap$/,/^---/' <<<"$ha_worm")"
need_fixed "name: $RUNTIME_SECRET" "$ha_worm_dep" "HA WORM Deployment did not read the shared runtime Secret (CONFIG-09e06212)"
need_fixed "mountPath: \"$OBJECTSTORE_MOUNT\"" "$ha_worm_dep" "HA WORM Deployment did not mount objectStore.mountPath (CONFIG-09e06212)"
need_fixed "claimName: \"$OBJECTSTORE_CLAIM\"" "$ha_worm_dep" "HA WORM Deployment did not mount objectStore.existingClaim (CONFIG-09e06212)"
need_fixed "PROBECTL_AUDIT_WORM_DIR: \"$OBJECTSTORE_MOUNT/audit-worm\"" "$ha_worm_cm" "HA WORM ConfigMap path escaped the shared claim (CONFIG-09e06212)"
if grep -q "PROBECTL_WORM_SIGNING_KEY_FILE" <<<"$ha_worm_cm"; then
  fail "HA WORM ConfigMap still contains a per-pod signing-key file (CONFIG-09e06212)"
fi

# A sovereign single replica may still generate/reuse a stable key file, but
# only while the WORM directory itself is on the required persistent claim.
single_worm_keyfile="$(render --set replicaCount=1 --set-string secrets.existingSecret= \
  --set secrets.envelopeKey="$KEY" --set secrets.sessionHMACKey="$SESSION_KEY" \
  --set-string control.extraEnv.PROBECTL_WORM_SIGNING_KEY_FILE="$OBJECTSTORE_MOUNT/audit-worm/worm-ed25519.pem")"
need_fixed "PROBECTL_WORM_SIGNING_KEY_FILE: \"$OBJECTSTORE_MOUNT/audit-worm/worm-ed25519.pem\"" "$single_worm_keyfile" "single-replica persistent signing-key file support regressed (CONFIG-09e06212)"

# 4. Medium + multi-tenant profiles ship a PodDisruptionBudget (zero-downtime, S34).
for f in values-medium.yaml values-multitenant.yaml; do
  need "kind: PodDisruptionBudget" "$(render -f "$CHART/$f")" "$f missing PodDisruptionBudget"
done

# 4a. TENANT-002: the multi-tenant reference profile must render the
# ClickHouse scoped-reader envs. The binary fails closed without these in
# ClickHouse-backed multi-tenant/regulated profiles; the chart must not make
# operators discover that only at pod startup.
multitenant="$(render -f "$CHART/values-multitenant.yaml")"
need_fixed 'PROBECTL_DEPLOYMENT_PROFILE: "multi-tenant"' "$multitenant" "multi-tenant profile did not render PROBECTL_DEPLOYMENT_PROFILE=multi-tenant (TENANT-002)"
for env in PROBECTL_PATHSTORE_READER_USER PROBECTL_FLOWSTORE_READER_USER PROBECTL_OTELSTORE_READER_USER PROBECTL_EBPFSTORE_READER_USER; do
  need_fixed "$env: \"probectl_reader\"" "$multitenant" "multi-tenant profile did not render $env scoped reader user (TENANT-002)"
done
for env in PROBECTL_AUDIT_WORM_DIR PROBECTL_SIEM_ENABLED PROBECTL_SIEM_ENDPOINT; do
  need_fixed "$env:" "$multitenant" "multi-tenant profile did not render $env audit-retention watermark config (PRIVACY-001)"
done
need_fixed 'PROBECTL_IR_PUBLIC_KEY_DIR: "/var/lib/probectl/objects/ir-keys"' "$multitenant" "multi-tenant profile did not render the IR public keyring the provider plane requires for admission (DPR-011)"
need_fixed "name: $RUNTIME_SECRET" "$multitenant" "multi-tenant profile did not reference the shared runtime Secret (CONFIG-09e06212)"
need_fixed "claimName: \"$OBJECTSTORE_CLAIM\"" "$multitenant" "multi-tenant profile did not mount the shared WORM claim (CONFIG-09e06212)"
if grep -q "PROBECTL_WORM_SIGNING_KEY_FILE" <<<"$multitenant"; then
  fail "multi-tenant profile rendered a per-pod WORM signing-key file (CONFIG-09e06212)"
fi

# 4b. WIRE-001: production-like profiles fail closed on plaintext datastore
#     transport. The config loader enforces this at boot; the chart catches the
#     same operator mistakes while rendering so a bad Secret/ConfigMap is never
#     applied.
if helm template probectl "$CHART" -f "$CHART/values-multitenant.yaml" \
  --set ingress.host=h.example.com \
  --set ingress.tlsSecretName=probectl-tls \
  --set ingress.backendTLS.trustSecret="$BACKEND_TLS_SECRET" \
  --set ingress.backendTLS.serverName="$BACKEND_TLS_SERVER_NAME" \
  --set control.tls.existingSecret="$CONTROL_TLS_SECRET" \
  --set image.digest="$CONTROL_IMAGE_DIGEST" \
  --set secrets.envelopeKey="$KEY" \
  --set secrets.sessionHMACKey="$SESSION_KEY" \
  --set database.url="postgres://probectl:s3cret-not-default@db:5432/probectl?sslmode=disable" >/dev/null 2>&1; then
  fail "chart rendered plaintext multi-tenant database.url (WIRE-001)"
fi
if render -f "$CHART/values-multitenant.yaml" \
     --set-string control.extraEnv.PROBECTL_DATABASE_READ_URL="postgres://probectl_reader:s3cret-not-default@db-ro:5432/probectl?sslmode=prefer" >/dev/null 2>&1; then
  fail "chart rendered plaintext multi-tenant PROBECTL_DATABASE_READ_URL (WIRE-001)"
fi
if render -f "$CHART/values-multitenant.yaml" \
     --set-string control.extraEnv.PROBECTL_FLOWSTORE_URL="http://clickhouse:8123" >/dev/null 2>&1; then
  fail "chart rendered plaintext multi-tenant PROBECTL_FLOWSTORE_URL (WIRE-001)"
fi
if render -f "$CHART/values-multitenant.yaml" \
     --set-string control.extraEnv.PROBECTL_DATAPLANES="us=http://clickhouse-us:8123" >/dev/null 2>&1; then
  fail "chart rendered plaintext multi-tenant PROBECTL_DATAPLANES (WIRE-001)"
fi
multitenant_tls="$(render -f "$CHART/values-multitenant.yaml" \
  --set-string control.extraEnv.PROBECTL_DATABASE_READ_URL="postgres://probectl_reader:s3cret-not-default@db-ro:5432/probectl?sslmode=verify-full" \
  --set-string control.extraEnv.PROBECTL_FLOWSTORE_URL="https://clickhouse:8443" \
  --set-string control.extraEnv.PROBECTL_DATAPLANES="us=https://clickhouse-us:8443")"
need_fixed 'PROBECTL_DATABASE_READ_URL: "postgres://probectl_reader:s3cret-not-default@db-ro:5432/probectl?sslmode=verify-full"' "$multitenant_tls" "multi-tenant profile rejected/rendered wrong TLS read-replica DSN (WIRE-001)"
need_fixed 'PROBECTL_FLOWSTORE_URL: "https://clickhouse:8443"' "$multitenant_tls" "multi-tenant profile rejected/rendered wrong TLS ClickHouse URL (WIRE-001)"
need_fixed 'PROBECTL_DATAPLANES: "us=https://clickhouse-us:8443"' "$multitenant_tls" "multi-tenant profile rejected/rendered wrong TLS dataplane URL (WIRE-001)"

# 5. Every profile lints clean — EVERY values-*.yaml in the chart, so a new
# profile can never ship un-linted by being forgotten here (the strict and
# multiregion profiles once were).
for f in values.yaml $(cd "$CHART" && ls values-*.yaml); do
  helm lint "$CHART" -f "$CHART/$f" \
    --set ingress.host=h.example.com --set ingress.tlsSecretName=probectl-tls \
    --set ingress.backendTLS.trustSecret="$BACKEND_TLS_SECRET" \
    --set ingress.backendTLS.serverName="$BACKEND_TLS_SERVER_NAME" \
    --set control.tls.existingSecret="$CONTROL_TLS_SECRET" \
    --set image.digest="$CONTROL_IMAGE_DIGEST" \
    --set secrets.existingSecret="$RUNTIME_SECRET" \
    --set database.url="postgres://probectl:s3cret-not-default@db:5432/probectl?sslmode=require" \
    --set objectStore.enabled=true \
    --set-string objectStore.mountPath="$OBJECTSTORE_MOUNT" \
    --set-string objectStore.existingClaim="$OBJECTSTORE_CLAIM" \
    --set-string control.extraEnv.PROBECTL_AUDIT_WORM_DIR="$OBJECTSTORE_MOUNT/audit-worm" \
    --set-string control.extraEnv.PROBECTL_SIEM_ENABLED=true \
    --set-string control.extraEnv.PROBECTL_SIEM_ENDPOINT=https://siem.example/ingest \
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
# SUPPLY-001: this privileged chart must render the deployment-time signature
# verifier by default. Digest pinning alone is not provenance; the Kyverno
# ClusterPolicy requires the image digest and the keyless release-workflow
# signature before a Pod is admitted.
need "kind: ClusterPolicy"              "$agent" "agent: image-integrity ClusterPolicy missing (SUPPLY-001)"
need "probectl-agent-image-integrity"   "$agent" "agent: image-integrity policy name missing (SUPPLY-001)"
need "verifyImages:"                    "$agent" "agent: Kyverno verifyImages rule missing (SUPPLY-001)"
need "required: true"                   "$agent" "agent: image signature verification is not required (SUPPLY-001)"
need "verifyDigest: true"              "$agent" "agent: image digest verification is not enforced (SUPPLY-001)"
need "validationFailureAction: Enforce" "$agent" "agent: image-integrity policy is not enforcing (SUPPLY-001)"
need_fixed 'release\\.yml@refs/tags'  "$agent" "agent: release workflow OIDC subject is not pinned (SUPPLY-001)"
need "probectl-agent-capability-posture" "$agent" "agent: capability posture ClusterPolicy missing (EBPF-007)"
need "probectl.dev/finding: EBPF-007"    "$agent" "agent: capability posture policy is not tied to EBPF-007"
need "validationFailureAction: Audit"    "$agent" "agent: capability posture policy must report, not hide, legacy/extra capabilities (EBPF-007)"
need "background: true"                  "$agent" "agent: capability posture policy must scan existing pods (EBPF-007)"
need "AnyNotIn"                          "$agent" "agent: capability posture policy does not check added/dropped capabilities (EBPF-007)"
need "SYS_ADMIN is legacy break-glass"   "$agent" "agent: capability posture policy does not report legacy SYS_ADMIN (EBPF-007)"
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
# OPS-001/WIRE-004: the DaemonSet ships real liveness + readiness probes
# without opening a plaintext health listener by default.
need "livenessProbe:"                   "$agent" "agent: no liveness probe (OPS-001)"
need "readinessProbe:"                  "$agent" "agent: no readiness probe (OPS-001)"
need "exec:"                            "$agent" "agent: default health probe is not exec-based (WIRE-004)"
need "healthcheck"                      "$agent" "agent: exec healthcheck command missing (WIRE-004)"
need "--live"                           "$agent" "agent: liveness exec probe missing --live (WIRE-004)"
need "--ready"                          "$agent" "agent: readiness exec probe missing --ready (WIRE-004)"
need "health_state_dir:"                "$agent" "agent: health state directory not rendered (WIRE-004)"
if grep -q "httpGet:" <<<"$agent"; then
  fail "agent: default chart renders plaintext httpGet health probes (WIRE-004)"
fi
if grep -q "containerPort: 9090" <<<"$agent"; then
  fail "agent: default chart opens plaintext health port 9090 (WIRE-004)"
fi
if helm template agent "$AGENT" --set tenantID=gate --set 'bus.brokers={kafka:9093}' \
     --set-string image.tag="$AGENT_IMAGE_TAG" --set health.mode=http >/dev/null 2>&1; then
  fail "agent chart rendered HTTP health mode without health.allowPlaintextHTTP=true (WIRE-004)"
fi
http_agent="$(arender --set health.mode=http --set health.allowPlaintextHTTP=true)"
need "path: /healthz"                   "$http_agent" "agent: acknowledged HTTP health mode missing /healthz"
need "path: /readyz"                    "$http_agent" "agent: acknowledged HTTP health mode missing /readyz"
# H6: /metrics stays loopback-only unless an operator explicitly enables pod
# scraping with a TLS Secret. A remote plaintext metrics port must never render.
if grep -q "prometheus.io/scrape" <<<"$agent"; then
  fail "agent: default chart advertises a pod-network metrics scrape without TLS opt-in (H6/WIRE-004)"
fi
if helm template agent "$AGENT" --set tenantID=gate --set 'bus.brokers={kafka:9093}' \
     --set-string image.tag="$AGENT_IMAGE_TAG" --set metrics.enabled=true >/dev/null 2>&1; then
  fail "agent chart rendered pod-network metrics without metrics.tls.existingSecret (H6/WIRE-004)"
fi
metrics_agent="$(arender --set metrics.enabled=true --set metrics.tls.existingSecret=agent-metrics-tls)"
need 'prometheus.io/scrape: "true"'      "$metrics_agent" "agent: metrics scrape annotation missing (H6)"
need 'prometheus.io/scheme: "https"'     "$metrics_agent" "agent: metrics scrape is not HTTPS (H6/WIRE-004)"
need 'containerPort: 9467'                "$metrics_agent" "agent: metrics port missing (H6)"
need 'PROBECTL_EBPF_METRICS_ADDR'         "$metrics_agent" "agent: metrics bind configuration missing (H6)"
need 'PROBECTL_EBPF_METRICS_TLS_CERT_FILE' "$metrics_agent" "agent: metrics TLS certificate not wired (H6)"
need 'PROBECTL_EBPF_METRICS_TLS_KEY_FILE' "$metrics_agent" "agent: metrics TLS key not wired (H6)"
need 'secretName: agent-metrics-tls'      "$metrics_agent" "agent: metrics TLS Secret not mounted (H6)"
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
agent_ds="$(awk '/kind: DaemonSet$/,/^---/' <<<"$agent")"
grep -q "SYS_ADMIN" <<<"$agent_ds" && fail "agent: SYS_ADMIN in the DEFAULT DaemonSet (legacy mode only)"
if helm template agent "$AGENT" --set tenantID=gate --set 'bus.brokers={kafka:9093}' \
     --set-string image.tag="$AGENT_IMAGE_TAG" --set capabilityMode=legacy >/dev/null 2>&1; then
  fail "agent chart rendered legacy SYS_ADMIN without legacyKernelRingBufferAck (EBPF-004)"
fi
legacy="$(arender --set capabilityMode=legacy --set legacyKernelRingBufferAck=i-confirm-runtime-ring-buffer-support)"
need "SYS_ADMIN" "$legacy" "agent: acknowledged legacy mode missing SYS_ADMIN"
need "probectl-agent-capability-posture" "$legacy" "agent: acknowledged legacy mode lost capability posture audit policy (EBPF-007)"
need "validationFailureAction: Audit" "$legacy" "agent: acknowledged legacy mode must still report capability posture (EBPF-007)"

# fail-closed rendering: no tenant, or plaintext kafka without the explicit
# dev override, must refuse (guardrail 1 / U-010).
if helm template agent "$AGENT" --set-string image.tag="$AGENT_IMAGE_TAG" >/dev/null 2>&1; then
  fail "agent chart rendered WITHOUT a tenantID"
fi
if helm template agent "$AGENT" --set tenantID=t --set 'bus.brokers={k:9093}' --set-string image.tag="0.4.0" >/dev/null 2>&1; then
  fail "agent chart rendered a privileged tag-only image without image.allowTagOnly=true (RED-003)"
fi
if helm template agent "$AGENT" --set tenantID=t --set 'bus.brokers={k:9093}' \
     --set image.allowTagOnly=true --set-string image.tag=0.4.0 >/dev/null 2>&1; then
  fail "agent chart rendered tag-only break-glass while image-integrity admission stayed enabled (SUPPLY-001)"
fi
if helm template agent "$AGENT" --set tenantID=t --set 'bus.brokers={k:9093}' \
     --set admission.imageIntegrity.enabled=false --set-string image.tag="$AGENT_IMAGE_TAG" >/dev/null 2>&1; then
  fail "agent chart disabled image-integrity admission without admission.imageIntegrity.acceptedRisk (SUPPLY-001)"
fi
if helm template agent "$AGENT" --set tenantID=t --set 'bus.brokers={k:9093}' \
     --set admission.imageIntegrity.validationFailureAction=Audit \
     --set-string image.tag="$AGENT_IMAGE_TAG" >/dev/null 2>&1; then
  fail "agent chart rendered non-enforcing image-integrity admission without admission.imageIntegrity.acceptedRisk (RED-003)"
fi
tag_break_glass="$(arender \
  --set image.allowTagOnly=true \
  --set-string image.tag=0.4.0 \
  --set admission.imageIntegrity.enabled=false \
  --set-string admission.imageIntegrity.acceptedRisk=dev-registry-has-equivalent-admission-control)"
need "probectl-ebpf-agent:0.4.0" "$tag_break_glass" "agent: tag-only break-glass render failed"
grep -q "probectl-agent-image-integrity" <<<"$tag_break_glass" && fail "agent: accepted tag-only break-glass still rendered the image-integrity Kyverno verifier"
need "probectl-agent-capability-posture" "$tag_break_glass" "agent: tag-only break-glass lost capability posture audit policy (EBPF-007)"
audit_break_glass="$(arender \
  --set admission.imageIntegrity.validationFailureAction=Audit \
  --set-string admission.imageIntegrity.acceptedRisk=dev-registry-has-equivalent-admission-control)"
need "validationFailureAction: Audit" "$audit_break_glass" "agent: accepted non-enforcing image-integrity render failed"
if helm template agent "$AGENT" --set tenantID=t --set 'bus.brokers={k:9092}' \
     --set-string image.tag="$AGENT_IMAGE_TAG" --set bus.tls.enabled=false >/dev/null 2>&1; then
  fail "agent chart rendered plaintext kafka without bus.allowPlaintext"
fi


# DPR-026: an operator CA bundle for OUTBOUND TLS (private-PKI IdP, SIEM, CMDB,
# managed Postgres with sslmode=verify-*) is a typed value, mounted read-only
# into both the migrate init container and control, and absent by default.
base_tb="$(render)"
if grep -q 'SSL_CERT_FILE' <<<"$base_tb"; then
  fail "SSL_CERT_FILE must not be set unless control.trustBundle.existingConfigMap is named (DPR-026)"
fi
tb="$(render --set control.trustBundle.existingConfigMap=probectl-trust-bundle)"
[ "$(grep -c 'name: SSL_CERT_FILE' <<<"$tb")" -eq 2 ] \
  || fail "control.trustBundle must set SSL_CERT_FILE on the migrate init container AND the control container (DPR-026)"
need_fixed 'value: "/etc/probectl/trust/ca-bundle.crt"' "$tb" "control.trustBundle must point SSL_CERT_FILE at <mountPath>/<key> (DPR-026)"
[ "$(grep -c 'name: trust-bundle' <<<"$tb")" -eq 3 ] \
  || fail "control.trustBundle must render two mounts and one ConfigMap volume named trust-bundle (DPR-026)"
need_fixed 'name: "probectl-trust-bundle"' "$tb" "control.trustBundle volume must reference the named ConfigMap (DPR-026)"
[ "$(grep -c 'mountPath: "/etc/probectl/trust"' <<<"$tb")" -eq 2 ] \
  || fail "control.trustBundle mounts must use the configured mountPath on both containers (DPR-026)"
if render --set-string control.extraEnv.SSL_CERT_FILE=/tmp/x >/dev/null 2>&1; then
  fail "control.extraEnv.SSL_CERT_FILE must be rejected: the trust bundle is a typed value (DPR-026)"
fi

# DPR-032: the backend hop must negotiate TLS 1.3, the only version the control
# listener accepts; without the annotation ingress-nginx offers TLS 1.2 and
# every request through the chart's own ingress is a 502.
need_fixed 'nginx.ingress.kubernetes.io/proxy-ssl-protocols: "TLSv1.3"' "$base_tb" "ingress must pin the backend hop to TLS 1.3, the control listener minimum (DPR-032)"

# DPR-030: credential FILES (basic-auth JSON, broker client keys) are staged by
# the binary into a private in-memory volume as 0600 regular files before
# migrate and control start; absent by default.
if grep -q 'stage-credentials' <<<"$base_tb"; then
  fail "stage-credentials must not render unless control.credentialFiles.existingSecret is named (DPR-030)"
fi
cf="$(render --set control.credentialFiles.existingSecret=probectl-store-credentials)"
need_fixed 'args: ["stage-credentials", "/etc/probectl/credentials-source", "/etc/probectl/credentials"]' "$cf" "control.credentialFiles must render the stage-credentials init container (DPR-030)"
need_fixed 'secretName: "probectl-store-credentials"' "$cf" "control.credentialFiles must mount the named Secret as the staging source (DPR-030)"
need_fixed 'medium: Memory' "$cf" "staged credentials must live in a memory-backed volume (DPR-030)"
[ "$(grep -c 'mountPath: "/etc/probectl/credentials"' <<<"$cf")" -eq 3 ] \
  || fail "credential volume must be mounted by stage-credentials (rw), migrate and control (ro) (DPR-030)"
if ! grep -B4 'name: stage-credentials' <<<"$cf" | grep -q 'initContainers:'; then
  fail "stage-credentials must be the first init container so migrate can already read the files (DPR-030)"
fi

echo "helm hardening gate: OK (control plane + agent charts)"
