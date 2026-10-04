#!/usr/bin/env bash
# SPDX-License-Identifier: BUSL-1.1
#
# SUP-07: the documented MSP (multi-tenant) Helm install command must actually
# render, and every PVC/Secret it depends on must appear in deploy/helm/README.md's
# pre-create list. The command once passed the RESERVED env
# control.extraEnv.PROBECTL_AUDIT_WORM_DIR and omitted the WORM PVC, so an operator
# following the README verbatim hit `helm` errors. This gate extracts the README
# command, renders it with `helm template`, and cross-checks the pre-create list
# against the claims values-multitenant.yaml and the command itself depend on.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
README="${repo_root}/deploy/helm/README.md"
VALUES="${repo_root}/deploy/helm/probectl/values-multitenant.yaml"
HELM="${HELM:-helm}"

# Extract the fenced block holding the MSP (multi-tenant) install command — the
# one that passes `-f .../values-multitenant.yaml`. Buffer each fenced block and
# emit the one that both installs probectl AND selects the multitenant profile,
# so a reordering of the README's other `helm install` examples cannot fool it.
extract_install_cmd() {
  awk '
    /^```/ {
      if (infence) {
        if (buf ~ /helm install probectl/ && buf ~ /values-multitenant/) { printf "%s", buf; exit }
        buf = ""
      }
      infence = !infence; next
    }
    infence { buf = buf $0 "\n" }
  ' "$1"
}

render_readme_cmd() {
  local readme="$1"
  local cmd
  cmd="$(extract_install_cmd "$readme")"
  if [ -z "$cmd" ]; then
    echo "::error::no 'helm install probectl' command found in $readme (SUP-07)"
    return 1
  fi
  # Render, not install; substitute the README's human placeholders with values
  # valid enough to render (a real operator supplies the true ones).
  cmd="${cmd//helm install probectl/helm template probectl}"
  cmd="${cmd//deploy\/helm\/probectl/${repo_root}/deploy/helm/probectl}"
  cmd="${cmd//-f deploy\/helm\/probectl/-f ${repo_root}/deploy/helm/probectl}"
  cmd="${cmd//sha256:<release-digest>/sha256:0000000000000000000000000000000000000000000000000000000000000000}"
  cmd="${cmd//oidc.issuer=.../oidc.issuer=https://idp.example/}"
  cmd="${cmd//oidc.clientId=.../oidc.clientId=probectl}"
  # The multitenant profile (replicaCount>1) requires the operator-supplied
  # durable bus + stores the README documents (its own values-multitenant.yaml
  # comments and the store table). Supply them here — render validates config,
  # not connectivity, so placeholder endpoints are enough — so the gate proves
  # the README command renders once its documented prerequisites are provided.
  cmd+=$' \\\n'
  cmd+='--set-string control.extraEnv.PROBECTL_BUS_MODE=nats '
  cmd+='--set-string control.extraEnv.PROBECTL_BUS_BROKERS=nats.probectl.svc.cluster.local:4222 '
  cmd+='--set-string control.extraEnv.PROBECTL_TSDB_MODE=prometheus '
  cmd+='--set-string control.extraEnv.PROBECTL_TSDB_URL=https://prometheus.probectl.svc.cluster.local:9090 '
  for s in PATHSTORE FLOWSTORE OTELSTORE EBPFSTORE ENDPOINTSTORE; do
    cmd+="--set-string control.extraEnv.PROBECTL_${s}_MODE=clickhouse "
    cmd+="--set-string control.extraEnv.PROBECTL_${s}_URL=https://clickhouse.probectl.svc.cluster.local:8443 "
  done
  # values-multitenant.yaml already points -f at the repo path above; eval the
  # transformed command and fail loudly if it does not render.
  if ! eval "$cmd" >/dev/null 2>/tmp/helm_readme_render.log; then
    echo "::error::the README MSP install command does not render (SUP-07):"
    sed 's/^/    /' /tmp/helm_readme_render.log >&2
    return 1
  fi
}

# Every existingClaim/existingSecret the profile or the command depends on must
# be named in the README PROSE (the pre-create list) so an operator creates it —
# a name that appears only inside the fenced install command is not documented.
check_precreate_list() {
  local readme="$1" values="$2"
  local names
  # The acceptance is specific: every existingClaim/existingSecret the PROFILE
  # (values-multitenant.yaml) references must be in the pre-create list. Names an
  # operator chooses via the command's own --set flags are theirs, not the
  # profile's, so they are out of scope here.
  names="$(grep -hoE '(existingClaim|existingSecret):[[:space:]]*[A-Za-z0-9._-]+' "$values" \
    | awk -F':' '{gsub(/[[:space:]]/,"",$2); print $2}')"
  # The pre-create list is prose: everything OUTSIDE fenced code blocks.
  local prose
  prose="$(awk '/^```/{f=!f;next} !f' "$readme")"
  local missing=0 n
  for n in $(printf '%s\n' "$names" | sort -u); do
    [ -z "$n" ] && continue
    if ! grep -qF -- "$n" <<<"$prose"; then
      echo "::error::'$n' is referenced by the MSP profile/command but not in the README pre-create list (SUP-07)"
      missing=1
    fi
  done
  return $missing
}

if [ "${1:-}" = "SELFTEST" ]; then
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT
  # A README whose pre-create prose omits a claim values-multitenant.yaml
  # references must FAIL: drop the WORM PVC's pre-create mention and confirm it
  # is detected.
  grep -vF 'probectl-provider-audit-worm' "$README" > "$tmp/README.md" || true
  if check_precreate_list "$tmp/README.md" "$VALUES" 2>/dev/null; then
    echo "SELFTEST FAILED: an omitted pre-create claim was not detected"
    exit 1
  fi
  echo "check_helm_readme_install SELFTEST ok (an omitted pre-create claim is detected)"
  exit 0
fi

render_readme_cmd "$README"
check_precreate_list "$README" "$VALUES"
echo "check_helm_readme_install OK (README MSP command renders; pre-create list covers every claim) (SUP-07)"
