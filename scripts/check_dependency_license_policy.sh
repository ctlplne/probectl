#!/usr/bin/env bash
# Enforce the commercial/self-hosted dependency boundary without adding a
# license-scanner dependency. The generated inventory remains the detailed
# source of truth; this gate catches license families that always require an
# explicit architecture + legal decision before they can ship.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
inventory="$root/docs/third-party-licenses.md"

inventory_violations() {
  local source="${1:?inventory path}"
  awk -F '|' '
    function trim(value) {
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)
      return value
    }
    /^\|/ {
      ecosystem = trim($2)
      package_name = trim($3)
      scope = tolower(trim($5))
      license_name = toupper(trim($6))
      if (scope !~ /runtime/) next
      if (license_name ~ /UNKNOWN|AGPL|(^|[^A-Z])GPL|LGPL|SSPL|BUSL|(^|[^A-Z])BSL|COMMONS CLAUSE|ELASTIC LICENSE|PROPRIETARY/) {
        print ecosystem " " package_name " (" trim($6) ")"
      }
    }
  ' "$source"
}

# DPR-208: without this the gate FAILS OPEN. runtime_ref_violations swallows
# stderr and falls back to `|| true`, so on a machine with no ripgrep it returned
# no violations and the policy passed having scanned nothing at all. That is how
# a supply-chain licence gate stops being a gate. The selftest caught it as
# "Grafana runtime was not rejected" — the planted violation could not be seen
# either — and the same absence takes delivery-audit-gate down.
require_ripgrep() {
  command -v rg >/dev/null 2>&1 || {
    echo "dependency-license-policy: ripgrep (rg) is required and not installed — refusing to report a clean scan it never ran" >&2
    exit 127
  }
}

runtime_ref_violations() {
  local scan_root="${1:?scan root}"
  rg -n -i \
    --glob '!check_dependency_license_policy.sh' \
    'grafana/(grafana|grafana-enterprise)(:|@|[[:space:]"'\''])' \
    "$scan_root/.github" "$scan_root/deploy" "$scan_root/scripts" "$scan_root/Makefile" \
    2>/dev/null || true
}

# Top level on purpose: runtime_ref_violations runs inside a pipeline, and an
# exit from there ends only that subshell — the caller would carry on and report
# a misleading "not rejected" instead of "the tool is missing".
require_ripgrep

if [ "${SELFTEST:-0}" = "1" ]; then
  fixture="$(mktemp -d "${TMPDIR:-/tmp}/probectl-license-policy.XXXXXX")"
  trap 'rm -rf "$fixture"' EXIT
  mkdir -p "$fixture/deploy"
  printf '%s\n' \
    '| Ecosystem | Package / module | Version | Scope | License (detected) | Evidence |' \
    '| go | `safe` | v1 | runtime | MIT | fixture |' \
    > "$fixture/inventory.md"
  [ -z "$(inventory_violations "$fixture/inventory.md")" ] || {
    echo "dependency-license-policy SELFTEST: permissive runtime was rejected" >&2
    exit 1
  }
  printf '%s\n' '| go | `bad` | v1 | runtime | AGPL-3.0 | fixture |' >> "$fixture/inventory.md"
  inventory_violations "$fixture/inventory.md" | grep -q 'bad' || {
    echo "dependency-license-policy SELFTEST: AGPL runtime was not rejected" >&2
    exit 1
  }
  printf '%s\n' 'services: { dashboard: { image: "grafana/grafana:latest" } }' \
    > "$fixture/deploy/compose.yml"
  runtime_ref_violations "$fixture" | grep -q 'grafana/grafana' || {
    echo "dependency-license-policy SELFTEST: Grafana runtime was not rejected" >&2
    exit 1
  }
  echo "dependency-license-policy SELFTEST: OK (planted AGPL + Grafana runtime rejected)"
  exit 0
fi

if [ ! -f "$inventory" ]; then
  echo "dependency-license-policy: missing generated inventory: $inventory" >&2
  exit 1
fi

violations="$(inventory_violations "$inventory")"
if [ -n "$violations" ]; then
  echo "dependency-license-policy: runtime dependency requires explicit product-owner + legal approval:" >&2
  printf '%s\n' "$violations" >&2
  exit 1
fi

# Grafana-compatible HTTP is first-party code. A Grafana runtime is not. Keep
# container/image references out of every shipping or CI surface; optional
# operator configuration examples under deploy/grafana remain valid.
runtime_ref="$(runtime_ref_violations "$root")"
if [ -n "$runtime_ref" ]; then
  echo "dependency-license-policy: Grafana runtime/container reference is forbidden by the native-surface contract:" >&2
  printf '%s\n' "$runtime_ref" >&2
  exit 1
fi

echo "dependency-license-policy: OK (no unapproved strong-copyleft runtime; no Grafana runtime)"
