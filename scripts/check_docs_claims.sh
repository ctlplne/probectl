#!/usr/bin/env bash
# check_docs_claims.sh — docs/claims drift gate (DOCS-S01..S14, SEC-004).
#
# The audit confirmed a set of HONEST-CLAIM strengths: the default AI is the
# air-gapped builtin, there is no vendor-telemetry egress in the source, no
# remediation executor exists, performance numbers are labeled illustrative /
# pending (never fabricated), there are no marketing boasts, and SECURITY.md
# now scopes provider-operator abuse as in-scope. This gate fails if any of
# those properties silently regresses — i.e. if a future change re-introduces
# a phone-home default, a remediation executor, a fabricated SLA, or drops the
# provider-operator scope language.
#
# Dependency-free string/grep assertions. SELFTEST proves each assertion can
# fail (anti-vacuous-green): it points the checks at a synthetic bad fixture.
set -euo pipefail
cd "$(dirname "$0")/.."

fail=0
err() { echo "::error::docs-claims: $*" >&2; fail=1; }

ROOT="${1:-.}"
if [ "$ROOT" = "SELFTEST" ]; then ROOT=""; fi  # handled below

run_checks() { # run_checks <root>
  local r="$1"
  local f=0

  # DOCS-S01: default AI is the builtin (air-gapped); remote egress is gated.
  if ! grep -q 'NewBuiltinModel' "$r/internal/control/ai.go" 2>/dev/null \
     || ! grep -q 'AIModelEnabled' "$r/internal/control/ai.go" 2>/dev/null; then
    echo "DOCS-S01: internal/control/ai.go must default to NewBuiltinModel gated by AIModelEnabled" >&2; f=1
  fi

  # DOCS-S02: no DEFAULT vendor-telemetry egress. The only allowed string-match
  # of a vendor name in non-test Go is as a configurable PROVIDER enum value
  # (builtin is the default) — never a hardcoded outbound beacon. Flag any
  # analytics/beacon SDK import.
  if grep -rniE 'posthog|sentry-go|segment\.io|datadoghq|newrelic|"https://api\.(anthropic|openai)' \
       "$r/internal" "$r/cmd" "$r/pkg" --include='*.go' 2>/dev/null \
       | grep -viE '_test\.go|/gen/' | grep -q .; then
    echo "DOCS-S02: vendor analytics/beacon SDK or hardcoded vendor egress URL found in source" >&2; f=1
  fi

  # DOCS-S04: no remediation executor. The product is observe-only / human-gated;
  # there must be no function that applies a route / opens an SSH session to a
  # device to enact a change.
  if grep -rniE 'func[^/]*\b(Apply|Enact|Push)Remediation|ssh\.Dial\(|netconf\.(Edit|Commit)' \
       "$r/internal" "$r/ee" "$r/cmd" --include='*.go' 2>/dev/null \
       | grep -viE '_test\.go' | grep -q .; then
    echo "DOCS-S04: a remediation executor (route-apply / ssh / netconf-commit) appeared — product is observe-only" >&2; f=1
  fi

  # DOCS-S05/S06: performance numbers stay labeled illustrative/pending, never
  # presented as measured SLAs. The bench floor (20k eps) must still exist.
  if ! grep -qE '20_000|20000' "$r/internal/ebpf/bench_test.go" 2>/dev/null; then
    echo "DOCS-S05: the eBPF bench floor (20k eps) guard disappeared" >&2; f=1
  fi
  if [ -f "$r/docs/agent-overhead.md" ] \
     && ! grep -qiE 'illustrative|reference hardware|smoke' "$r/docs/agent-overhead.md"; then
    echo "DOCS-S05: docs/agent-overhead.md no longer frames its numbers as illustrative" >&2; f=1
  fi

  # DOCS-S10: eval dev-auth stays build-tag-gated.
  if [ -f "$r/internal/control/devauth.go" ] \
     && ! grep -q '//go:build devauth' "$r/internal/control/devauth.go"; then
    echo "DOCS-S10: internal/control/devauth.go lost its //go:build devauth tag" >&2; f=1
  fi

  # DOCS-S13: no marketing boasts (customer counts / SLA promises / battle-tested)
  # in README. (Docs that legitimately discuss MSP "customers" are excluded by
  # checking README only for the boast patterns.)
  if grep -rniE 'battle.?tested|trusted by [0-9]|[0-9]+\+? (customers|enterprises) (trust|use)|99\.9+% uptime guarantee' \
       "$r/README.md" 2>/dev/null | grep -q .; then
    echo "DOCS-S13: a marketing boast (customer count / uptime guarantee / battle-tested) appeared in README" >&2; f=1
  fi

  # DOCS-S14: README keeps an explicit "What probectl is not" section.
  if [ -f "$r/README.md" ] && ! grep -qi 'What probectl is not' "$r/README.md"; then
    echo "DOCS-S14: README lost its 'What probectl is not' section" >&2; f=1
  fi

  # SEC-004: SECURITY.md scopes provider-operator break-glass abuse as in-scope.
  if [ -f "$r/SECURITY.md" ] \
     && ! grep -qi 'break-glass-gate bypass' "$r/SECURITY.md"; then
    echo "SEC-004: SECURITY.md no longer names provider-operator break-glass abuse as in-scope" >&2; f=1
  fi

  return $f
}

if [ "${1:-}" = "SELFTEST" ]; then
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT
  # Build a deliberately-bad fixture missing every guarded property.
  mkdir -p "$tmp/internal/control" "$tmp/internal/ebpf"
  echo 'package control' > "$tmp/internal/control/ai.go"   # no NewBuiltinModel
  echo 'package control' > "$tmp/internal/control/devauth.go" # no build tag
  echo 'package ebpf' > "$tmp/internal/ebpf/bench_test.go"  # no floor
  printf 'trusted by 500 enterprises use this; 99.9%% uptime guarantee\n' > "$tmp/README.md" # boast, no "is not"
  echo '# scope' > "$tmp/SECURITY.md"                       # no break-glass scope
  if run_checks "$tmp" 2>/dev/null; then
    echo "SELFTEST FAILED: docs-claims gate passed a deliberately-bad fixture" >&2
    exit 1
  fi
  echo "check_docs_claims SELFTEST OK (bad fixture correctly rejected)"
  exit 0
fi

run_checks "." || fail=1
if [ "$fail" -ne 0 ]; then exit 1; fi
echo "check_docs_claims: all honest-claim properties hold (DOCS-S01..S14, SEC-004)"
