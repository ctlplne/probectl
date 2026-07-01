#!/usr/bin/env bash
# check_docs_claims.sh — docs/claims drift gate (DOCS-S01..S15, SEC-004).
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

  # DOCS-S03 / DOCS-004: README and AI docs claim cited, caller-scoped RCA; the
  # code backing that claim must still be the default in-process builtin plus a
  # fail-closed egress gate for any explicit remote model path.
  if ! grep -q 'cited evidence' "$r/README.md" 2>/dev/null \
     || ! grep -q 'caller is allowed to see' "$r/README.md" 2>/dev/null; then
    echo "DOCS-S03: README must keep the AI claim cited and scoped to what the caller may see" >&2; f=1
  fi
  if ! grep -qE 'no network call, no phone-home|no network; also' "$r/docs/ai-rca.md" 2>/dev/null \
     || ! grep -q 'NewBuiltinModel' "$r/internal/ai/eval/eval.go" 2>/dev/null \
     || ! grep -q 'network, no phone-home' "$r/internal/ai/model_builtin.go" 2>/dev/null \
     || ! grep -q 'ErrEgressDenied' "$r/internal/ai/egressgate.go" 2>/dev/null; then
    echo "DOCS-S03: AI/RCA docs must be backed by builtin no-phone-home implementation and fail-closed egress gate" >&2; f=1
  fi

  # DOCS-S04: no remediation executor. The product is observe-only / human-gated;
  # there must be no function that applies a route / opens an SSH session to a
  # device to enact a change.
  if grep -rniE 'func[^/]*\b(Apply|Enact|Push)Remediation|ssh\.Dial\(|netconf\.(Edit|Commit)' \
       "$r/internal" "$r/ee" "$r/cmd" --include='*.go' 2>/dev/null \
       | grep -viE '_test\.go' | grep -q .; then
    echo "DOCS-S04: a remediation executor (route-apply / ssh / netconf-commit) appeared — product is observe-only" >&2; f=1
  fi

  # DOCS-S05: the eBPF userspace bench floor (20k eps) must still exist.
  if ! grep -qE '20_000|20000' "$r/internal/ebpf/bench_test.go" 2>/dev/null; then
    echo "DOCS-S05: the eBPF bench floor (20k eps) guard disappeared" >&2; f=1
  fi

  # DOCS-S06: performance/scale numbers stay labeled as smoke/reference/
  # illustrative, never as measured customer SLAs or invoice-accurate numbers.
  if [ -f "$r/docs/agent-overhead.md" ] \
     && ! grep -qiE 'illustrative|reference hardware|smoke' "$r/docs/agent-overhead.md"; then
    echo "DOCS-S06: docs/agent-overhead.md no longer frames its numbers as illustrative/reference/smoke" >&2; f=1
  fi
  if ! grep -qi 'illustrative, not guarantees' "$r/docs/perf-baseline.md" 2>/dev/null \
     || ! grep -qi 'not a platform promise' "$r/docs/capacity.md" 2>/dev/null \
     || ! grep -qi 'not a reconciliation of your actual invoice' "$r/docs/finops.md" 2>/dev/null; then
    echo "DOCS-S06: performance/cost docs must frame numbers as illustrative, reference/smoke, or non-invoice estimates" >&2; f=1
  fi

  # DOCS-S07: NDR-lite claims remain confidence-scored signals, not IPS blocks.
  if ! grep -q 'confidence-scored signals' "$r/docs/ndr.md" 2>/dev/null \
     || ! grep -q 'detector.confidence' "$r/internal/threat/ndr.go" 2>/dev/null \
     || ! grep -q 'Confidence int' "$r/internal/threat/model.go" "$r/internal/threat/detections.go" 2>/dev/null; then
    echo "DOCS-S07: NDR-lite docs/code must keep confidence-scored signal evidence" >&2; f=1
  fi

  # DOCS-S08: limitations/non-goals stay explicit and not accidentally served.
  if ! grep -q 'plugin/detection marketplace' "$r/docs/limitations.md" 2>/dev/null \
     || ! grep -q 'inline IPS/firewall' "$r/docs/limitations.md" 2>/dev/null \
     || ! grep -q 'autonomous remediation' "$r/docs/limitations.md" 2>/dev/null \
     || ! grep -q 'vendor-hosted public SaaS' "$r/docs/limitations.md" 2>/dev/null \
     || ! grep -q 'F49 .*marketplace.*limitations.md' "$r/docs/features.md" 2>/dev/null; then
    echo "DOCS-S08: limitations/features docs must keep marketplace/IPS/autonomous-remediation/SaaS non-goals explicit" >&2; f=1
  fi
  if grep -rniE '/v1/(marketplace|plugins)\b' "$r/internal/control" --include='*.go' 2>/dev/null | grep -q .; then
    echo "DOCS-S08: a marketplace/plugins control-plane route appeared despite the non-goal claim" >&2; f=1
  fi

  # DOCS-S09: OTLP export remains operator-configured, not a hardcoded egress
  # path. Empty endpoints must fail closed.
  if ! grep -q 'ExporterConfig' "$r/internal/otel/otlp/exporter.go" 2>/dev/null \
     || ! grep -q 'requires an endpoint URL' "$r/internal/otel/otlp/exporter.go" 2>/dev/null \
     || grep -qE 'https://(api\.|otel\.|telemetry\.)' "$r/internal/otel/otlp/exporter.go" 2>/dev/null; then
    echo "DOCS-S09: OTLP exporter must stay operator-configured with no hardcoded telemetry endpoint" >&2; f=1
  fi

  # DOCS-S10: eval dev-auth stays build-tag-gated.
  if [ -f "$r/internal/control/devauth.go" ] \
     && ! grep -q '//go:build devauth' "$r/internal/control/devauth.go"; then
    echo "DOCS-S10: internal/control/devauth.go lost its //go:build devauth tag" >&2; f=1
  fi

  # DOCS-S11: release CI still proves devauth is physically absent from release
  # binaries, not merely hidden behind config.
  if ! grep -q 'no-devauth-in-release' "$r/.github/workflows/ci.yml" 2>/dev/null \
     || ! grep -q 'release binary contains dev-auth principal implementation' "$r/.github/workflows/ci.yml" 2>/dev/null \
     || ! grep -q 'release binary STARTED in dev mode' "$r/.github/workflows/ci.yml" 2>/dev/null \
     || ! grep -q 'no-devauth-in-release' "$r/docs/ci-pipeline.md" 2>/dev/null; then
    echo "DOCS-S11: CI/docs must keep the no-devauth-in-release binary guard" >&2; f=1
  fi

  # DOCS-S12: the docs-claims gate itself is wired into local lint, CI, and the
  # CI-pipeline docs so it cannot become an optional manual check.
  if ! grep -q 'check_docs_claims.sh SELFTEST && .*check_docs_claims.sh' "$r/Makefile" 2>/dev/null \
     || ! grep -q 'check_docs_claims.sh SELFTEST && .*check_docs_claims.sh' "$r/.github/workflows/ci.yml" 2>/dev/null \
     || ! grep -q 'check_docs_claims.sh' "$r/docs/ci-pipeline.md" 2>/dev/null; then
    echo "DOCS-S12: docs-claims gate must be wired into Makefile, CI, and docs/ci-pipeline.md" >&2; f=1
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

  # DOCS-S15: built-not-yet-served limitations stay canonical. Feature pages may
  # state local caveats, but the durable denominator lives in docs/limitations.md.
  local limits="$r/docs/limitations.md"
  if ! grep -q '## Built, not yet served edges' "$limits" 2>/dev/null \
     || ! grep -q 'Chaos injector API/control-plane surface' "$limits" 2>/dev/null \
     || ! grep -q 'eBPF TLS posture ingest' "$limits" 2>/dev/null \
     || ! grep -q 'Raw eBPF flow retention' "$limits" 2>/dev/null \
     || ! grep -q 'Browser artifact S3 / MinIO backend' "$limits" 2>/dev/null; then
    echo "DOCS-S15: docs/limitations.md must keep the canonical built-not-yet-served table" >&2; f=1
  fi
  if ! grep -q '../limitations.md#built-not-yet-served-edges' "$r/docs/features/cost-slo-and-chaos.md" 2>/dev/null \
     || ! grep -q 'limitations.md#built-not-yet-served-edges' "$r/docs/tls-observability.md" 2>/dev/null \
     || ! grep -q 'limitations.md#built-not-yet-served-edges' "$r/docs/deploying-agents.md" 2>/dev/null \
     || ! grep -q 'limitations.md#built-not-yet-served-edges' "$r/docs/browser-synthetic.md" 2>/dev/null; then
    echo "DOCS-S15: built-not-yet-served feature caveats must link to docs/limitations.md" >&2; f=1
  fi
  local disclosure_hits hit file
  disclosure_hits="$(grep -RniE 'not wired|not shipped yet|not exposed|not reachable' "$r/docs" --include='*.md' 2>/dev/null || true)"
  while IFS= read -r hit; do
    [ -n "$hit" ] || continue
    file="${hit%%:*}"
    case "$file" in
      "$r/docs/limitations.md")
        continue
        ;;
      # Runtime deployment state flags, not library-only product edges.
      "$r/docs/carbon.md"|"$r/docs/slo.md"|"$r/docs/features/topology-and-change.md"|"$r/docs/journeys/alert-to-root-cause.md")
        continue
        ;;
      # Config/hardening caveats: not buyer-relevant served-vs-library claims.
      "$r/docs/configuration.md"|"$r/docs/features/alerting-and-incidents.md")
        continue
        ;;
    esac
    if ! grep -q 'limitations.md#built-not-yet-served-edges' "$file" 2>/dev/null; then
      echo "DOCS-S15: buyer-relevant built-not-yet-served disclosure lacks a docs/limitations.md backlink: $hit" >&2; f=1
    fi
  done <<<"$disclosure_hits"

  # SEC-004: SECURITY.md scopes provider-operator break-glass abuse as in-scope.
  if [ -f "$r/SECURITY.md" ] \
     && ! grep -qi 'break-glass-gate bypass' "$r/SECURITY.md"; then
    echo "SEC-004: SECURITY.md no longer names provider-operator break-glass abuse as in-scope" >&2; f=1
  fi

  return $f
}

write_good_fixture() { # write_good_fixture <dir>
  local d="$1"
  mkdir -p \
    "$d/.github/workflows" \
    "$d/cmd" "$d/ee" "$d/internal/ai/eval" "$d/internal/control" \
    "$d/internal/ebpf" "$d/internal/otel/otlp" "$d/internal/threat" \
    "$d/pkg" "$d/docs/features"

  cat > "$d/internal/control/ai.go" <<'EOF'
package control
var _ = NewBuiltinModel
var _ = AIModelEnabled
EOF
  cat > "$d/README.md" <<'EOF'
# probectl
cited evidence stays scoped to what the caller is allowed to see.
## What probectl is not
EOF
  cat > "$d/docs/ai-rca.md" <<'EOF'
Default RCA uses no network call, no phone-home.
EOF
  cat > "$d/internal/ai/eval/eval.go" <<'EOF'
package eval
var _ = NewBuiltinModel
EOF
  cat > "$d/internal/ai/model_builtin.go" <<'EOF'
package ai
// builtin model: network, no phone-home
EOF
  cat > "$d/internal/ai/egressgate.go" <<'EOF'
package ai
var ErrEgressDenied = error(nil)
EOF
  cat > "$d/internal/ebpf/bench_test.go" <<'EOF'
package ebpf
const floor = 20_000
EOF
  cat > "$d/docs/agent-overhead.md" <<'EOF'
These figures are illustrative on reference hardware and are a smoke guard.
EOF
  cat > "$d/docs/perf-baseline.md" <<'EOF'
The figures below are illustrative, not guarantees.
EOF
  cat > "$d/docs/capacity.md" <<'EOF'
CI/dev smoke only; not a platform promise.
EOF
  cat > "$d/docs/finops.md" <<'EOF'
This is not a reconciliation of your actual invoice.
EOF
  cat > "$d/docs/ndr.md" <<'EOF'
NDR-lite emits confidence-scored signals with detector.confidence.
EOF
  cat > "$d/internal/threat/ndr.go" <<'EOF'
package threat
const confidenceAttr = "detector.confidence"
EOF
  cat > "$d/internal/threat/model.go" <<'EOF'
package threat
type Finding struct { Confidence int }
EOF
  cat > "$d/internal/threat/detections.go" <<'EOF'
package threat
type Detection struct { Confidence int }
EOF
  cat > "$d/docs/limitations.md" <<'EOF'
## Built, not yet served edges
Chaos injector API/control-plane surface
eBPF TLS posture ingest
Raw eBPF flow retention
Browser artifact S3 / MinIO backend
The plugin/detection marketplace is a non-goal.
inline IPS/firewall
autonomous remediation
vendor-hosted public SaaS
EOF
  cat > "$d/docs/features.md" <<'EOF'
| F49 marketplace | limitations.md |
EOF
  cat > "$d/internal/otel/otlp/exporter.go" <<'EOF'
package otlp
type ExporterConfig struct { Endpoint string }
const err = "requires an endpoint URL"
EOF
  cat > "$d/internal/control/devauth.go" <<'EOF'
//go:build devauth
package control
EOF
  cat > "$d/.github/workflows/ci.yml" <<'EOF'
jobs:
  no-devauth-in-release:
    steps:
      - run: echo "::error::release binary contains dev-auth principal implementation"; exit 1; fi
      - run: '[ "$rc" -ne 0 ] || { echo "::error::release binary STARTED in dev mode"; exit 1; }'
  lint-go:
    steps:
      - run: ./scripts/check_docs_claims.sh SELFTEST && ./scripts/check_docs_claims.sh
EOF
  cat > "$d/docs/ci-pipeline.md" <<'EOF'
no-devauth-in-release
scripts/check_docs_claims.sh SELFTEST && scripts/check_docs_claims.sh
EOF
  cat > "$d/Makefile" <<'EOF'
lint-go:
	./scripts/check_docs_claims.sh SELFTEST && ./scripts/check_docs_claims.sh
	SELFTEST=1 ./scripts/check_editions_imports.sh
EOF
  cat > "$d/LICENSE" <<'EOF'
TBD
EOF
  cat > "$d/docs/features/cost-slo-and-chaos.md" <<'EOF'
../limitations.md#built-not-yet-served-edges
EOF
  cat > "$d/docs/tls-observability.md" <<'EOF'
limitations.md#built-not-yet-served-edges
EOF
  cat > "$d/docs/deploying-agents.md" <<'EOF'
limitations.md#built-not-yet-served-edges
EOF
  cat > "$d/docs/browser-synthetic.md" <<'EOF'
limitations.md#built-not-yet-served-edges
EOF
  cat > "$d/SECURITY.md" <<'EOF'
break-glass-gate bypass
EOF
}

break_fixture() { # break_fixture <label> <dir>
  local label="$1"
  local d="$2"
  case "$label" in
    DOCS-S01)
      echo 'package control' > "$d/internal/control/ai.go"
      ;;
    DOCS-S02)
      echo 'package telemetry; import _ "github.com/getsentry/sentry-go"' > "$d/internal/telemetry.go"
      ;;
    DOCS-S03)
      echo 'remote model only' > "$d/docs/ai-rca.md"
      ;;
    DOCS-S04)
      echo 'package remediation; func ApplyRemediation() {}' > "$d/internal/remediation.go"
      ;;
    DOCS-S05)
      echo 'package ebpf' > "$d/internal/ebpf/bench_test.go"
      ;;
    DOCS-S06)
      echo 'numbers are guarantees' > "$d/docs/perf-baseline.md"
      ;;
    DOCS-S07)
      echo 'package threat' > "$d/internal/threat/ndr.go"
      ;;
    DOCS-S08)
      echo '| F49 | shipped |' > "$d/docs/features.md"
      ;;
    DOCS-S09)
      cat > "$d/internal/otel/otlp/exporter.go" <<'EOF'
package otlp
type ExporterConfig struct { Endpoint string }
const endpoint = "https://telemetry.example/v1/metrics"
EOF
      ;;
    DOCS-S10)
      echo 'package control' > "$d/internal/control/devauth.go"
      ;;
    DOCS-S11)
      cat > "$d/.github/workflows/ci.yml" <<'EOF'
jobs:
  lint-go:
    steps:
      - run: ./scripts/check_docs_claims.sh SELFTEST && ./scripts/check_docs_claims.sh
EOF
      ;;
    DOCS-S12)
      echo 'lint-go:' > "$d/Makefile"
      ;;
    DOCS-S13)
      cat > "$d/README.md" <<'EOF'
# probectl
cited evidence stays scoped to what the caller is allowed to see.
trusted by 500 enterprises use this platform.
## What probectl is not
EOF
      ;;
    DOCS-S14)
      cat > "$d/README.md" <<'EOF'
# probectl
cited evidence stays scoped to what the caller is allowed to see.
EOF
      ;;
    DOCS-S15)
      cat > "$d/docs/unlisted-edge.md" <<'EOF'
The packet mirror is not wired yet.
EOF
      ;;
    SEC-004)
      echo '# scope' > "$d/SECURITY.md"
      ;;
    *)
      echo "unknown SELFTEST label: $label" >&2
      return 2
      ;;
  esac
}

expect_label_failure() { # expect_label_failure <label>
  local label="$1"
  local tmp out
  tmp="$(mktemp -d)"
  out="$tmp/out"
  write_good_fixture "$tmp"
  break_fixture "$label" "$tmp"
  if run_checks "$tmp" >"$out" 2>&1; then
    echo "SELFTEST FAILED: $label fixture passed unexpectedly" >&2
    cat "$out" >&2
    rm -rf "$tmp"
    return 1
  fi
  if ! grep -q "^$label:" "$out"; then
    echo "SELFTEST FAILED: $label fixture failed for the wrong rule" >&2
    cat "$out" >&2
    rm -rf "$tmp"
    return 1
  fi
  rm -rf "$tmp"
}

if [ "${1:-}" = "SELFTEST" ]; then
  labels="${2:-DOCS-S01 DOCS-S02 DOCS-S03 DOCS-S04 DOCS-S05 DOCS-S06 DOCS-S07 DOCS-S08 DOCS-S09 DOCS-S10 DOCS-S11 DOCS-S12 DOCS-S13 DOCS-S14 DOCS-S15 SEC-004}"
  for label in $labels; do
    expect_label_failure "$label"
  done
  echo "check_docs_claims SELFTEST OK (targeted bad fixtures correctly rejected: $labels)"
  exit 0
fi

run_checks "." || fail=1
if [ "$fail" -ne 0 ]; then exit 1; fi
echo "check_docs_claims: all honest-claim properties hold (DOCS-S01..S15, SEC-004)"
