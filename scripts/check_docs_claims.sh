#!/usr/bin/env bash
# check_docs_claims.sh — claim-register gate + honest-claim properties
# (Foundation-Loop T-eb2b5d7c; formerly DOCS-S01..S19, SEC-004 only).
#
# Two layers, one rule:
#
#  1. REGISTER (the rule): docs/claims/register.json declares every
#     capability claim made in a governed surface (README, PRDs, docs/,
#     SECURITY/LICENSING/CONTRIBUTING, UI copy catalog) and binds it to the
#     code paths that implement it and the gate/test that proves it.
#     scripts/claims_register_check.py enforces BOTH directions: an
#     undeclared capability-shaped claim fails (REG-UNCOVERED — new files
#     and new claim families are always caught), and a declared claim whose
#     bound code path, proof, surface, or phrasing stops existing fails
#     (REG-STALE-CODE / REG-BAD-PROOF / REG-STALE-SURFACE /
#     REG-STALE-PATTERN). The claim grammar may only be extended
#     (REG-GRAMMAR-FLOOR).
#
#  2. PROPERTIES (migrated, not deleted): the DOCS-S01..S19 + SEC-004
#     honest-claim assertions below are register entries of kind
#     legacy-property; the register binds each to its planted-failure
#     selftest here, and the SELFTEST label list is read FROM the register,
#     so dropping a property from either side fails the gate.
#
# SELFTEST proves the gate can fail before it is trusted: the good fixture
# must PASS (anti-vacuous harness), then every legacy label and every REG-*
# failure shape is planted and must be caught.
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
  # (Foundation-Loop T-82cf4a6f: 'Alert email delivery' left this table — SMTP
  # is wired — so the row and docs/alerting.md's caveat link are no longer
  # required; a doc claiming a resolved limitation would itself be untrue.)
  local limits="$r/docs/limitations.md"
  if ! grep -q '## Built, not yet served edges' "$limits" 2>/dev/null \
     || ! grep -q 'Chaos injector API/control-plane surface' "$limits" 2>/dev/null \
     || ! grep -q 'Go `crypto/tls` eBPF handshake metadata' "$limits" 2>/dev/null \
     || ! grep -q 'Raw eBPF call/flow history' "$limits" 2>/dev/null; then
    echo "DOCS-S15: docs/limitations.md must keep the canonical built-not-yet-served table" >&2; f=1
  fi
  if ! grep -q '../limitations.md#built-not-yet-served-edges' "$r/docs/features/cost-slo-and-chaos.md" 2>/dev/null \
     || ! grep -q 'limitations.md#built-not-yet-served-edges' "$r/docs/tls-observability.md" 2>/dev/null \
     || ! grep -q 'limitations.md#built-not-yet-served-edges' "$r/docs/deploying-agents.md" 2>/dev/null \
     || ! grep -q '../limitations.md#built-not-yet-served-edges' "$r/docs/features/alerting-and-incidents.md" 2>/dev/null; then
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
      "$r/docs/configuration.md")
        continue
        ;;
    esac
    if ! grep -q 'limitations.md#built-not-yet-served-edges' "$file" 2>/dev/null; then
      echo "DOCS-S15: buyer-relevant built-not-yet-served disclosure lacks a docs/limitations.md backlink: $hit" >&2; f=1
    fi
  done <<<"$disclosure_hits"

  # DOCS-S16 / LICENSE-001: the owner decision is final for core. The root
  # grant is canonical BUSL-1.1 with its parameters for the core, followed by
  # canonical MPL-2.0 without Exhibit B for pkg/, proto/ and examples/; only the
  # separate commercial paper remains counsel work. Keep buyer/compliance pages
  # from quietly reverting to the old "root LICENSE is a placeholder" state.
  if ! grep -q '^Business Source License 1\.1$' "$r/LICENSE" 2>/dev/null \
     || ! grep -q '^Mozilla Public License Version 2\.0$' "$r/LICENSE" 2>/dev/null \
     || ! grep -q 'complete, unmodified license is in' "$r/LICENSING.md" 2>/dev/null \
     || ! grep -q 'root `LICENSE` is already the final' "$r/docs/compliance/control-evidence.md" 2>/dev/null \
     || ! grep -q 'core license grant is already final' "$r/docs/pricing.md" 2>/dev/null; then
    echo "DOCS-S16: root LICENSE must remain final (unmodified BUSL-1.1 core, unmodified MPL-2.0 client tree); only commercial paper is pending counsel" >&2; f=1
  fi
  if grep -RniE 'legal source-available license text is still|`LICENSE` / commercial license texts.{0,40}(pending|placeholder)|root LICENSE.{0,40}(pending|placeholder)' \
       "$r/README.md" "$r/LICENSING.md" "$r/CONTRIBUTING.md" "$r/docs" 2>/dev/null | grep -q .; then
    echo "DOCS-S16: stale root-LICENSE placeholder/pending-counsel claim found" >&2; f=1
  fi

  # DOCS-S17: quickstart time-to-first-data is readiness-based, not a
  # host/cache-dependent stopwatch promise. The viewer must wait for both the
  # ready endpoint and a non-empty sample-flow topology, then fail loudly.
  if grep -niE '~20s|~60|60 seconds to first data|a couple of minutes|wait a few seconds' \
       "$r/README.md" "$r/docs/getting-started.md" "$r/docs/install.md" \
       "$r/deploy/compose/README.md" "$r/deploy/compose/eval.yml" 2>/dev/null | grep -q .; then
    echo "DOCS-S17: uncited quickstart timing promise found; use readiness-based language" >&2; f=1
  fi
  if ! grep -q 'viewer waits for control-plane readiness and sample topology data' "$r/README.md" 2>/dev/null \
     || ! grep -q 'viewer waits for control-plane readiness and sample topology data' "$r/docs/getting-started.md" 2>/dev/null \
     || ! grep -q 'viewer waits for control-plane readiness and sample topology data' "$r/docs/install.md" 2>/dev/null \
     || ! grep -q -- '--profile tools run --rm --no-deps viewer' "$r/README.md" 2>/dev/null \
     || ! grep -q -- '--profile tools run --rm --no-deps viewer' "$r/docs/getting-started.md" 2>/dev/null \
     || ! grep -q -- '--profile tools run --rm --no-deps viewer' "$r/docs/install.md" 2>/dev/null \
     || ! grep -q 'until curl .*readyz' "$r/deploy/compose/eval.yml" 2>/dev/null \
     || ! grep -Fq "grep -Eq '\"flow_edges\"[[:space:]]*:[[:space:]]*[1-9][0-9]*'" "$r/deploy/compose/eval.yml" 2>/dev/null \
     || ! grep -q 'sample topology data did not arrive' "$r/deploy/compose/eval.yml" 2>/dev/null; then
    echo "DOCS-S17: eval viewer must gate success on readiness plus non-empty sample topology data" >&2; f=1
  fi

  # DOCS-S18: evidence consolidation is implemented; incident-duration
  # improvement is not yet measured. MTTI/MTTR language must preserve that
  # boundary until a customer or reproducible proof-of-value receipt exists.
  if grep -niEi 'shorter[^.]{0,40}MTTI|lower[^.]{0,40}MTTR|faster[ -]time[- ]to[- ](identify|resolve)' \
       "$r/README.md" "$r/docs/alerting.md" "$r/docs/ai-rca.md" 2>/dev/null | grep -q .; then
    echo "DOCS-S18: unmeasured MTTI/MTTR improvement stated as an outcome" >&2; f=1
  fi
  if ! grep -q 'design intent, not a measured outcome' "$r/README.md" 2>/dev/null \
     || ! grep -q 'design intent, not a measured outcome' "$r/docs/alerting.md" 2>/dev/null \
     || ! grep -q 'design intent, not a measured' "$r/docs/ai-rca.md" 2>/dev/null; then
    echo "DOCS-S18: MTTI/MTTR language must distinguish design intent from measured outcomes" >&2; f=1
  fi

  # DOCS-S19: the canonical PoV must distinguish the zero-phone-home DEFAULT
  # from operator-enabled egress. It must also avoid mutable, named competitor
  # absence claims without a dated evidence link.
  local pov="$r/docs/pov-demo-script.md"
  if ! grep -q 'By default, no probectl call-home or product' "$pov" 2>/dev/null \
     || ! grep -q 'remote AI (tenant' "$pov" 2>/dev/null \
     || ! grep -q 'public-data/threat/outage feed' "$pov" 2>/dev/null \
     || ! grep -q 'OTLP/SIEM/on-call exports' "$pov" 2>/dev/null \
     || ! grep -q 'active probes to their configured' "$pov" 2>/dev/null; then
    echo "DOCS-S19: canonical PoV must enumerate the default posture and operator-enabled outbound paths" >&2; f=1
  fi
  if grep -niE 'What leaves my network.{0,80}Nothing|telemetry never leaves your network|open-data feeds are inbound-only|have no cross-plane single-axis|None of the .* competitors|competitors (do not|don.t) (have|surface)' \
       "$pov" 2>/dev/null | grep -q .; then
    echo "DOCS-S19: canonical PoV contains an unqualified zero-egress or unsupported competitor-absence claim" >&2; f=1
  fi
  if grep -niE 'Kentik|ThousandEyes|Datadog|Auvik|Grafana' "$pov" 2>/dev/null | grep -q . \
     && ! grep -qE 'https?://|matrix/gen-[0-9]+-matrix\.md' "$pov" 2>/dev/null; then
    echo "DOCS-S19: named PoV comparison requires a current dated source or matrix link" >&2; f=1
  fi

  # SEC-004: SECURITY.md scopes provider-operator break-glass abuse as in-scope.
  if [ -f "$r/SECURITY.md" ] \
     && ! grep -qi 'break-glass-gate bypass' "$r/SECURITY.md"; then
    echo "SEC-004: SECURITY.md no longer names provider-operator break-glass abuse as in-scope" >&2; f=1
  fi

  return $f
}

run_register() { # run_register <root> — the claim-register rule (T-eb2b5d7c)
  python3 scripts/claims_register_check.py --root "$1"
}

run_all() { # run_all <root> — properties + register together
  local f=0
  run_checks "$1" || f=1
  run_register "$1" || f=1
  return $f
}

write_good_fixture() { # write_good_fixture <dir>
  local d="$1"
  mkdir -p \
    "$d/.github/workflows" \
    "$d/cmd" "$d/ee" "$d/internal/ai/eval" "$d/internal/control" \
    "$d/internal/ebpf" "$d/internal/otel/otlp" "$d/internal/threat" \
    "$d/pkg" "$d/docs/compliance" "$d/docs/features" "$d/deploy/compose"

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
Alert email delivery
Go `crypto/tls` eBPF handshake metadata
Raw eBPF call/flow history
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
Business Source License 1.1
Mozilla Public License Version 2.0
EOF
  cat > "$d/LICENSING.md" <<'EOF'
The complete, unmodified license is in LICENSE. Commercial paper remains counsel-owned.
EOF
  cat > "$d/CONTRIBUTING.md" <<'EOF'
Core is final BUSL-1.1 with an MPL-2.0 client tree; only commercial terms remain counsel work.
EOF
  cat > "$d/docs/compliance/control-evidence.md" <<'EOF'
The root `LICENSE` is already the final grant: unmodified BUSL-1.1 core, unmodified MPL-2.0 client tree; draft `ee/LICENSE` remains counsel work.
EOF
  cat > "$d/docs/pricing.md" <<'EOF'
The core license grant is already final; draft `ee/LICENSE` and commercial agreements remain counsel-owned.
EOF
  cat > "$d/docs/getting-started.md" <<'EOF'
The viewer waits for control-plane readiness and sample topology data.
docker compose -f deploy/compose/eval.yml --profile tools run --rm --no-deps viewer
EOF
  cat > "$d/docs/install.md" <<'EOF'
The viewer waits for control-plane readiness and sample topology data.
docker compose -f deploy/compose/eval.yml --profile tools run --rm --no-deps viewer
EOF
  cat >> "$d/docs/alerting.md" <<'EOF'
Reducing MTTI or MTTR is a design intent, not a measured outcome.
EOF
  cat >> "$d/docs/ai-rca.md" <<'EOF'
Reducing MTTI or MTTR is a design intent, not a measured outcome.
EOF
  cat > "$d/docs/pov-demo-script.md" <<'EOF'
# Canonical PoV
By default, no probectl call-home or product telemetry egress occurs.
Operator-enabled outbound paths are explicit: remote AI (tenant consent,
redaction, and audit), read-only public-data/threat/outage feed fetches,
OTLP/SIEM/on-call exports, and active probes to their configured targets.
EOF
  cat > "$d/deploy/compose/README.md" <<'EOF'
The viewer waits for control-plane readiness and sample topology data.
EOF
  cat >> "$d/README.md" <<'EOF'
The viewer waits for control-plane readiness and sample topology data.
docker compose -f deploy/compose/eval.yml --profile tools run --rm --no-deps viewer
Reducing MTTI or MTTR is a design intent, not a measured outcome.
EOF
  cat > "$d/deploy/compose/eval.yml" <<'EOF'
services:
  viewer:
    command:
      - |
        until curl -fsS https://127.0.0.1:8443/readyz; do sleep 2; done
        if printf '%s' "$body" | grep -Eq '"flow_edges"[[:space:]]*:[[:space:]]*[1-9][0-9]*'; then exit 0; fi
        echo "sample topology data did not arrive"
EOF
  cat > "$d/docs/features/cost-slo-and-chaos.md" <<'EOF'
../limitations.md#built-not-yet-served-edges
EOF
  cat > "$d/docs/features/alerting-and-incidents.md" <<'EOF'
Email channel not wired; see ../limitations.md#built-not-yet-served-edges
EOF
  cat >> "$d/docs/alerting.md" <<'EOF'
Email channel not wired; see limitations.md#built-not-yet-served-edges
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

  # Claim-register fixture: the governed fixture surfaces above carry
  # register coverage exactly like the real tree, so SELFTEST exercises the
  # same rule the live run enforces. Grammar and legacy entries come from
  # the real register (single source of truth); capability entries bind the
  # fixture's own claim-bearing lines.
  mkdir -p "$d/docs/claims" "$d/scripts"
  cp scripts/check_docs_claims.sh "$d/scripts/check_docs_claims.sh"
  python3 - "$d" <<'PYEOF'
import json, sys
d = sys.argv[1]
real = json.load(open("docs/claims/register.json", encoding="utf-8"))
legacy = [c for c in real["claims"] if c.get("kind") == "legacy-property"]
claims = [
  {"id": "CLM-NO-PHONE-HOME", "kind": "capability",
   "statement": "fixture: no default egress",
   "pattern": "phone-home|call-home|never leaves|leaves the (operator|deployment|network)|zero[- ]egress|no egress",
   "surfaces": ["docs/ai-rca.md", "docs/pov-demo-script.md"],
   "code": ["internal/ai/egressgate.go", "internal/ai/model_builtin.go"],
   "proof": ["selftest-label:DOCS-S03"]},
  {"id": "CLM-NOT-AN-IPS", "kind": "capability",
   "statement": "fixture: signals not blocking",
   "pattern": "never an IPS|not an IPS|not an inline IPS|inline (IPS|blocking)",
   "surfaces": ["docs/limitations.md"],
   "code": ["internal/threat/ndr.go"],
   "proof": ["selftest-label:DOCS-S07"]},
  {"id": "CLM-HONEST-NUMBERS", "kind": "capability",
   "statement": "fixture: numbers stay labeled",
   "pattern": "\\bguarantees?\\b",
   "surfaces": ["docs/perf-baseline.md"],
   "code": [],
   "proof": ["selftest-label:DOCS-S06"]},
] + legacy
fix = {"version": 1, "governed": real["governed"], "grammar": real["grammar"], "claims": claims}
json.dump(fix, open(f"{d}/docs/claims/register.json", "w", encoding="utf-8"), indent=1)
PYEOF
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
      cat > "$d/docs/limitations.md" <<'EOF'
## Built, not yet served edges
Chaos injector API/control-plane surface
Go `crypto/tls` eBPF handshake metadata
Raw eBPF call/flow history
The plugin/detection marketplace is a non-goal.
inline IPS/firewall
autonomous remediation
vendor-hosted public SaaS
EOF
      cat > "$d/docs/alerting.md" <<'EOF'
Email channel not wired.
EOF
      ;;
    DOCS-S16)
      cat > "$d/docs/compliance/control-evidence.md" <<'EOF'
The `LICENSE` / commercial license texts are a legal artifact pending counsel (placeholder in-tree).
EOF
      ;;
    DOCS-S17)
      cat >> "$d/README.md" <<'EOF'
First data arrives in ~60 seconds.
EOF
      ;;
    DOCS-S18)
      cat >> "$d/README.md" <<'EOF'
The product delivers shorter MTTI and faster time-to-resolve.
EOF
      ;;
    DOCS-S19)
      cat > "$d/docs/pov-demo-script.md" <<'EOF'
# Canonical PoV
**"What leaves my network?"** Nothing. Open-data feeds are inbound-only.
Kentik and ThousandEyes have no cross-plane single-axis view.
EOF
      ;;
    SEC-004)
      echo '# scope' > "$d/SECURITY.md"
      ;;
    REG-UNCOVERED)
      # A brand-new file making a capability-shaped claim (an untrue one,
      # deliberately) must fail until it is consciously registered.
      echo 'This build adds phone-home telemetry to the collector.' > "$d/docs/new-page.md"
      ;;
    REG-STALE-CODE)
      python3 - "$d" <<'PYEOF'
import json, sys
p = f"{sys.argv[1]}/docs/claims/register.json"
r = json.load(open(p))
for c in r["claims"]:
    if c["id"] == "CLM-NO-PHONE-HOME":
        c["code"] = ["internal/ai/missing_gadget.go"]
json.dump(r, open(p, "w"))
PYEOF
      ;;
    REG-STALE-PATTERN)
      python3 - "$d" <<'PYEOF'
import json, sys
p = f"{sys.argv[1]}/docs/claims/register.json"
r = json.load(open(p))
r["claims"].append({"id": "CLM-GHOST", "kind": "capability",
  "statement": "fixture: registered claim nothing asserts",
  "pattern": "quantum teleportation drive",
  "surfaces": ["docs/ai-rca.md"], "code": [], "proof": ["selftest-label:DOCS-S01"]})
json.dump(r, open(p, "w"))
PYEOF
      ;;
    REG-BAD-PROOF)
      python3 - "$d" <<'PYEOF'
import json, sys
p = f"{sys.argv[1]}/docs/claims/register.json"
r = json.load(open(p))
for c in r["claims"]:
    if c["id"] == "CLM-NOT-AN-IPS":
        c["proof"] = ["make:no-such-target"]
json.dump(r, open(p, "w"))
PYEOF
      ;;
    REG-GRAMMAR-FLOOR)
      python3 - "$d" <<'PYEOF'
import json, sys
p = f"{sys.argv[1]}/docs/claims/register.json"
r = json.load(open(p))
r["grammar"] = "phone-home"
json.dump(r, open(p, "w"))
PYEOF
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
  if run_all "$tmp" >"$out" 2>&1; then
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
  # 0) Anti-vacuous harness: the good fixture must PASS before planted
  #    failures prove anything — a gate that fails on everything would
  #    otherwise pass every planted-failure assertion below.
  good="$(mktemp -d)"
  write_good_fixture "$good"
  if ! run_all "$good" >"$good/out" 2>&1; then
    echo "SELFTEST FAILED: the good fixture did not pass — the harness cannot distinguish red from green" >&2
    cat "$good/out" >&2
    rm -rf "$good"
    exit 1
  fi
  rm -rf "$good"

  # The legacy label list is read FROM the register (single source of
  # truth): dropping a migrated property from the register drops its
  # planted-failure proof and this selftest with it — visibly.
  legacy_labels="$(python3 scripts/claims_register_check.py --list-legacy)"
  reg_labels="REG-UNCOVERED REG-STALE-CODE REG-STALE-PATTERN REG-BAD-PROOF REG-GRAMMAR-FLOOR"
  labels="${2:-$legacy_labels $reg_labels}"
  for label in $labels; do
    expect_label_failure "$label"
  done
  echo "check_docs_claims SELFTEST OK (good fixture passes; planted failures rejected: $(echo $labels | tr '\n' ' '))"
  exit 0
fi

run_all "." || fail=1
if [ "$fail" -ne 0 ]; then exit 1; fi
echo "check_docs_claims: honest-claim properties + claim register hold (see docs/claims/register.json)"
