#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-probectl-TBD
#
# check-test-clocks.sh (TEST-002 / RESIL-002) — prevent the SLO-engine time-bomb
# regression class.
#
# THE BOMB (RESIL-002): a test constructs the SLO engine, feeds it FIXED-timestamp
# events, but lets the engine evaluate its rolling error-budget window against the
# default WALL clock (time.Now). It passes the day it's written and silently fails
# later, when the fixed events age past the window. TestChaosRunDetectedBySLO did
# exactly this and was failing in CI by the time the audit ran.
#
# THE RULE: any test that uses the SLO engine cross-package (`slo.NewEngine(`)
# MUST inject a deterministic clock with `.WithClock(...)`, so evaluation is
# anchored to the same synthetic timeline as the events. In-package slo tests set
# the unexported `e.clock` field directly and are inherently clock-aware, so the
# guard is intentionally scoped to the QUALIFIED `slo.NewEngine(` call.
#
# Why scoped, not "flag every future date": the repo standardizes on 2026-06-xx as
# a fixed test epoch, fed through per-test injected clocks — flagging all of those
# is ~55 false positives and the guard would just get disabled. Precision beats
# noise. A line may still opt out explicitly with  //clocklint:allow <reason> .
#
# To extend: if another clock-windowed evaluator gains a `WithClock`-style seam,
# add its qualified constructor to CTORS below.
set -euo pipefail

CTORS='slo\.NewEngine\('

hits=""
while IFS= read -r f; do
    [ -z "$f" ] && continue
    grep -q 'WithClock' "$f" && continue                       # clock injected — safe
    fh="$(grep -nE "$CTORS" "$f" 2>/dev/null | grep -v 'clocklint:allow' || true)"
    [ -n "$fh" ] && hits="${hits}${f}:
${fh}
"
done < <(grep -rlE "$CTORS" --include='*_test.go' . 2>/dev/null || true)

if [ -n "$hits" ]; then
    echo "::error::RESIL-002: a test uses the SLO engine cross-package without injecting a clock (.WithClock) — feeding fixed-timestamp events while it evaluates against the wall clock is a time-bomb. Add .WithClock(func() time.Time { return <synthetic now> }), or annotate //clocklint:allow <reason>:"
    printf '%s\n' "$hits"
    exit 1
fi
echo "no SLO-engine time-bombs (every cross-package slo.NewEngine injects a clock)"
