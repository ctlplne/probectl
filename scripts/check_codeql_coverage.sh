#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0
#
# check_codeql_coverage.sh (DPR-245) — CodeQL must actually be analysing the
# product, not just the workflows.
#
# On 2026-09-19 this was discovered by reading the alert list rather than by any
# gate: CodeQL's last analysis of Go, JavaScript/TypeScript, Python and C/C++ was
# 2026-07-02 on commit 0aa5ff0. Only `/language:actions` had run since — 79 days,
# the whole design-partner-readiness programme, with no static analysis of the
# product at all. The 17 open alerts were a frozen July snapshot whose line
# numbers no longer matched the code, and a local run of the same suite on current
# code found TWO high-severity rule classes GitHub had never reported
# (go/clear-text-logging, go/zipslip) plus a different set of integer-conversion
# sites.
#
# Nothing noticed because nothing looked. SUPPLY-007's controls are govulncheck,
# trivy and npm audit; none of them is CodeQL, and the language list lives in repo
# SETTINGS, so no diff could ever show that Go analysis had stopped.
#
# This asks the API the one question that matters: for each language the product
# is written in, how old is the newest analysis? A missing language is a failure,
# and a stale one is a failure, because both mean the alert list is fiction.
#
#   scripts/check_codeql_coverage.sh                 # needs GH_TOKEN with security-events: read
#   SELFTEST=1 scripts/check_codeql_coverage.sh      # prove the staleness arithmetic
set -euo pipefail

MAX_AGE_DAYS="${PROBECTL_CODEQL_MAX_AGE_DAYS:-14}"
REPO="${GITHUB_REPOSITORY:-ctlplne/probectl}"

# The languages the product is written in. `actions` is deliberately NOT here: it
# is the one that kept running while these stopped, so requiring it would have
# passed throughout.
REQUIRED_LANGUAGES=(go javascript-typescript python)

age_days() { # age_days <iso8601> -> whole days
  python3 - "$1" <<'PY'
import datetime, sys
then = datetime.datetime.fromisoformat(sys.argv[1].replace('Z', '+00:00'))
now = datetime.datetime.now(datetime.timezone.utc)
print(int((now - then).total_seconds() // 86400))
PY
}

if [ "${SELFTEST:-0}" = "1" ]; then
  # The arithmetic, without the network: a fresh timestamp passes, an old one does not.
  fresh="$(python3 -c "import datetime;print((datetime.datetime.now(datetime.timezone.utc)-datetime.timedelta(days=1)).strftime('%Y-%m-%dT%H:%M:%SZ'))")"
  stale="$(python3 -c "import datetime;print((datetime.datetime.now(datetime.timezone.utc)-datetime.timedelta(days=79)).strftime('%Y-%m-%dT%H:%M:%SZ'))")"
  if [ "$(age_days "$fresh")" -gt "$MAX_AGE_DAYS" ]; then
    echo "codeql-coverage SELFTEST FAILED: a 1-day-old analysis was called stale" >&2; exit 1
  fi
  if [ "$(age_days "$stale")" -le "$MAX_AGE_DAYS" ]; then
    echo "codeql-coverage SELFTEST FAILED: a 79-day-old analysis was called fresh" >&2; exit 1
  fi
  echo "codeql-coverage SELFTEST: OK (1 day fresh, 79 days stale, threshold ${MAX_AGE_DAYS}d)"
  exit 0
fi

if ! command -v gh >/dev/null 2>&1; then
  echo "codeql-coverage: gh is required — refusing to report coverage it never checked" >&2
  exit 127
fi

analyses="$(gh api "/repos/${REPO}/code-scanning/analyses?per_page=100" 2>/dev/null || true)"
if [ -z "$analyses" ]; then
  echo "::error::codeql-coverage: could not read code-scanning analyses for ${REPO} (needs security-events: read)" >&2
  exit 1
fi

fail=0
for lang in "${REQUIRED_LANGUAGES[@]}"; do
  newest="$(printf '%s' "$analyses" | python3 -c "
import json,sys
lang = sys.argv[1]
runs = [a for a in json.load(sys.stdin) if a.get('category') == '/language:' + lang]
print(runs[0]['created_at'] if runs else '')
" "$lang")"
  if [ -z "$newest" ]; then
    echo "::error::codeql-coverage: NO analysis for /language:${lang} in the last 100 — the product is not being scanned (DPR-245)" >&2
    fail=1
    continue
  fi
  age="$(age_days "$newest")"
  if [ "$age" -gt "$MAX_AGE_DAYS" ]; then
    echo "::error::codeql-coverage: /language:${lang} last analysed ${age} days ago (${newest}), over the ${MAX_AGE_DAYS}-day bar — the open alert list is a stale snapshot (DPR-245)" >&2
    fail=1
  else
    echo "codeql-coverage: /language:${lang} analysed ${age}d ago (${newest})"
  fi
done

if [ "$fail" -ne 0 ]; then
  echo "codeql-coverage gate FAILED — enable the missing language(s) in code scanning, or adopt the in-repo workflow (decisions-needed D-14)." >&2
  exit 1
fi
echo "codeql-coverage gate: OK (every product language analysed within ${MAX_AGE_DAYS} days)"
