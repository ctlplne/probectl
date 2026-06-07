#!/usr/bin/env bash
#
# no-stringbuilt-sql gate (Sprint 7 — ARCH-002/SEC-005/TENANT-108): ClickHouse
# query VALUES must travel as SERVER-BOUND parameters ({name:Type} placeholders
# + param_* HTTP parameters), never be string-interpolated or hand-escaped into
# the SQL text. This gate fails the build when string-built CH SQL reappears.
#
# What it bans:
#   1. The deleted client-side escaping helpers (chStr / chTime / sqlStr) —
#      their reintroduction anywhere is the regression signal.
#   2. Value-position interpolation in the CH stores: a comparison or VALUES
#      list built by string concatenation or a %s/%q verb (e.g.
#      `tenant_id="+x`, `= '%s'`, `VALUES ('%s', ...)`).
#
# What it deliberately ALLOWS (and why):
#   - Identifier interpolation in DDL (table names from compile-time constants,
#     CH USER names validated by chValidUser/chUserRe, fail closed): SQL
#     dialects cannot bind identifiers; validation — not escaping — is the
#     correct control there.
#   - %d of int values (an int cannot carry SQL syntax).
set -euo pipefail

cd "$(dirname "$0")/.."

# The packages that speak ClickHouse.
CH_DIRS=(internal/store/flowstore internal/store/pathstore internal/store/chmigrate)

fail=0

# ── 1. The escaping helpers must stay deleted (repo-wide, tests included). ──
helpers="$(grep -rEn '\b(chStr|chTime|sqlStr)\(' --include='*.go' internal/ cmd/ ee/ 2>/dev/null \
  | grep -v 'chTimeParam(' || true)"
if [ -n "${helpers}" ]; then
  echo "FORBIDDEN client-side SQL escaping helpers (use bound {name:Type} params):" >&2
  echo "${helpers}" >&2
  fail=1
fi

# ── 2. No value-position interpolation in CH SQL (non-test store files). ────
# 2a. Concatenating a variable directly after a comparison operator INSIDE SQL
#     text: `... WHERE tenant_id="+x`, `ts < "+y`. Scoped to lines carrying an
#     SQL keyword so URL/transport plumbing (`"?query=" + url.QueryEscape`)
#     doesn't false-positive.
concat="$(grep -rEn 'SELECT|DELETE FROM|INSERT INTO|WHERE|VALUES' \
  --include='*.go' --exclude='*_test.go' "${CH_DIRS[@]}" 2>/dev/null \
  | grep -E "(=|<|>)[[:space:]]*\"[[:space:]]*\+[[:space:]]*[A-Za-z_]" || true)"
if [ -n "${concat}" ]; then
  echo "STRING-CONCATENATED value in a ClickHouse comparison (bind it as {name:Type} + param_*):" >&2
  echo "${concat}" >&2
  fail=1
fi

# 2b. %s/%q format verbs in value positions of SQL-bearing format strings:
#     = %s, ='%s', VALUES ('%s'  / VALUES (%s
verbs="$(grep -rEn "(=[[:space:]]*'?%[sq])|(VALUES[[:space:]]*\([^)]*%[sq])" \
  --include='*.go' --exclude='*_test.go' "${CH_DIRS[@]}" 2>/dev/null || true)"
if [ -n "${verbs}" ]; then
  echo "Sprintf VALUE interpolation in ClickHouse SQL (bind it as {name:Type} + param_*):" >&2
  echo "${verbs}" >&2
  fail=1
fi

# ── self-test: the patterns must actually catch the banned shapes ───────────
if [ "${SELFTEST:-0}" = "1" ]; then
  probe='x := "SELECT 1 FROM t WHERE tenant_id="+tenant'
  echo "${probe}" | grep -E 'SELECT|DELETE FROM|INSERT INTO|WHERE|VALUES' \
    | grep -qE "(=|<|>)[[:space:]]*\"[[:space:]]*\+[[:space:]]*[A-Za-z_]" \
    || { echo "SELFTEST FAILED: concat pattern missed ${probe}" >&2; exit 1; }
  probe2="q := fmt.Sprintf(\"DELETE FROM t WHERE id = '%s'\", id)"
  echo "${probe2}" | grep -qE "(=[[:space:]]*'?%[sq])" \
    || { echo "SELFTEST FAILED: verb pattern missed ${probe2}" >&2; exit 1; }
  probe3='v := chStr(tenantID)'
  echo "${probe3}" | grep -qE '\b(chStr|chTime|sqlStr)\(' \
    || { echo "SELFTEST FAILED: helper pattern missed ${probe3}" >&2; exit 1; }
fi

if [ "${fail}" -ne 0 ]; then
  echo "" >&2
  echo "ClickHouse values must be SERVER-BOUND: put {name:Type} in the SQL and pass the value via chParams (param_* HTTP parameters). See docs/security/tenant-isolation.md." >&2
  exit 1
fi

echo "no-stringbuilt-sql gate: OK (CH values are bound parameters; no escaping helpers)"
