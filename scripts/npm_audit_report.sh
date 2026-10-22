#!/usr/bin/env bash
# SPDX-License-Identifier: BUSL-1.1
#
# Use of this source code is governed by the Business Source License 1.1
# in the LICENSE file at the root of this repository; on its Change Date
# each version converts to the Mozilla Public License 2.0.

# npm_audit_report.sh <out.json> — write `npm audit --json` for the package in
# the current directory to <out.json>, asking again (three attempts) when the
# registry returns no usable report. On 2026-10-22 the audit endpoint answered
# 503 Service Unavailable and turned `main` red for a reason no commit carried.
#
# npm exits non-zero whenever it finds a vulnerability, so its exit status says
# nothing here: a report is recognized by its shape (`auditReportVersion`).
# Judging the report stays with scripts/check_npm_audit_policy.mjs, which fails
# closed on a missing or unusable report, so a registry that never answers still
# fails the gate. This only stops one transient error from deciding it.
#
#   bash ../scripts/npm_audit_report.sh ../npm-audit-web.json
#   bash scripts/npm_audit_report.sh --selftest
set -uo pipefail

usable() { # usable <file> — a parsed npm audit report, not an error body
  node -e 'const r = JSON.parse(require("fs").readFileSync(process.argv[1], "utf8")); process.exit(r && r.auditReportVersion ? 0 : 1)' "$1" 2>/dev/null
}

report() { # report <out.json>
  local out="$1" attempt
  for attempt in 1 2 3; do
    npm audit --json > "$out" 2>/dev/null
    if usable "$out"; then
      return 0
    fi
    echo "npm audit returned no usable report (attempt ${attempt} of 3)" >&2
    if [ "$attempt" -lt 3 ]; then sleep "${NPM_AUDIT_RETRY_SECONDS:-20}"; fi
  done
  # The unusable body is left in place for the policy gate to refuse.
  return 0
}

selftest() {
  local dir fail=0
  dir="$(mktemp -d)"
  mkdir -p "$dir/bin"
  # A registry that fails twice and then answers.
  cat > "$dir/bin/npm" <<'STUB'
#!/usr/bin/env bash
n="$(cat "$STUB_COUNT" 2>/dev/null || echo 0)"; n=$((n + 1)); echo "$n" > "$STUB_COUNT"
if [ "$n" -lt 3 ]; then echo '{"error":{"code":"E503","summary":"Service Unavailable"}}'; exit 1; fi
echo '{"auditReportVersion":2,"vulnerabilities":{},"metadata":{}}'; exit 1
STUB
  chmod +x "$dir/bin/npm"
  STUB_COUNT="$dir/count" NPM_AUDIT_RETRY_SECONDS=0 PATH="$dir/bin:$PATH" report "$dir/out.json" 2>/dev/null
  if ! usable "$dir/out.json"; then
    echo "SELFTEST FAIL: a registry that answered on the third attempt left no usable report" >&2; fail=1
  fi
  # A registry that never answers leaves the error body for the policy gate.
  printf '#!/usr/bin/env bash\necho %s; exit 1\n' "'{\"error\":{\"code\":\"E503\"}}'" > "$dir/bin/npm"
  NPM_AUDIT_RETRY_SECONDS=0 PATH="$dir/bin:$PATH" report "$dir/out2.json" 2>/dev/null
  if usable "$dir/out2.json"; then
    echo "SELFTEST FAIL: a registry that never answered produced a usable report" >&2; fail=1
  fi
  rm -rf "$dir"
  if [ "$fail" -ne 0 ]; then
    echo "npm_audit_report SELFTEST: FAILED" >&2
    return 1
  fi
  echo "npm_audit_report SELFTEST: OK (a transient error is retried; a dead endpoint still reaches the policy gate unusable)"
}

if [ "${1:-}" = "--selftest" ]; then
  selftest
  exit $?
fi
report "${1:?usage: npm_audit_report.sh <out.json> | --selftest}"
exit $?
