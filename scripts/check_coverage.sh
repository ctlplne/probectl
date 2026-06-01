#!/usr/bin/env bash
#
# Coverage gate: enforce a per-package statement-coverage floor from a Go cover
# profile (default coverage.out). A regression that drops a package below its
# floor fails CI.
#
# Scope: the pure-logic / parser / probe packages, whose meaningful coverage does
# NOT need external services. The stateful DB/transport packages (audit, tenancy,
# store/postgres, control, agent, agenttransport) are gated for *correctness* by
# the dedicated `integration` and `cross-tenant-isolation` CI jobs — a stronger
# guarantee than a coverage percentage — so they are not floored here. Generated
# code and not-yet-implemented placeholder packages are exempt.
#
# Floors are set a few points below the coverage measured in CI (the gate's
# environment — some privileged/raw-socket tests skip there), so ordinary refactors
# don't trip the gate while a real drop does. Local privileged runs read higher.
set -euo pipefail

PROFILE="${1:-coverage.out}"
MODULE="github.com/imfeelingtheagi/netctl/"

if [ ! -f "${PROFILE}" ]; then
  echo "coverage gate: profile ${PROFILE} not found (run 'make cover-gate')" >&2
  exit 1
fi

awk -v mod="${MODULE}" '
  BEGIN {
    default_floor = 40
    floor["internal/version"]        = 95
    floor["internal/apierror"]       = 88
    floor["internal/otel"]           = 85
    floor["internal/config"]         = 78
    floor["internal/a2a"]            = 78
    floor["internal/canary"]         = 70
    floor["internal/pipeline"]       = 73
    floor["internal/bus"]            = 70
    floor["internal/bgp"]            = 68
    floor["internal/crypto"]         = 67
    floor["internal/opendata"]       = 80
    floor["internal/alert"]          = 75
    floor["internal/incident"]       = 72
    floor["internal/auth"]           = 72
    floor["internal/ebpf"]           = 72
    # The pooled driver (pooled.go) is exercised by the perf-smoke integration job
    # (needs Postgres) and skips in this service-free gate, so the floor covers the
    # no-DB drivers (metrics/ingest/baseline).
    floor["internal/perf"]           = 60
    # Raw-socket tracer paths need CAP_NET_RAW (skipped in CI); CI coverage is lower
    # than a privileged local run, so this floor reflects the CI-measured value.
    floor["internal/path"]           = 50
    floor["internal/cli"]            = 55
    floor["internal/store/tsdb"]     = 42
    floor["internal/store/pathstore"]= 35
    floor["internal/store/migrate"]  = 28

    n = split("internal/ai internal/billing internal/change internal/compliance internal/cost internal/slo internal/threat internal/topology", ex, " ")
    for (i = 1; i <= n; i++) exempt[ex[i]] = 1
  }
  NR == 1 && $1 == "mode:" { next }
  {
    file = substr($1, 1, index($1, ":") - 1)
    sub("^" mod, "", file)
    parts_n = split(file, parts, "/")
    pkg = parts[1]
    for (i = 2; i < parts_n; i++) pkg = pkg "/" parts[i]
    total[pkg] += $2
    if ($3 + 0 > 0) covered[pkg] += $2
    seen[pkg] = 1
  }
  END {
    k = 0
    for (p in seen) keys[++k] = p
    for (i = 1; i <= k; i++)
      for (j = i + 1; j <= k; j++)
        if (keys[j] < keys[i]) { t = keys[i]; keys[i] = keys[j]; keys[j] = t }

    printf "%-34s %8s %7s   %s\n", "PACKAGE", "COVER", "FLOOR", "STATUS"
    print "----------------------------------------------------------------"
    violations = 0
    for (i = 1; i <= k; i++) {
      p = keys[i]
      pct = total[p] > 0 ? 100.0 * covered[p] / total[p] : 0.0
      if (p ~ /^internal\/gen\//  || p in exempt) {
        printf "%-34s %7.1f%% %7s   exempt\n", p, pct, "-"
        continue
      }
      fl = (p in floor) ? floor[p] : default_floor
      status = (pct + 0.05 >= fl) ? "ok" : "LOW"
      if (status == "LOW") violations++
      printf "%-34s %7.1f%% %7d   %s\n", p, pct, fl, status
    }
    print "----------------------------------------------------------------"
    if (violations > 0) {
      printf "coverage gate: FAIL — %d package(s) below floor\n", violations
      exit 3
    }
    print "coverage gate: OK"
  }
' "${PROFILE}"
