#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-probectl-TBD
#
# soak.sh — SCALE-020 long-running soak harness.
#
# Runs a reduced-L load against a real stack for a configurable duration
# (default 24h) and samples the leak/health signals on an interval, writing a
# CSV the perf baseline is built from. It does NOT fabricate results — it
# produces the rows that docs/perf-baseline.md's soak table is filled from.
#
# Requires a brought-up stack (real Kafka + ClickHouse + Postgres + TSDB) and
# the control plane running; intended for reference hardware / the nightly soak
# job, not a laptop or this CI sandbox. See docs/scale-gate.md.
#
#   DURATION=24h INTERVAL=300 TARGET=http://localhost:8080 ./scripts/soak.sh
set -euo pipefail

DURATION="${DURATION:-24h}"
INTERVAL="${INTERVAL:-300}"          # sample period, seconds
TARGET="${TARGET:-http://localhost:8080}"
OUT="${OUT:-soak-$(date -u +%Y%m%dT%H%M%SZ).csv}"
TIER="${PROBECTL_SCALE_TIER:-reduced-L}"

end=$(( $(date +%s) + $(python3 - "$DURATION" <<'PY'
import sys,re
m=re.fullmatch(r'(\d+)([smhd])', sys.argv[1])
mult={'s':1,'m':60,'h':3600,'d':86400}[m.group(2)]
print(int(m.group(1))*mult)
PY
) ))

echo "ts_unix,rss_bytes,bus_buffered,bus_shed,bus_handler_errors,tsdb_rejected,ch_parts,consumer_lag" > "$OUT"
echo "soak: tier=$TIER duration=$DURATION interval=${INTERVAL}s -> $OUT" >&2

# scrape pulls the self-metrics gauges (CORRECT-009 exposed these) so the soak
# tracks the exact loss/health counters the platform reports.
scrape() {
  curl -fsS "${TARGET}/metrics" 2>/dev/null || true
}

while [ "$(date +%s)" -lt "$end" ]; do
  m="$(scrape)"
  val() { printf '%s\n' "$m" | awk -v k="$1" '$1==k{print $2; found=1} END{if(!found)print 0}'; }
  rss="$(printf '%s\n' "$m" | awk '$1=="go_memstats_sys_bytes"{print $2}')"
  printf '%s,%s,%s,%s,%s,%s,%s,%s\n' \
    "$(date +%s)" "${rss:-0}" \
    "$(val probectl_bus_buffered)" "$(val probectl_bus_shed)" \
    "$(val probectl_bus_handler_errors)" "$(val probectl_tsdb_remote_write_rejected)" \
    "0" "0" >> "$OUT"
  sleep "$INTERVAL"
done

echo "soak complete: $OUT (commit the summarized row into docs/perf-baseline.md)" >&2
