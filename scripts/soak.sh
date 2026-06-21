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
#
# Optional inputs for richer rows:
#   CONTROL_PID=<pid>                      # true process RSS + fd count
#   CLICKHOUSE_URL=http://user:pass@h:8123 # active part count from system.parts
#   SOAK_QUERY_P95_METRIC=<metric_name>    # p95/query tail gauge exposed on /metrics
set -euo pipefail

DURATION="${DURATION:-24h}"
INTERVAL="${INTERVAL:-300}"          # sample period, seconds
TARGET="${TARGET:-http://localhost:8080}"
OUT="${OUT:-soak-$(date -u +%Y%m%dT%H%M%SZ).csv}"
TIER="${PROBECTL_SCALE_TIER:-reduced-L}"
CONTROL_PID="${CONTROL_PID:-}"
CLICKHOUSE_URL="${CLICKHOUSE_URL:-}"
SOAK_QUERY_P95_METRIC="${SOAK_QUERY_P95_METRIC:-}"

end=$(( $(date +%s) + $(python3 - "$DURATION" <<'PY'
import sys,re
m=re.fullmatch(r'(\d+)([smhd])', sys.argv[1])
mult={'s':1,'m':60,'h':3600,'d':86400}[m.group(2)]
print(int(m.group(1))*mult)
PY
) ))

echo "ts_unix,go_sys_bytes,go_goroutines,go_threads,process_rss_bytes,open_fds,bus_buffered,bus_shed,bus_handler_errors,tsdb_rejected,ch_active_parts,consumer_lag,query_p95_ms" > "$OUT"
echo "soak: tier=$TIER duration=$DURATION interval=${INTERVAL}s -> $OUT" >&2

# scrape pulls the self-metrics gauges (CORRECT-009 exposed these) so the soak
# tracks the exact loss/health counters the platform reports.
scrape() {
  curl -fsS "${TARGET}/metrics" 2>/dev/null || true
}

metric_or_zero() {
  awk -v k="$1" '$1==k{print $2; found=1} END{if(!found)print 0}'
}

metric_or_blank() {
  awk -v k="$1" '$1==k{print $2; found=1} END{if(!found)print ""}'
}

process_rss_bytes() {
  [ -n "$CONTROL_PID" ] || return 0
  ps -o rss= -p "$CONTROL_PID" 2>/dev/null | awk 'NF{print $1 * 1024; found=1} END{if(!found)print ""}'
}

open_fds() {
  [ -n "$CONTROL_PID" ] || return 0
  if [ -d "/proc/$CONTROL_PID/fd" ]; then
    find "/proc/$CONTROL_PID/fd" -maxdepth 1 -type l 2>/dev/null | wc -l | tr -d ' '
  else
    echo ""
  fi
}

clickhouse_active_parts() {
  local from_metrics="$1"
  if [ -n "$from_metrics" ]; then
    echo "$from_metrics"
    return 0
  fi
  [ -n "$CLICKHOUSE_URL" ] || return 0
  curl -fsS --data-binary "SELECT count() FROM system.parts WHERE active" "$CLICKHOUSE_URL" 2>/dev/null | tr -d '[:space:]' || true
}

while [ "$(date +%s)" -lt "$end" ]; do
  m="$(scrape)"
  val0() { printf '%s\n' "$m" | metric_or_zero "$1"; }
  val_blank() { printf '%s\n' "$m" | metric_or_blank "$1"; }
  ch_parts="$(clickhouse_active_parts "$(val_blank probectl_clickhouse_active_parts)")"
  consumer_lag="$(val_blank probectl_bus_consumer_lag)"
  [ -n "$consumer_lag" ] || consumer_lag="$(val_blank probectl_kafka_consumer_lag)"
  query_p95=""
  [ -z "$SOAK_QUERY_P95_METRIC" ] || query_p95="$(val_blank "$SOAK_QUERY_P95_METRIC")"
  printf '%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n' \
    "$(date +%s)" "$(val0 go_memstats_sys_bytes)" "$(val0 go_goroutines)" "$(val0 go_threads)" \
    "$(process_rss_bytes)" "$(open_fds)" \
    "$(val0 probectl_bus_buffered)" "$(val0 probectl_bus_shed)" \
    "$(val0 probectl_bus_handler_errors)" "$(val0 probectl_tsdb_remote_write_rejected)" \
    "$ch_parts" "$consumer_lag" "$query_p95" >> "$OUT"
  sleep "$INTERVAL"
done

echo "soak complete: $OUT (commit the summarized row into docs/perf-baseline.md)" >&2
