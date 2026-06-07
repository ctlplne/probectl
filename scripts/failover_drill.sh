#!/usr/bin/env bash
#
# failover_drill.sh — the U-053 TIMED region-failover drill, mirroring the
# documented multi-region model (docs/multi-region.md: one Postgres writer +
# streaming replicas; failover = promote a standby):
#
#   primary + streaming replica → continuous acked writes → KILL -9 the
#   primary → pg_promote() the replica → first successful write on the
#   promoted node.
#
#   RTO = primary-kill → promoted replica ACCEPTING WRITES (measured).
#   RPO = client-ACKED rows missing on the promoted replica (async
#         streaming's honest loss window, measured in rows + seconds).
#
# DESTRUCTIVE to the dev stack (kills its postgres, tears down at the end);
# runs in CI on every pass (failover-drill job). docs/ops/dr.md is the
# runbook + results table.
set -euo pipefail

DEV="deploy/compose/dev.yml"
DRILL="deploy/compose/dr-drill.yml"
DC=(docker compose -f "$DEV" -f "$DRILL")
ACKED="$(mktemp "${TMPDIR:-/tmp}/drill-acked.XXXXXX")"

step() { echo; echo "== failover drill: $1 =="; }
psql_primary() { "${DC[@]}" exec -T postgres psql -U probectl -d probectl -qAt -v ON_ERROR_STOP=1 -c "$1"; }
psql_replica() { "${DC[@]}" exec -T pg-replica psql -U probectl -d probectl -qAt -v ON_ERROR_STOP=1 -c "$1"; }

cleanup() {
  kill "${WPID:-0}" 2>/dev/null || true
  "${DC[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
  rm -f "$ACKED"
}
trap cleanup EXIT

step "boot the primary"
"${DC[@]}" up -d --wait postgres

step "allow streaming replication + start the replica"
"${DC[@]}" exec -T postgres bash -ec \
  'grep -q "host replication probectl" "$PGDATA/pg_hba.conf" || echo "host replication probectl all scram-sha-256" >> "$PGDATA/pg_hba.conf"'
psql_primary "SELECT pg_reload_conf()" >/dev/null
"${DC[@]}" up -d --wait pg-replica
if [ "$(psql_replica 'SELECT pg_is_in_recovery()')" != "t" ]; then
  echo "drill: replica is not in recovery — not a standby?" >&2; exit 1
fi

step "continuous acked writes against the primary"
psql_primary "CREATE TABLE IF NOT EXISTS drill_markers (seq int PRIMARY KEY, at timestamptz NOT NULL DEFAULT now())" >/dev/null
psql_primary "TRUNCATE drill_markers" >/dev/null
(
  i=0
  while :; do
    i=$((i + 1))
    psql_primary "INSERT INTO drill_markers(seq) VALUES ($i)" >/dev/null 2>&1 || break
    echo "$i" > "$ACKED"
  done
) &
WPID=$!
sleep 5 # accumulate a baseline of acked writes at a measured rate
writes_before="$(cat "$ACKED")"
rate="$(awk -v w="$writes_before" 'BEGIN{printf "%.1f", w/5.0}')"
echo "writer: $writes_before acked writes in 5s (~${rate}/s)"

step "REGION LOSS: kill -9 the primary"
t_kill=$(date +%s%N)
"${DC[@]}" kill -s SIGKILL postgres
wait "$WPID" 2>/dev/null || true
last_acked="$(cat "$ACKED")"
echo "last client-ACKED write: seq $last_acked"

step "promote the replica"
psql_replica "SELECT pg_promote(true, 60)" >/dev/null
# RTO clock stops at the first successful WRITE on the promoted node.
until psql_replica "INSERT INTO drill_markers(seq) VALUES (1000000)" >/dev/null 2>&1; do
  sleep 0.2
done
t_ready=$(date +%s%N)
rto_ms=$(((t_ready - t_kill) / 1000000))

step "measure RPO on the promoted node"
survived="$(psql_replica 'SELECT COALESCE(max(seq),0) FROM drill_markers WHERE seq < 1000000')"
lost=$((last_acked - survived))
[ "$lost" -lt 0 ] && lost=0
rpo_s="$(awk -v l="$lost" -v r="$rate" 'BEGIN{ if (r>0) printf "%.2f", l/r; else print "0" }')"

echo
echo "failover drill: PASS — RTO ${rto_ms}ms (kill → promoted+writable); RPO ${lost} acked rows (~${rpo_s}s at ${rate} writes/s)"
echo "record this row in docs/ops/dr.md"
