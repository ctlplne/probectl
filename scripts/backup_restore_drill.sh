#!/usr/bin/env bash
#
# backup_restore_drill.sh — the U-030 restore DRILL: seed → backup → wipe →
# restore → verify, against the dev compose stack, asserting byte-for-byte
# marker survival in BOTH datastores and printing the measured backup and
# restore times (the runbook's RTO evidence). Runs on every CI pass (the
# backup-drill job) and locally via `make backup-restore-drill`.
#
# The drill restores from the OFF-BOX copies (the host artifacts the backup
# scripts produced), so it proves the artifact an operator would actually
# carry to a new box — not a warm server-side cache.
set -euo pipefail

COMPOSE_FILE="${COMPOSE_FILE:-deploy/compose/dev.yml}"
export COMPOSE_FILE
PG_ROWS=137
CH_ROWS=251
NONCE="drill-$(date -u +%s)-$$"
OUT="$(mktemp -d "${TMPDIR:-/tmp}/probectl-drill.XXXXXX")"
trap 'rm -rf "${OUT}"' EXIT

step() { echo; echo "== drill: $1 =="; }

psql_db() {
  docker compose -f "${COMPOSE_FILE}" exec -T postgres \
    psql -U probectl -d probectl -v ON_ERROR_STOP=1 -qAt -c "$1"
}
ch() {
  docker compose -f "${COMPOSE_FILE}" exec -T clickhouse \
    clickhouse-client --user probectl --password probectl --query "$1"
}

step "boot postgres + clickhouse (dev compose)"
docker compose -f "${COMPOSE_FILE}" up -d --wait postgres clickhouse

step "seed marker data (nonce ${NONCE})"
psql_db "CREATE TABLE IF NOT EXISTS probectl_drill_marker (id int PRIMARY KEY, nonce text NOT NULL)"
psql_db "TRUNCATE probectl_drill_marker"
psql_db "INSERT INTO probectl_drill_marker SELECT g, '${NONCE}' FROM generate_series(1, ${PG_ROWS}) g"
ch "CREATE TABLE IF NOT EXISTS probectl.probectl_drill_marker (id UInt32, nonce String) ENGINE = MergeTree ORDER BY id"
ch "TRUNCATE TABLE probectl.probectl_drill_marker"
ch "INSERT INTO probectl.probectl_drill_marker SELECT number, '${NONCE}' FROM numbers(${CH_ROWS})"
test "$(psql_db 'SELECT count(*) FROM probectl_drill_marker')" = "${PG_ROWS}"
test "$(ch 'SELECT count() FROM probectl.probectl_drill_marker')" = "${CH_ROWS}"

step "backup both stores"
t0=$(date +%s)
./scripts/backup_postgres.sh "${OUT}"
./scripts/backup_clickhouse.sh "${OUT}"
backup_secs=$(( $(date +%s) - t0 ))
ls -l "${OUT}"

step "WIPE both stores"
docker compose -f "${COMPOSE_FILE}" exec -T postgres \
  psql -U probectl -d postgres -v ON_ERROR_STOP=1 -qAt \
  -c "DROP DATABASE IF EXISTS probectl WITH (FORCE)"
ch "DROP DATABASE IF EXISTS probectl SYNC"
if psql_db "SELECT 1" >/dev/null 2>&1; then
  echo "drill: postgres database still present after wipe" >&2; exit 1
fi
if ch "SELECT count() FROM probectl.probectl_drill_marker" >/dev/null 2>&1; then
  echo "drill: clickhouse database still present after wipe" >&2; exit 1
fi
echo "wipe confirmed: both databases gone"

step "restore from the off-box artifacts"
t1=$(date +%s)
./scripts/restore_postgres.sh "${OUT}"/postgres-probectl-*.dump
./scripts/restore_clickhouse.sh "${OUT}"/clickhouse-probectl-*.zip
restore_secs=$(( $(date +%s) - t1 ))

step "verify marker survival"
pg_count="$(psql_db 'SELECT count(*) FROM probectl_drill_marker')"
pg_nonce="$(psql_db 'SELECT DISTINCT nonce FROM probectl_drill_marker')"
ch_count="$(ch 'SELECT count() FROM probectl.probectl_drill_marker')"
ch_nonce="$(ch 'SELECT DISTINCT nonce FROM probectl.probectl_drill_marker')"
test "${pg_count}" = "${PG_ROWS}" || { echo "drill: postgres rows ${pg_count} != ${PG_ROWS}" >&2; exit 1; }
test "${pg_nonce}" = "${NONCE}" || { echo "drill: postgres nonce mismatch (${pg_nonce})" >&2; exit 1; }
test "${ch_count}" = "${CH_ROWS}" || { echo "drill: clickhouse rows ${ch_count} != ${CH_ROWS}" >&2; exit 1; }
test "${ch_nonce}" = "${NONCE}" || { echo "drill: clickhouse nonce mismatch (${ch_nonce})" >&2; exit 1; }

echo
echo "backup-restore drill: PASS (backup ${backup_secs}s, restore ${restore_secs}s — record in docs/ops/backup-restore.md)"
