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
DRILL_PROFILE="${PROBECTL_DRILL_PROFILE:-ci-marker}"
PG_ROWS="${PROBECTL_DRILL_PG_ROWS:-137}"
CH_ROWS="${PROBECTL_DRILL_CH_ROWS:-251}"
CH_OTHER_ROWS="${PROBECTL_DRILL_CH_OTHER_ROWS:-17}"
MIN_ARTIFACT_BYTES="${PROBECTL_DRILL_MIN_ARTIFACT_BYTES:-0}"
RTO_BUDGET_SECONDS="${PROBECTL_DRILL_RTO_BUDGET_SECONDS:-0}"
RESULT_FILE="${PROBECTL_DRILL_RESULT_FILE:-}"
CH_TENANT="11111111-1111-1111-1111-111111111111"
CH_OTHER_TENANT="22222222-2222-2222-2222-222222222222"
NONCE="drill-$(date -u +%s)-$$"
OUT="$(mktemp -d "${TMPDIR:-/tmp}/probectl-drill.XXXXXX")"
trap 'rm -rf "${OUT}"' EXIT

step() { echo; echo "== drill: $1 =="; }
is_uint() { case "$1" in ""|*[!0-9]*) return 1 ;; *) return 0 ;; esac; }
file_size() {
  if stat -c %s "$1" >/dev/null 2>&1; then
    stat -c %s "$1"
  else
    stat -f %z "$1"
  fi
}

for v in PG_ROWS CH_ROWS CH_OTHER_ROWS MIN_ARTIFACT_BYTES RTO_BUDGET_SECONDS; do
  eval "value=\${${v}}"
  is_uint "${value}" || { echo "drill: ${v} must be an unsigned integer, got ${value}" >&2; exit 1; }
done

psql_db() {
  docker compose -f "${COMPOSE_FILE}" exec -T postgres \
    psql -U probectl -d probectl -v ON_ERROR_STOP=1 -qAt -c "$1"
}
ch() {
  docker compose -f "${COMPOSE_FILE}" exec -T clickhouse \
    clickhouse-client --user probectl --password probectl --query "$1"
}

step "prepare backup sealing key + probectl-control"
PCTL_BIN="$(command -v probectl-control || true)"
if [ -z "${PCTL_BIN}" ]; then
  PCTL_BIN="${OUT}/probectl-control"
  ( cd "$(git rev-parse --show-toplevel 2>/dev/null || echo .)" && go build -o "${PCTL_BIN}" ./cmd/probectl-control )
fi
# 32-byte KEK, base64 — the same env var the Helm restore Job feeds the binary.
export PROBECTL_ENVELOPE_KEY="$(head -c 32 /dev/urandom | base64 | tr -d '\n')"
export PROBECTL_CONTROL_BIN="${PCTL_BIN}"

step "boot postgres + clickhouse (dev compose)"
docker compose -f "${COMPOSE_FILE}" up -d --wait postgres clickhouse

step "seed marker data (nonce ${NONCE})"
psql_db "CREATE TABLE IF NOT EXISTS probectl_drill_marker (id int PRIMARY KEY, nonce text NOT NULL)"
psql_db "TRUNCATE probectl_drill_marker"
psql_db "INSERT INTO probectl_drill_marker SELECT g, '${NONCE}' FROM generate_series(1, ${PG_ROWS}) g"
ch "CREATE TABLE IF NOT EXISTS probectl.probectl_drill_marker (tenant_id String, id UInt32, nonce String) ENGINE = MergeTree ORDER BY (tenant_id, id)"
ch "TRUNCATE TABLE probectl.probectl_drill_marker"
ch "INSERT INTO probectl.probectl_drill_marker SELECT '${CH_TENANT}', number, '${NONCE}' FROM numbers(${CH_ROWS})"
ch "INSERT INTO probectl.probectl_drill_marker SELECT '${CH_OTHER_TENANT}', number, '${NONCE}' FROM numbers(${CH_OTHER_ROWS})"
test "$(psql_db 'SELECT count(*) FROM probectl_drill_marker')" = "${PG_ROWS}"
test "$(ch "SELECT count() FROM probectl.probectl_drill_marker WHERE tenant_id = '${CH_TENANT}'")" = "${CH_ROWS}"
test "$(ch "SELECT count() FROM probectl.probectl_drill_marker WHERE tenant_id = '${CH_OTHER_TENANT}'")" = "${CH_OTHER_ROWS}"

step "backup both stores"
t0=$(date +%s)
./scripts/backup_postgres.sh "${OUT}"
./scripts/backup_clickhouse.sh "${OUT}"
backup_secs=$(( $(date +%s) - t0 ))
ls -l "${OUT}"
PBK="$(find "${OUT}" -maxdepth 1 -name 'postgres-probectl-*.dump.pbk' -print -quit)"
CH_ZIP="$(find "${OUT}" -maxdepth 1 -name 'clickhouse-probectl-*.zip' -print -quit)"
test -n "${PBK}" && test -s "${PBK}" || { echo "drill: backup_postgres did not produce a sealed .dump.pbk" >&2; exit 1; }
test -n "${CH_ZIP}" && test -s "${CH_ZIP}" || { echo "drill: backup_clickhouse did not produce a .zip artifact" >&2; exit 1; }
test -s "${PBK}.sha256" || { echo "drill: missing Postgres sealed checksum ${PBK}.sha256" >&2; exit 1; }
(cd "$(dirname "${PBK}")" && sha256sum -c "$(basename "${PBK}").sha256" >/dev/null)
pbk_bytes="$(file_size "${PBK}")"
ch_bytes="$(file_size "${CH_ZIP}")"
artifact_bytes=$(( pbk_bytes + ch_bytes ))
if [ "${MIN_ARTIFACT_BYTES}" -gt 0 ] && [ "${artifact_bytes}" -lt "${MIN_ARTIFACT_BYTES}" ]; then
  echo "drill: artifact bytes ${artifact_bytes} below PROBECTL_DRILL_MIN_ARTIFACT_BYTES=${MIN_ARTIFACT_BYTES}; refusing to call this production-shaped evidence" >&2
  exit 1
fi
if find "${OUT}" -maxdepth 1 -name 'postgres-probectl-*.dump' -print -quit | grep -q .; then
  echo "drill: backup_postgres left a plaintext .dump despite sealed default" >&2
  exit 1
fi

step "WIPE both stores (simulated regional loss; restore only from off-box artifacts)"
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

step "restore from the ENCRYPTED .pbk via backup-open (the shipped Job's command)"
t1=$(date +%s)
# Mirror restore-job.yaml line-for-line: backup-open reads the .pbk on stdin
# (NO --in/--out flags) and emits the plaintext dump on stdout for restore.
DECRYPTED="${OUT}/postgres-probectl.decrypted.dump"
(cd "$(dirname "${PBK}")" && sha256sum -c "$(basename "${PBK}").sha256" >/dev/null)
"${PCTL_BIN}" backup-open < "${PBK}" > "${DECRYPTED}"
test -s "${DECRYPTED}" || { echo "drill: backup-open produced an empty dump (flag/contract break?)" >&2; exit 1; }
(cd "$(dirname "${DECRYPTED}")" && sha256sum "$(basename "${DECRYPTED}")" > "$(basename "${DECRYPTED}").sha256")
./scripts/restore_postgres.sh "${DECRYPTED}"
./scripts/restore_clickhouse.sh "${CH_ZIP}"
restore_secs=$(( $(date +%s) - t1 ))

step "verify marker survival"
pg_count="$(psql_db 'SELECT count(*) FROM probectl_drill_marker')"
pg_nonce="$(psql_db 'SELECT DISTINCT nonce FROM probectl_drill_marker')"
ch_count="$(ch "SELECT count() FROM probectl.probectl_drill_marker WHERE tenant_id = '${CH_TENANT}'")"
ch_other_count="$(ch "SELECT count() FROM probectl.probectl_drill_marker WHERE tenant_id = '${CH_OTHER_TENANT}'")"
ch_nonce="$(ch "SELECT DISTINCT nonce FROM probectl.probectl_drill_marker WHERE tenant_id = '${CH_TENANT}'")"
test "${pg_count}" = "${PG_ROWS}" || { echo "drill: postgres rows ${pg_count} != ${PG_ROWS}" >&2; exit 1; }
test "${pg_nonce}" = "${NONCE}" || { echo "drill: postgres nonce mismatch (${pg_nonce})" >&2; exit 1; }
test "${ch_count}" = "${CH_ROWS}" || { echo "drill: clickhouse rows ${ch_count} != ${CH_ROWS}" >&2; exit 1; }
test "${ch_other_count}" = "${CH_OTHER_ROWS}" || { echo "drill: clickhouse other-tenant rows ${ch_other_count} != ${CH_OTHER_ROWS}" >&2; exit 1; }
test "${ch_nonce}" = "${NONCE}" || { echo "drill: clickhouse nonce mismatch (${ch_nonce})" >&2; exit 1; }
if [ "${RTO_BUDGET_SECONDS}" -gt 0 ] && [ "${restore_secs}" -gt "${RTO_BUDGET_SECONDS}" ]; then
  echo "drill: restore ${restore_secs}s exceeded PROBECTL_DRILL_RTO_BUDGET_SECONDS=${RTO_BUDGET_SECONDS}" >&2
  exit 1
fi

result_row="BACKUP_RESTORE_RESULT profile=${DRILL_PROFILE} pg_rows=${PG_ROWS} ch_rows=${CH_ROWS} ch_other_rows=${CH_OTHER_ROWS} postgres_artifact_bytes=${pbk_bytes} clickhouse_artifact_bytes=${ch_bytes} artifact_bytes=${artifact_bytes} backup_secs=${backup_secs} restore_secs=${restore_secs} rto_budget_seconds=${RTO_BUDGET_SECONDS}"
if [ -n "${RESULT_FILE}" ]; then
  if [ ! -s "${RESULT_FILE}" ]; then
    echo "profile,pg_rows,ch_rows,ch_other_rows,postgres_artifact_bytes,clickhouse_artifact_bytes,artifact_bytes,backup_secs,restore_secs,rto_budget_seconds" > "${RESULT_FILE}"
  fi
  echo "${DRILL_PROFILE},${PG_ROWS},${CH_ROWS},${CH_OTHER_ROWS},${pbk_bytes},${ch_bytes},${artifact_bytes},${backup_secs},${restore_secs},${RTO_BUDGET_SECONDS}" >> "${RESULT_FILE}"
fi

echo
echo "clickhouse regional-loss drill: PASS (tenant ${CH_TENANT} rows ${ch_count}/${CH_ROWS}; default shipped telemetry RPO <= 24h with nightly off-region backups)"
echo "${result_row}"
echo "backup-restore drill: PASS (backup ${backup_secs}s, restore ${restore_secs}s — record in docs/ops/backup-restore.md)"
