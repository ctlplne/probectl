#!/usr/bin/env bash
#
# backup_restore_drill.sh — the U-030 restore DRILL: seed → backup → wipe →
# restore → verify, against the dev compose stack, asserting byte-for-byte
# marker survival in Postgres, ClickHouse, and the object-store/WORM tree, then
# printing the measured backup and restore times (the runbook's RTO evidence).
# Runs on every CI pass (the
# backup-drill job) and locally via `make backup-restore-drill`.
#
# The drill restores from the OFF-BOX copies (the host artifacts the backup
# scripts produced), so it proves the artifact an operator would actually
# carry to a new box — not a warm server-side cache.
set -euo pipefail

COMPOSE_FILE="${COMPOSE_FILE:-deploy/compose/dev.yml}"
export COMPOSE_FILE
COMPOSE_OVERRIDE_FILE="${PROBECTL_COMPOSE_OVERRIDE_FILE:-}"
DC=(docker compose -f "${COMPOSE_FILE}")
if [ -n "${COMPOSE_OVERRIDE_FILE}" ]; then
  DC+=(-f "${COMPOSE_OVERRIDE_FILE}")
fi
DRILL_PROFILE="${PROBECTL_DRILL_PROFILE:-ci-marker}"
PG_ROWS="${PROBECTL_DRILL_PG_ROWS:-137}"
CH_ROWS="${PROBECTL_DRILL_CH_ROWS:-251}"
CH_OTHER_ROWS="${PROBECTL_DRILL_CH_OTHER_ROWS:-17}"
MIN_ARTIFACT_BYTES="${PROBECTL_DRILL_MIN_ARTIFACT_BYTES:-0}"
RTO_BUDGET_SECONDS="${PROBECTL_DRILL_RTO_BUDGET_SECONDS:-0}"
RPO_SECONDS="${PROBECTL_DRILL_RPO_SECONDS:-86400}"
RESULT_FILE="${PROBECTL_DRILL_RESULT_FILE:-}"
RUN_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
GIT_SHA="$(git rev-parse --short=12 HEAD 2>/dev/null || echo unknown)"
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
file_hash() { sha256sum "$1" | awk '{print $1}'; }

for v in PG_ROWS CH_ROWS CH_OTHER_ROWS MIN_ARTIFACT_BYTES RTO_BUDGET_SECONDS RPO_SECONDS; do
  eval "value=\${${v}}"
  is_uint "${value}" || { echo "drill: ${v} must be an unsigned integer, got ${value}" >&2; exit 1; }
done

psql_db() {
  "${DC[@]}" exec -T postgres \
    psql -U probectl -d probectl -v ON_ERROR_STOP=1 -qAt -c "$1"
}
ch() {
  "${DC[@]}" exec -T clickhouse \
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

step "generate and verify signed WORM/object-store fixture"
OBJECTSTORE_LIVE="${OUT}/objectstore-live"
go run ./test/drill/wormfixture --dir "${OBJECTSTORE_LIVE}" --nonce "${NONCE}"
WORM_SEGMENT="${OBJECTSTORE_LIVE}/worm/audit/provider/segment-000000000001-000000000003.json"
WORM_SIGNATURE="${WORM_SEGMENT}.sig"
WORM_PUBLIC_KEY="${OBJECTSTORE_LIVE}/worm/audit/provider/signing.pub"
OBJECT_MARKER="${OBJECTSTORE_LIVE}/tenants/${CH_TENANT}/support/drill-marker.txt"
for artifact in "${WORM_SEGMENT}" "${WORM_SIGNATURE}" "${WORM_PUBLIC_KEY}" "${OBJECT_MARKER}"; do
  test -s "${artifact}" || { echo "drill: WORM/object fixture missing ${artifact}" >&2; exit 1; }
done
worm_segment_hash_before="$(file_hash "${WORM_SEGMENT}")"
worm_signature_hash_before="$(file_hash "${WORM_SIGNATURE}")"
worm_public_key_hash_before="$(file_hash "${WORM_PUBLIC_KEY}")"
object_marker_hash_before="$(file_hash "${OBJECT_MARKER}")"

step "boot postgres + clickhouse (dev compose)"
"${DC[@]}" up -d --wait postgres clickhouse

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

step "backup Postgres + ClickHouse + object-store/WORM"
t0=$(date +%s)
./scripts/backup_postgres.sh "${OUT}"
PROBECTL_CLICKHOUSE_BACKUP_ACK=encrypted-clickhouse-backup-target ./scripts/backup_clickhouse.sh "${OUT}"
PROBECTL_OBJECTSTORE_MODE=filesystem PROBECTL_OBJECTSTORE_DIR="${OBJECTSTORE_LIVE}" \
  ./scripts/backup_objectstore.sh "${OUT}"
backup_secs=$(( $(date +%s) - t0 ))
ls -l "${OUT}"
PBK="$(find "${OUT}" -maxdepth 1 -name 'postgres-probectl-*.dump.pbk' -print -quit)"
CH_PBK="$(find "${OUT}" -maxdepth 1 -name 'clickhouse-probectl-*.zip.pbk' -print -quit)"
OBJECT_PBK="$(find "${OUT}" -maxdepth 1 -name 'objectstore-*.tar.pbk' -print -quit)"
test -n "${PBK}" && test -s "${PBK}" || { echo "drill: backup_postgres did not produce a sealed .dump.pbk" >&2; exit 1; }
test -n "${CH_PBK}" && test -s "${CH_PBK}" || { echo "drill: backup_clickhouse did not produce a sealed .zip.pbk artifact" >&2; exit 1; }
test -n "${OBJECT_PBK}" && test -s "${OBJECT_PBK}" || { echo "drill: backup_objectstore did not produce a sealed .tar.pbk artifact" >&2; exit 1; }
test -s "${PBK}.sha256" || { echo "drill: missing Postgres sealed checksum ${PBK}.sha256" >&2; exit 1; }
test -s "${CH_PBK}.sha256" || { echo "drill: missing ClickHouse sealed checksum ${CH_PBK}.sha256" >&2; exit 1; }
test -s "${OBJECT_PBK}.sha256" || { echo "drill: missing object-store sealed checksum ${OBJECT_PBK}.sha256" >&2; exit 1; }
(cd "$(dirname "${PBK}")" && sha256sum -c "$(basename "${PBK}").sha256" >/dev/null)
(cd "$(dirname "${CH_PBK}")" && sha256sum -c "$(basename "${CH_PBK}").sha256" >/dev/null)
(cd "$(dirname "${OBJECT_PBK}")" && sha256sum -c "$(basename "${OBJECT_PBK}").sha256" >/dev/null)
pbk_bytes="$(file_size "${PBK}")"
ch_bytes="$(file_size "${CH_PBK}")"
objectstore_bytes="$(file_size "${OBJECT_PBK}")"
artifact_bytes=$(( pbk_bytes + ch_bytes + objectstore_bytes ))
if [ "${MIN_ARTIFACT_BYTES}" -gt 0 ] && [ "${artifact_bytes}" -lt "${MIN_ARTIFACT_BYTES}" ]; then
  echo "drill: artifact bytes ${artifact_bytes} below PROBECTL_DRILL_MIN_ARTIFACT_BYTES=${MIN_ARTIFACT_BYTES}; refusing to call this production-shaped evidence" >&2
  exit 1
fi
if find "${OUT}" -maxdepth 1 -name 'postgres-probectl-*.dump' -print -quit | grep -q .; then
  echo "drill: backup_postgres left a plaintext .dump despite sealed default" >&2
  exit 1
fi
if find "${OUT}" -maxdepth 1 -name 'clickhouse-probectl-*.zip' ! -name '*.pbk' -print -quit | grep -q .; then
  echo "drill: backup_clickhouse left a raw .zip despite sealed default" >&2
  exit 1
fi
if find "${OUT}" -maxdepth 1 -name 'objectstore-*.tar' ! -name '*.pbk' -print -quit | grep -q .; then
  echo "drill: backup_objectstore left a plaintext .tar despite sealed default" >&2
  exit 1
fi

step "WIPE all three stores (simulated regional loss; restore only from off-box artifacts)"
"${DC[@]}" exec -T postgres \
  psql -U probectl -d postgres -v ON_ERROR_STOP=1 -qAt \
  -c "DROP DATABASE IF EXISTS probectl WITH (FORCE)"
ch "DROP DATABASE IF EXISTS probectl SYNC"
mv "${OBJECTSTORE_LIVE}" "${OBJECTSTORE_LIVE}.lost"
if psql_db "SELECT 1" >/dev/null 2>&1; then
  echo "drill: postgres database still present after wipe" >&2; exit 1
fi
if ch "SELECT count() FROM probectl.probectl_drill_marker" >/dev/null 2>&1; then
  echo "drill: clickhouse database still present after wipe" >&2; exit 1
fi
test ! -e "${OBJECTSTORE_LIVE}" || { echo "drill: object store still present after wipe" >&2; exit 1; }
echo "wipe confirmed: both databases and object store gone"

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
./scripts/restore_clickhouse.sh "${CH_PBK}"
PROBECTL_OBJECTSTORE_MODE=filesystem PROBECTL_OBJECTSTORE_RESTORE_ACK=replace-objectstore \
  ./scripts/restore_objectstore.sh "${OBJECT_PBK}" "${OBJECTSTORE_LIVE}"
restore_secs=$(( $(date +%s) - t1 ))

step "verify database markers + exact signed WORM/object bytes"
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
test "$(file_hash "${WORM_SEGMENT}")" = "${worm_segment_hash_before}" || { echo "drill: restored WORM segment bytes changed" >&2; exit 1; }
test "$(file_hash "${WORM_SIGNATURE}")" = "${worm_signature_hash_before}" || { echo "drill: restored WORM signature bytes changed" >&2; exit 1; }
test "$(file_hash "${WORM_PUBLIC_KEY}")" = "${worm_public_key_hash_before}" || { echo "drill: restored WORM public key bytes changed" >&2; exit 1; }
test "$(file_hash "${OBJECT_MARKER}")" = "${object_marker_hash_before}" || { echo "drill: restored tenant object bytes changed" >&2; exit 1; }
test "$(cat "${OBJECT_MARKER}")" = "${NONCE}" || { echo "drill: restored object marker nonce mismatch" >&2; exit 1; }
if [ "${RTO_BUDGET_SECONDS}" -gt 0 ] && [ "${restore_secs}" -gt "${RTO_BUDGET_SECONDS}" ]; then
  echo "drill: restore ${restore_secs}s exceeded PROBECTL_DRILL_RTO_BUDGET_SECONDS=${RTO_BUDGET_SECONDS}" >&2
  exit 1
fi

result_row="BACKUP_RESTORE_RESULT run_at=${RUN_AT} git_sha=${GIT_SHA} profile=${DRILL_PROFILE} pg_rows=${PG_ROWS} ch_rows=${CH_ROWS} ch_other_rows=${CH_OTHER_ROWS} worm_events=3 postgres_artifact_bytes=${pbk_bytes} clickhouse_artifact_bytes=${ch_bytes} objectstore_artifact_bytes=${objectstore_bytes} artifact_bytes=${artifact_bytes} backup_secs=${backup_secs} restore_secs=${restore_secs} rpo_seconds=${RPO_SECONDS} rto_budget_seconds=${RTO_BUDGET_SECONDS}"
if [ -n "${RESULT_FILE}" ]; then
  if [ ! -s "${RESULT_FILE}" ]; then
    echo "run_at,git_sha,profile,pg_rows,ch_rows,ch_other_rows,worm_events,postgres_artifact_bytes,clickhouse_artifact_bytes,objectstore_artifact_bytes,artifact_bytes,backup_secs,restore_secs,rpo_seconds,rto_budget_seconds" > "${RESULT_FILE}"
  fi
  echo "${RUN_AT},${GIT_SHA},${DRILL_PROFILE},${PG_ROWS},${CH_ROWS},${CH_OTHER_ROWS},3,${pbk_bytes},${ch_bytes},${objectstore_bytes},${artifact_bytes},${backup_secs},${restore_secs},${RPO_SECONDS},${RTO_BUDGET_SECONDS}" >> "${RESULT_FILE}"
fi

echo
echo "clickhouse regional-loss drill: PASS (tenant ${CH_TENANT} rows ${ch_count}/${CH_ROWS}; default shipped telemetry RPO <= 24h; documented telemetry RPO ${RPO_SECONDS}s with the selected backup cadence)"
echo "object-store/WORM drill: PASS (3-event Ed25519-signed chain + tenant object restored byte-for-byte from sealed .tar.pbk)"
echo "${result_row}"
echo "backup-restore drill: PASS (backup ${backup_secs}s, restore ${restore_secs}s — record in docs/ops/backup-restore.md)"
