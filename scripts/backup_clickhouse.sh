#!/usr/bin/env bash
#
# backup_clickhouse.sh <output-dir> — ClickHouse-native backup (U-030).
#
# Runs `BACKUP DATABASE <db> TO File(...)` (every probectl table, including
# the probectl_ch_migrations ledger, U-046) onto the server's /backups disk
# (the chbackups volume; allowed_path comes from
# deploy/compose/clickhouse-backups.xml), then streams that server-side .zip
# through `probectl-control backup-seal` before anything lands off-box. The
# default host artifact is .zip.pbk plus a SHA-256 manifest. Restore
# counterpart: scripts/restore_clickhouse.sh.
#
# Env: COMPOSE_FILE (default deploy/compose/dev.yml), CH_SERVICE
#      (clickhouse), CH_USER / CH_PASSWORD / CH_DB (probectl),
#      PROBECTL_CONTROL_BIN (probectl-control), PROBECTL_ENVELOPE_KEY or
#      PROBECTL_BACKUP_KEY_FILE/PROBECTL_ENVELOPE_KEY_FILE.
#
# Raw .zip output is permitted only when the server backup path and off-box
# target are encrypted operator-controlled storage:
#   PROBECTL_CLICKHOUSE_BACKUP_ACK=encrypted-clickhouse-backup-target
set -euo pipefail

COMPOSE_FILE="${COMPOSE_FILE:-deploy/compose/dev.yml}"
CH_SERVICE="${CH_SERVICE:-clickhouse}"
CH_USER="${CH_USER:-probectl}"
CH_PASSWORD="${CH_PASSWORD:-probectl}"
CH_DB="${CH_DB:-probectl}"
ACK="${PROBECTL_CLICKHOUSE_BACKUP_ACK:-}"
PCTL_BIN="${PROBECTL_CONTROL_BIN:-probectl-control}"
KEY_FILE="${PROBECTL_BACKUP_KEY_FILE:-${PROBECTL_ENVELOPE_KEY_FILE:-}}"
OUT_DIR="${1:?usage: backup_clickhouse.sh <output-dir>}"

seal_cmd=("${PCTL_BIN}" backup-seal)
if [ -n "${KEY_FILE}" ]; then
  seal_cmd+=(--key-file "${KEY_FILE}")
fi

can_seal=false
if [ -n "${PROBECTL_ENVELOPE_KEY:-}" ] || [ -n "${KEY_FILE}" ]; then
  can_seal=true
fi

if [ "${can_seal}" = "true" ] && ! command -v "${PCTL_BIN}" >/dev/null 2>&1; then
  echo "backup_clickhouse: ${PCTL_BIN} not found; set PROBECTL_CONTROL_BIN so backup-seal can run" >&2
  exit 1
fi

if [ "${can_seal}" != "true" ] && [[ "${ACK}" != "encrypted-clickhouse-backup-target" ]]; then
  cat >&2 <<'EOF'
backup_clickhouse: refusing to write an off-box raw ClickHouse .zip.
Set PROBECTL_ENVELOPE_KEY or PROBECTL_BACKUP_KEY_FILE/PROBECTL_ENVELOPE_KEY_FILE
so backup-seal can write a .zip.pbk artifact. If you intentionally rely on an
encrypted ClickHouse backup path and encrypted off-box target, set
PROBECTL_CLICKHOUSE_BACKUP_ACK=encrypted-clickhouse-backup-target. A raw .zip
contains tenant telemetry.
EOF
  exit 1
fi

mkdir -p "${OUT_DIR}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
NAME="clickhouse-${CH_DB}-${STAMP}.zip"

ch() {
  docker compose -f "${COMPOSE_FILE}" exec -T "${CH_SERVICE}" \
    clickhouse-client --user "${CH_USER}" --password "${CH_PASSWORD}" --query "$1"
}

# A fresh backups volume mounts root-owned, but the ClickHouse server runs as
# the clickhouse user (uid 101) and must write the backup + its lock file.
# Best-effort make it writable via a root exec on the dev/compose stack; this
# no-ops where exec-as-root is unavailable, and managed production sets the
# ClickHouse pod's securityContext.fsGroup to the clickhouse gid instead
# (see deploy/backup/README.md).
docker compose -f "${COMPOSE_FILE}" exec -u 0 -T "${CH_SERVICE}" \
  sh -c 'mkdir -p /backups && chmod 1777 /backups' 2>/dev/null || true

ch "BACKUP DATABASE ${CH_DB} TO File('/backups/${NAME}')" > /dev/null

if [ "${can_seal}" = "true" ]; then
  OUT="${OUT_DIR}/${NAME}.pbk"
  TMP="${OUT}.tmp"
  trap 'rm -f "${TMP:-}"' EXIT
  docker compose -f "${COMPOSE_FILE}" exec -T "${CH_SERVICE}" \
    sh -c 'cat "$1"' sh "/backups/${NAME}" \
    | "${seal_cmd[@]}" > "${TMP}"
  test -s "${TMP}" || { echo "backup_clickhouse: empty sealed artifact ${OUT}" >&2; exit 1; }
  mv "${TMP}" "${OUT}"
  trap - EXIT
  docker compose -f "${COMPOSE_FILE}" exec -T "${CH_SERVICE}" \
    sh -c 'rm -f "$1"' sh "/backups/${NAME}" >/dev/null 2>&1 || true
  (cd "${OUT_DIR}" && sha256sum "$(basename "${OUT}")" > "$(basename "${OUT}").sha256")
  echo "backup_clickhouse: wrote sealed ClickHouse artifact ${OUT} via backup-seal" >&2
  echo "backup_clickhouse: wrote ${OUT} ($(wc -c < "${OUT}") bytes)"
else
  docker compose -f "${COMPOSE_FILE}" cp "${CH_SERVICE}:/backups/${NAME}" "${OUT_DIR}/${NAME}"
  test -s "${OUT_DIR}/${NAME}" || { echo "backup_clickhouse: empty artifact ${NAME}" >&2; exit 1; }
  (cd "${OUT_DIR}" && sha256sum "${NAME}" > "${NAME}.sha256")
  echo "backup_clickhouse: wrote raw ClickHouse artifact under explicit encrypted-target ack PROBECTL_CLICKHOUSE_BACKUP_ACK=encrypted-clickhouse-backup-target" >&2
  echo "backup_clickhouse: wrote ${OUT_DIR}/${NAME} ($(wc -c < "${OUT_DIR}/${NAME}") bytes)"
fi
