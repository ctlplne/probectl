#!/usr/bin/env bash
#
# restore_clickhouse.sh <backup-zip-or-zip.pbk> — restore a
# scripts/backup_clickhouse.sh artifact (U-030). Verifies the SHA-256 manifest,
# decrypts .zip.pbk through `probectl-control backup-open`,
# copies the resulting zip back into the server's /backups disk, drops the
# database, and runs `RESTORE DATABASE <db> FROM File(...)` (schema + data +
# the migration ledger).
#
# DESTRUCTIVE: the existing database is dropped. The full procedure and RTO
# expectations are in docs/ops/backup-restore.md.
set -euo pipefail

COMPOSE_FILE="${COMPOSE_FILE:-deploy/compose/dev.yml}"
CH_SERVICE="${CH_SERVICE:-clickhouse}"
CH_USER="${CH_USER:-probectl}"
CH_PASSWORD="${CH_PASSWORD:-probectl}"
CH_DB="${CH_DB:-probectl}"
PCTL_BIN="${PROBECTL_CONTROL_BIN:-probectl-control}"
KEY_FILE="${PROBECTL_BACKUP_KEY_FILE:-${PROBECTL_ENVELOPE_KEY_FILE:-}}"
ZIP="${1:?usage: restore_clickhouse.sh <backup-zip-or-zip.pbk>}"

test -s "${ZIP}" || { echo "restore_clickhouse: no artifact at ${ZIP}" >&2; exit 1; }
test -s "${ZIP}.sha256" || { echo "restore_clickhouse: missing checksum sidecar ${ZIP}.sha256" >&2; exit 1; }
(cd "$(dirname "${ZIP}")" && sha256sum -c "$(basename "${ZIP}").sha256" >/dev/null)
echo "restore_clickhouse: checksum verified"

ch() {
  docker compose -f "${COMPOSE_FILE}" exec -T "${CH_SERVICE}" \
    clickhouse-client --user "${CH_USER}" --password "${CH_PASSWORD}" --query "$1"
}

RESTORE_ZIP="${ZIP}"
TMP_DIR=""
if [[ "${ZIP}" == *.pbk ]]; then
  if [ -z "${PROBECTL_ENVELOPE_KEY:-}" ] && [ -z "${KEY_FILE}" ]; then
    echo "restore_clickhouse: sealed .zip.pbk requires PROBECTL_ENVELOPE_KEY or PROBECTL_BACKUP_KEY_FILE/PROBECTL_ENVELOPE_KEY_FILE" >&2
    exit 1
  fi
  if ! command -v "${PCTL_BIN}" >/dev/null 2>&1; then
    echo "restore_clickhouse: ${PCTL_BIN} not found; set PROBECTL_CONTROL_BIN so backup-open can run" >&2
    exit 1
  fi
  open_cmd=("${PCTL_BIN}" backup-open)
  if [ -n "${KEY_FILE}" ]; then
    open_cmd+=(--key-file "${KEY_FILE}")
  fi
  TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/probectl-ch-restore.XXXXXX")"
  trap 'rm -rf "${TMP_DIR:-}"' EXIT
  RESTORE_ZIP="${TMP_DIR}/$(basename "${ZIP%.pbk}")"
  "${open_cmd[@]}" < "${ZIP}" > "${RESTORE_ZIP}"
  test -s "${RESTORE_ZIP}" || { echo "restore_clickhouse: backup-open produced an empty zip" >&2; exit 1; }
  echo "restore_clickhouse: opened sealed ClickHouse backup ${ZIP}"
fi

BASE="restore-$(basename "${RESTORE_ZIP}")"
docker compose -f "${COMPOSE_FILE}" cp "${RESTORE_ZIP}" "${CH_SERVICE}:/backups/${BASE}"

# The ClickHouse server (uid 101) must be able to write its lock in /backups
# and READ the artifact docker cp just placed there as root (see the backup
# script's note; managed prod uses the pod's fsGroup instead).
docker compose -f "${COMPOSE_FILE}" exec -u 0 -T "${CH_SERVICE}" \
  sh -c "mkdir -p /backups && chmod 1777 /backups && chmod a+r '/backups/${BASE}'" 2>/dev/null || true

ch "DROP DATABASE IF EXISTS ${CH_DB} SYNC"
ch "RESTORE DATABASE ${CH_DB} FROM File('/backups/${BASE}')" > /dev/null

echo "restore_clickhouse: restored ${CH_DB} from ${ZIP}"
