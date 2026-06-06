#!/usr/bin/env bash
#
# restore_clickhouse.sh <backup-zip> — restore a scripts/backup_clickhouse.sh
# artifact (U-030). Verifies the SHA-256 manifest when present, copies the
# off-box artifact back into the server's /backups disk, drops the database,
# and runs `RESTORE DATABASE <db> FROM File(...)` (schema + data + the
# migration ledger).
#
# DESTRUCTIVE: the existing database is dropped. The full procedure and RTO
# expectations are in docs/ops/backup-restore.md.
set -euo pipefail

COMPOSE_FILE="${COMPOSE_FILE:-deploy/compose/dev.yml}"
CH_SERVICE="${CH_SERVICE:-clickhouse}"
CH_USER="${CH_USER:-probectl}"
CH_PASSWORD="${CH_PASSWORD:-probectl}"
CH_DB="${CH_DB:-probectl}"
ZIP="${1:?usage: restore_clickhouse.sh <backup-zip>}"

test -s "${ZIP}" || { echo "restore_clickhouse: no artifact at ${ZIP}" >&2; exit 1; }
if [ -f "${ZIP}.sha256" ]; then
  (cd "$(dirname "${ZIP}")" && sha256sum -c "$(basename "${ZIP}").sha256" >/dev/null)
  echo "restore_clickhouse: checksum verified"
fi

ch() {
  docker compose -f "${COMPOSE_FILE}" exec -T "${CH_SERVICE}" \
    clickhouse-client --user "${CH_USER}" --password "${CH_PASSWORD}" --query "$1"
}

BASE="restore-$(basename "${ZIP}")"
docker compose -f "${COMPOSE_FILE}" cp "${ZIP}" "${CH_SERVICE}:/backups/${BASE}"

ch "DROP DATABASE IF EXISTS ${CH_DB} SYNC"
ch "RESTORE DATABASE ${CH_DB} FROM File('/backups/${BASE}')" > /dev/null

echo "restore_clickhouse: restored ${CH_DB} from ${ZIP}"
