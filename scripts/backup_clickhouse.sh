#!/usr/bin/env bash
#
# backup_clickhouse.sh <output-dir> — ClickHouse-native backup (U-030).
#
# Runs `BACKUP DATABASE <db> TO File(...)` (every probectl table, including
# the probectl_ch_migrations ledger, U-046) onto the server's /backups disk
# (the chbackups volume; allowed_path comes from
# deploy/compose/clickhouse-backups.xml), then copies the artifact OFF-BOX
# into <output-dir> with a SHA-256 manifest. Restore counterpart:
# scripts/restore_clickhouse.sh.
#
# Env: COMPOSE_FILE (default deploy/compose/dev.yml), CH_SERVICE
#      (clickhouse), CH_USER / CH_PASSWORD / CH_DB (probectl).
set -euo pipefail

COMPOSE_FILE="${COMPOSE_FILE:-deploy/compose/dev.yml}"
CH_SERVICE="${CH_SERVICE:-clickhouse}"
CH_USER="${CH_USER:-probectl}"
CH_PASSWORD="${CH_PASSWORD:-probectl}"
CH_DB="${CH_DB:-probectl}"
OUT_DIR="${1:?usage: backup_clickhouse.sh <output-dir>}"

mkdir -p "${OUT_DIR}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
NAME="clickhouse-${CH_DB}-${STAMP}.zip"

ch() {
  docker compose -f "${COMPOSE_FILE}" exec -T "${CH_SERVICE}" \
    clickhouse-client --user "${CH_USER}" --password "${CH_PASSWORD}" --query "$1"
}

ch "BACKUP DATABASE ${CH_DB} TO File('/backups/${NAME}')" > /dev/null

docker compose -f "${COMPOSE_FILE}" cp "${CH_SERVICE}:/backups/${NAME}" "${OUT_DIR}/${NAME}"
test -s "${OUT_DIR}/${NAME}" || { echo "backup_clickhouse: empty artifact ${NAME}" >&2; exit 1; }
(cd "${OUT_DIR}" && sha256sum "${NAME}" > "${NAME}.sha256")
echo "backup_clickhouse: wrote ${OUT_DIR}/${NAME} ($(wc -c < "${OUT_DIR}/${NAME}") bytes)"
