#!/usr/bin/env bash
#
# restore_postgres.sh <dump-file> — restore a scripts/backup_postgres.sh
# dump (U-030). Verifies the SHA-256 manifest first, force-drops and
# recreates the database, and pg_restores the dump from stdin (so an
# off-box artifact restores without entering the container's filesystem).
#
# DESTRUCTIVE: the existing database is dropped. The full procedure and RTO
# expectations are in docs/ops/backup-restore.md.
set -euo pipefail

COMPOSE_FILE="${COMPOSE_FILE:-deploy/compose/dev.yml}"
PG_SERVICE="${PG_SERVICE:-postgres}"
PGUSER="${PGUSER:-probectl}"
PGDATABASE="${PGDATABASE:-probectl}"
DUMP="${1:?usage: restore_postgres.sh <dump-file>}"

test -s "${DUMP}" || { echo "restore_postgres: no dump at ${DUMP}" >&2; exit 1; }
test -s "${DUMP}.sha256" || { echo "restore_postgres: missing checksum sidecar ${DUMP}.sha256" >&2; exit 1; }
(cd "$(dirname "${DUMP}")" && sha256sum -c "$(basename "${DUMP}").sha256" >/dev/null)
echo "restore_postgres: checksum verified"

psql_admin() {
  docker compose -f "${COMPOSE_FILE}" exec -T "${PG_SERVICE}" \
    psql -U "${PGUSER}" -d postgres -v ON_ERROR_STOP=1 -qAt -c "$1"
}

psql_admin "DROP DATABASE IF EXISTS \"${PGDATABASE}\" WITH (FORCE)"
psql_admin "CREATE DATABASE \"${PGDATABASE}\" OWNER \"${PGUSER}\""

docker compose -f "${COMPOSE_FILE}" exec -T "${PG_SERVICE}" \
  pg_restore -U "${PGUSER}" -d "${PGDATABASE}" --no-owner --exit-on-error < "${DUMP}"

echo "restore_postgres: restored ${PGDATABASE} from ${DUMP}"
