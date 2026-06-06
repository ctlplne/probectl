#!/usr/bin/env bash
#
# backup_postgres.sh <output-dir> — logical Postgres backup (U-030).
#
# Takes a pg_dump (custom format, --no-owner) of the probectl database by
# exec-ing INSIDE the compose postgres container (no host pg client needed)
# and writes it to <output-dir> with a SHA-256 manifest. Production cron
# examples (compose overlay + k8s CronJob) live in deploy/backup/; the
# restore counterpart is scripts/restore_postgres.sh.
#
# Env: COMPOSE_FILE (default deploy/compose/dev.yml), PG_SERVICE (postgres),
#      PGUSER / PGDATABASE (probectl).
set -euo pipefail

COMPOSE_FILE="${COMPOSE_FILE:-deploy/compose/dev.yml}"
PG_SERVICE="${PG_SERVICE:-postgres}"
PGUSER="${PGUSER:-probectl}"
PGDATABASE="${PGDATABASE:-probectl}"
OUT_DIR="${1:?usage: backup_postgres.sh <output-dir>}"

mkdir -p "${OUT_DIR}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="${OUT_DIR}/postgres-${PGDATABASE}-${STAMP}.dump"

docker compose -f "${COMPOSE_FILE}" exec -T "${PG_SERVICE}" \
  pg_dump -U "${PGUSER}" -d "${PGDATABASE}" --format=custom --no-owner > "${OUT}"

test -s "${OUT}" || { echo "backup_postgres: empty dump ${OUT}" >&2; exit 1; }
(cd "${OUT_DIR}" && sha256sum "$(basename "${OUT}")" > "$(basename "${OUT}").sha256")
echo "backup_postgres: wrote ${OUT} ($(wc -c < "${OUT}") bytes)"
