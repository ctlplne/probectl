#!/usr/bin/env bash
#
# backup_postgres.sh <output-dir> — logical Postgres backup (U-030).
#
# Takes a pg_dump (custom format, --no-owner) of the probectl database by
# exec-ing INSIDE the compose postgres container (no host pg client needed)
# and streams it through `probectl-control backup-seal` before anything lands
# in <output-dir>. The default artifact is .dump.pbk plus a SHA-256 manifest.
# Production cron examples (compose overlay + k8s CronJob) live in
# deploy/backup/; the restore counterpart is scripts/restore_postgres.sh.
#
# Env: COMPOSE_FILE (default deploy/compose/dev.yml), PG_SERVICE (postgres),
#      PGUSER / PGDATABASE (probectl), PROBECTL_CONTROL_BIN
#      (probectl-control), PROBECTL_ENVELOPE_KEY or
#      PROBECTL_BACKUP_KEY_FILE/PROBECTL_ENVELOPE_KEY_FILE.
#
# Plaintext tenant backups are break-glass only:
#   PROBECTL_PLAINTEXT_BACKUP_ACK=allow-plaintext-tenant-backup
set -euo pipefail

COMPOSE_FILE="${COMPOSE_FILE:-deploy/compose/dev.yml}"
PG_SERVICE="${PG_SERVICE:-postgres}"
PGUSER="${PGUSER:-probectl}"
PGDATABASE="${PGDATABASE:-probectl}"
PCTL_BIN="${PROBECTL_CONTROL_BIN:-probectl-control}"
KEY_FILE="${PROBECTL_BACKUP_KEY_FILE:-${PROBECTL_ENVELOPE_KEY_FILE:-}}"
PLAINTEXT_ACK="${PROBECTL_PLAINTEXT_BACKUP_ACK:-}"
OUT_DIR="${1:?usage: backup_postgres.sh <output-dir>}"

mkdir -p "${OUT_DIR}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"

seal_cmd=("${PCTL_BIN}" backup-seal)
if [ -n "${KEY_FILE}" ]; then
  seal_cmd+=(--key-file "${KEY_FILE}")
fi

if [ "${PLAINTEXT_ACK}" = "allow-plaintext-tenant-backup" ]; then
  OUT="${OUT_DIR}/postgres-${PGDATABASE}-${STAMP}.dump"
  TMP="${OUT}.tmp"
  trap 'rm -f "${TMP:-}"' EXIT
  echo "backup_postgres: WARNING writing PLAINTEXT tenant backup under explicit break-glass ack" >&2
  docker compose -f "${COMPOSE_FILE}" exec -T "${PG_SERVICE}" \
    pg_dump -U "${PGUSER}" -d "${PGDATABASE}" --format=custom --no-owner > "${TMP}"
else
  OUT="${OUT_DIR}/postgres-${PGDATABASE}-${STAMP}.dump.pbk"
  TMP="${OUT}.tmp"
  trap 'rm -f "${TMP:-}"' EXIT
  if [ -z "${PROBECTL_ENVELOPE_KEY:-}" ] && [ -z "${KEY_FILE}" ]; then
    echo "backup_postgres: refusing to write plaintext tenant backup; set PROBECTL_ENVELOPE_KEY or PROBECTL_BACKUP_KEY_FILE/PROBECTL_ENVELOPE_KEY_FILE for backup-seal" >&2
    echo "backup_postgres: break-glass plaintext requires PROBECTL_PLAINTEXT_BACKUP_ACK=allow-plaintext-tenant-backup" >&2
    exit 1
  fi
  if ! command -v "${PCTL_BIN}" >/dev/null 2>&1; then
    echo "backup_postgres: ${PCTL_BIN} not found; set PROBECTL_CONTROL_BIN to probectl-control so backup-seal can run" >&2
    exit 1
  fi
  docker compose -f "${COMPOSE_FILE}" exec -T "${PG_SERVICE}" \
    pg_dump -U "${PGUSER}" -d "${PGDATABASE}" --format=custom --no-owner \
    | "${seal_cmd[@]}" > "${TMP}"
fi

test -s "${TMP}" || { echo "backup_postgres: empty backup ${OUT}" >&2; exit 1; }
mv "${TMP}" "${OUT}"
trap - EXIT
(cd "${OUT_DIR}" && sha256sum "$(basename "${OUT}")" > "$(basename "${OUT}").sha256")
echo "backup_postgres: wrote ${OUT} ($(wc -c < "${OUT}") bytes)"

# RTO-15: a logical pg_dump does NOT carry cluster ROLES, so restoring onto a
# brand-new cluster aborted on the first object/policy that references the app
# roles (probectl_app et al., created by migrations). Write a companion roles
# file — all probectl* roles with their attributes, WITHOUT password hashes
# (--no-role-passwords, so no secret leaves the source) — that restore_postgres.sh
# applies before the data restore. The login role's password is re-set from the
# operator's own credentials at restore time, not carried here.
#
# Each `CREATE ROLE` is rewritten into a duplicate-tolerant DO block. pg_dumpall
# emits a bare `CREATE ROLE probectl;` for the cluster's OWN bootstrap superuser,
# and that role ALWAYS exists on the restore target (probectl's compose/Helm
# Postgres is initdb'd with probectl as the superuser), so a plain CREATE would
# abort the whole restore under ON_ERROR_STOP. The guard lets a pre-existing role
# pass while the ALTER that follows still (re)asserts its exact attributes;
# genuinely missing roles (the fresh-cluster case) are still created.
ROLES_OUT="${OUT}.roles.sql"
docker compose -f "${COMPOSE_FILE}" exec -T "${PG_SERVICE}" \
  pg_dumpall -U "${PGUSER}" --roles-only --no-role-passwords 2>/dev/null \
  | grep -iE '(CREATE|ALTER|GRANT) .*probectl' \
  | awk '
      /^CREATE ROLE / { r=$0; sub(/^CREATE ROLE /,"",r); sub(/;[[:space:]]*$/,"",r);
        printf "DO $$ BEGIN CREATE ROLE %s; EXCEPTION WHEN duplicate_object THEN NULL; END $$;\n", r; next }
      { print }' > "${ROLES_OUT}"
test -s "${ROLES_OUT}" || { echo "backup_postgres: refusing empty roles companion ${ROLES_OUT} (no probectl* roles found)" >&2; exit 1; }
(cd "${OUT_DIR}" && sha256sum "$(basename "${ROLES_OUT}")" > "$(basename "${ROLES_OUT}").sha256")
echo "backup_postgres: wrote ${ROLES_OUT} ($(grep -c 'CREATE ROLE' "${ROLES_OUT}") roles)"
