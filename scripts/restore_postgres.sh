#!/usr/bin/env bash
#
# restore_postgres.sh <dump-file> — restore a scripts/backup_postgres.sh
# dump (U-030). Verifies the SHA-256 manifest first, force-drops and
# recreates the database, and pg_restores the dump from stdin (so an
# off-box artifact restores without entering the container's filesystem).
#
# RTO-15: a plain `pg_dump` logical dump does NOT carry the cluster's ROLES, so
# restoring onto a BRAND-NEW Postgres cluster (the real disaster-recovery case —
# a fresh box with only the bootstrap superuser) failed: the dump's objects,
# GRANTs and RLS policies reference the `probectl` role, and `CREATE DATABASE …
# OWNER probectl` / connecting as `probectl` cannot even run when that role does
# not exist yet. We therefore RECREATE the application role from the operator's
# own credentials (never from the dump — a dumped password hash would be a
# backup-exfil risk) as the bootstrap SUPERUSER before touching the database.
#
# DESTRUCTIVE: the existing database is dropped. The full procedure and RTO
# expectations are in docs/ops/backup-restore.md.
#
# Env:
#   COMPOSE_FILE (deploy/compose/dev.yml), PG_SERVICE (postgres)
#   PGUSER / PGDATABASE (probectl)          — the application role + database
#   PGSUPERUSER (postgres)                  — the bootstrap superuser on the target
#   PGAPPPASSWORD                           — password to (re)create PGUSER with on a
#                                             fresh cluster; defaults to PGUSER
#   PROBECTL_PG_EXEC                        — override the exec wrapper (testing):
#                                             a command prefix that runs its args
#                                             inside the target Postgres container
set -euo pipefail

COMPOSE_FILE="${COMPOSE_FILE:-deploy/compose/dev.yml}"
PG_SERVICE="${PG_SERVICE:-postgres}"
PGUSER="${PGUSER:-probectl}"
PGDATABASE="${PGDATABASE:-probectl}"
PGSUPERUSER="${PGSUPERUSER:-postgres}"
PGAPPPASSWORD="${PGAPPPASSWORD:-${PGUSER}}"
DUMP="${1:?usage: restore_postgres.sh <dump-file>}"

test -s "${DUMP}" || { echo "restore_postgres: no dump at ${DUMP}" >&2; exit 1; }
test -s "${DUMP}.sha256" || { echo "restore_postgres: missing checksum sidecar ${DUMP}.sha256" >&2; exit 1; }
(cd "$(dirname "${DUMP}")" && sha256sum -c "$(basename "${DUMP}").sha256" >/dev/null)
echo "restore_postgres: checksum verified"

# pg_exec runs its arguments inside the target Postgres container. The default
# uses the dev compose stack; PROBECTL_PG_EXEC overrides it (e.g. a standalone
# `docker exec <container>` for the fresh-cluster restore drill).
if [ -n "${PROBECTL_PG_EXEC:-}" ]; then
  # shellcheck disable=SC2206
  PG_EXEC=(${PROBECTL_PG_EXEC})
else
  PG_EXEC=(docker compose -f "${COMPOSE_FILE}" exec -T "${PG_SERVICE}")
fi

# psql as the bootstrap superuser (connects to the always-present `postgres` db).
psql_super() {
  "${PG_EXEC[@]}" psql -U "${PGSUPERUSER}" -d postgres -v ON_ERROR_STOP=1 -qAt "$@"
}

# RTO-15: recreate the application ROLES FIRST, as the superuser, so a fresh
# cluster has every role the dump's objects / GRANTs / RLS policies reference. A
# logical pg_dump carries NONE of them (roles are cluster globals), so without
# this a brand-new-cluster restore aborted on the first `CREATE POLICY … TO
# probectl_app`. backup_postgres.sh writes a companion `<dump>.roles.sql`
# (pg_dumpall --roles-only --no-role-passwords, probectl* only — no password
# hashes leave the source), which recreates probectl + probectl_app + the other
# NOLOGIN RLS/auth roles with their exact attributes. We then set the LOGIN
# role's password from the operator's own credentials (PGAPPPASSWORD) so the app
# can connect. Older backups without the companion fall back to bootstrapping
# just the login role.
ROLES_SQL="${DUMP}.roles.sql"
pw_esc="${PGAPPPASSWORD//\'/\'\'}"
if [ -s "${ROLES_SQL}" ]; then
  if [ -s "${ROLES_SQL}.sha256" ]; then
    (cd "$(dirname "${ROLES_SQL}")" && sha256sum -c "$(basename "${ROLES_SQL}").sha256" >/dev/null)
  fi
  psql_super < "${ROLES_SQL}"
  psql_super -c "ALTER ROLE \"${PGUSER}\" LOGIN PASSWORD '${pw_esc}'"
  echo "restore_postgres: applied carried roles from ${ROLES_SQL}"
elif [ -z "$(psql_super -c "SELECT 1 FROM pg_roles WHERE rolname = '${PGUSER}'")" ]; then
  psql_super -c "CREATE ROLE \"${PGUSER}\" LOGIN PASSWORD '${pw_esc}'"
  echo "restore_postgres: no roles companion; created only the login role ${PGUSER}"
else
  echo "restore_postgres: application role ${PGUSER} already present"
fi

# Drop + recreate the database as the superuser, owned by the app role.
psql_super -c "DROP DATABASE IF EXISTS \"${PGDATABASE}\" WITH (FORCE)"
psql_super -c "CREATE DATABASE \"${PGDATABASE}\" OWNER \"${PGUSER}\""

# Restore the logical dump. --no-owner (ownership is re-established by the role
# recreation above + the database owner); run as the superuser so GRANT/role
# statements in the dump apply against the just-created role.
"${PG_EXEC[@]}" pg_restore -U "${PGSUPERUSER}" -d "${PGDATABASE}" --no-owner --role="${PGUSER}" --exit-on-error < "${DUMP}"

echo "restore_postgres: restored ${PGDATABASE} from ${DUMP}"
