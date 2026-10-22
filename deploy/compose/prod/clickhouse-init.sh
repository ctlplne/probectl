#!/usr/bin/env bash
# SPDX-License-Identifier: BUSL-1.1
#
# Use of this source code is governed by the Business Source License 1.1
# in the LICENSE file at the root of this repository; on its Change Date
# each version converts to the Mozilla Public License 2.0.
#
# clickhouse-init — provisions the ClickHouse accounts of the durable
# production Compose profile (deploy/compose/probectl.prod.yml, beta gate G2).
# It runs on every `up` after ClickHouse is healthy and before the control
# plane starts, connecting as the bootstrap admin over the strictly verified
# secure native port (9440; docs/guardrails.md G7-12):
#
#   probectl         the control plane's service login (its credential is the
#                    0600 JSON file secrets-init wrote). It owns the telemetry
#                    schema: DDL, inserts, tenant erasure and the setting-scoped
#                    reader row policies it installs at boot.
#   probectl_reader  the SELECT-only reader every ClickHouse lane names in
#                    PROBECTL_*STORE_READER_USER. The control plane binds the
#                    row policy `tenant_id = getSetting('SQL_probectl_tenant')`
#                    to it (docs/guardrails.md G7-1), so it can only ever read
#                    the one tenant its query names.
#
# Idempotent: CREATE ... IF NOT EXISTS, then ALTER USER so a password rotated in
# .env takes effect on the next `up`. Passwords are validated to
# [A-Za-z0-9._~-] before they are placed inside a SQL string literal, and are
# never printed.
set -euo pipefail

ADMIN_USER=probectl_admin

die() {
  echo "clickhouse-init: $*" >&2
  exit 1
}

require_secret() { # require_secret <ENV_NAME>
  local name="$1" value="${!1:-}"
  [ -n "$value" ] || die "$name is empty; set it in deploy/compose/.env (openssl rand -hex 24)"
  [ "${#value}" -ge 16 ] || die "$name is shorter than 16 characters (openssl rand -hex 24)"
  case "$value" in
    *[!A-Za-z0-9._~-]*) die "$name may contain only letters, digits, '.', '_', '~' and '-' (openssl rand -hex 24)" ;;
  esac
}

for name in CLICKHOUSE_ADMIN_PASSWORD CLICKHOUSE_CONTROL_PASSWORD CLICKHOUSE_READER_PASSWORD; do
  require_secret "$name"
done

ch() { # ch <user> <password> <query>
  clickhouse-client --secure --host clickhouse --port 9440 \
    --user "$1" --password "$2" --query "$3"
}

admin() { ch "$ADMIN_USER" "$CLICKHOUSE_ADMIN_PASSWORD" "$1"; }

# The control plane's service login. Explicit privileges rather than ALL: it
# needs the telemetry schema (pooled `default` database plus per-tenant silo
# databases), writes, ALTER for TTLs and tenant erasure, and the row-policy
# DDL for the setting-scoped reader policies. It gets no user/role management.
admin "CREATE USER IF NOT EXISTS probectl IDENTIFIED WITH sha256_password BY '${CLICKHOUSE_CONTROL_PASSWORD}'"
admin "ALTER USER probectl IDENTIFIED WITH sha256_password BY '${CLICKHOUSE_CONTROL_PASSWORD}'"
admin "GRANT SHOW, SELECT, INSERT, ALTER, CREATE DATABASE, CREATE TABLE, CREATE VIEW, CREATE TEMPORARY TABLE, DROP DATABASE, DROP TABLE, DROP VIEW, TRUNCATE, OPTIMIZE, CREATE ROW POLICY, ALTER ROW POLICY, DROP ROW POLICY ON *.* TO probectl"

# The tenant-scoped reader: SELECT on the pooled telemetry database only.
admin "CREATE USER IF NOT EXISTS probectl_reader IDENTIFIED WITH sha256_password BY '${CLICKHOUSE_READER_PASSWORD}'"
admin "ALTER USER probectl_reader IDENTIFIED WITH sha256_password BY '${CLICKHOUSE_READER_PASSWORD}'"
admin "GRANT SELECT ON default.* TO probectl_reader"

# Prove the fail-closed tenant-setting default reaches both SQL-created users
# before the control plane installs any reader row policy: an omitted tenant
# must resolve to '' (no rows), never error open or inherit another value.
check="SELECT throwIf(getSetting('SQL_probectl_tenant') != '', 'tenant setting default must fail closed') FORMAT Null"
ch probectl "$CLICKHOUSE_CONTROL_PASSWORD" "$check"
ch probectl_reader "$CLICKHOUSE_READER_PASSWORD" "$check"

echo "clickhouse-init: probectl + probectl_reader provisioned; tenant-setting default verified"
