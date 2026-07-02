#!/usr/bin/env bash
# Static guard for the Kubernetes ClickHouse backup/restore filesystem contract.
# ClickHouse BACKUP/RESTORE File(...) paths are resolved by the ClickHouse server.
# Sealed .zip.pbk restore therefore requires the Job to mount the SAME
# server-visible backup PVC path, open the .pbk into that path, and then ask the
# server to RESTORE the opened .zip. A pod-local-only /backups mount would still
# be wrong.
set -euo pipefail

CHART="${CHART:-deploy/helm/probectl}"
BACKUP_TEMPLATE="$CHART/templates/backup-cronjobs.yaml"
RESTORE_TEMPLATE="$CHART/templates/restore-job.yaml"
VALUES_FILE="$CHART/values.yaml"

fail() {
  echo "clickhouse restore contract: FAIL - $*" >&2
  exit 1
}

need() {
  local pattern="$1"
  local file="$2"
  local message="$3"
  grep -qE -- "$pattern" "$file" || fail "$message"
}

deny() {
  local pattern="$1"
  local file="$2"
  local message="$3"
  if grep -qE -- "$pattern" "$file"; then
    fail "$message"
  fi
}

need '\.Values\.backup\.clickhouse\.serverBackupPath' "$BACKUP_TEMPLATE" \
  "ClickHouse backup template must use backup.clickhouse.serverBackupPath"
need '\.Values\.restore\.clickhouse\.serverBackupPath' "$RESTORE_TEMPLATE" \
  "ClickHouse restore template must use restore.clickhouse.serverBackupPath"
need 'serverBackupPath:[[:space:]]*/backups' "$VALUES_FILE" \
  "values.yaml must document the default ClickHouse server backup path"
need 'backup-open' "$RESTORE_TEMPLATE" \
  "ClickHouse restore template must open sealed .zip.pbk artifacts before RESTORE"
need 'mountPath:[[:space:]]*\{\{[[:space:]]*required "restore\.clickhouse\.serverBackupPath is required"' "$RESTORE_TEMPLATE" \
  "ClickHouse restore Job must mount the server-visible backup path, not a hardcoded pod-local path"

deny "BACKUP DATABASE .* TO File\\('/backups/" "$BACKUP_TEMPLATE" \
  "ClickHouse backup template hardcodes /backups instead of serverBackupPath"
deny "RESTORE DATABASE .* FROM File\\('/backups/" "$RESTORE_TEMPLATE" \
  "ClickHouse restore template hardcodes /backups instead of serverBackupPath"
deny 'test -s "/backups/\{\{[[:space:]]*\.Values\.restore\.clickhouse\.backupFile[[:space:]]*\}\}"' "$RESTORE_TEMPLATE" \
  "ClickHouse restore Job checks its own pod-local /backups path"

echo "clickhouse restore contract: OK"
