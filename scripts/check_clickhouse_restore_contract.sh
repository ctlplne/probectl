#!/usr/bin/env bash
# Static guard for the Kubernetes ClickHouse backup/restore filesystem contract.
# ClickHouse BACKUP/RESTORE File(...) paths are resolved by the ClickHouse server,
# not by the client Job pod. A restore Job-local /backups mount proves the wrong
# thing and can let a broken disaster recovery path pass review.
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

deny "BACKUP DATABASE .* TO File\\('/backups/" "$BACKUP_TEMPLATE" \
  "ClickHouse backup template hardcodes /backups instead of serverBackupPath"
deny "RESTORE DATABASE .* FROM File\\('/backups/" "$RESTORE_TEMPLATE" \
  "ClickHouse restore template hardcodes /backups instead of serverBackupPath"
deny 'test -s "/backups/\{\{[[:space:]]*\.Values\.restore\.clickhouse\.backupFile[[:space:]]*\}\}"' "$RESTORE_TEMPLATE" \
  "ClickHouse restore Job checks its own pod-local /backups path"

ch_restore_block="$(awk '/- name: ch-restore/{inside=1} inside{print} /^\{\{- end \}\}/{inside=0}' "$RESTORE_TEMPLATE")"
if grep -qE 'mountPath:[[:space:]]*/backups|claimName:[[:space:]]*\{\{[[:space:]]*\.Values\.backup\.persistence\.claimName' <<<"$ch_restore_block"; then
  fail "ClickHouse restore Job mounts the backups PVC; RESTORE reads the ClickHouse server filesystem"
fi

echo "clickhouse restore contract: OK"
