#!/usr/bin/env bash
# SPDX-License-Identifier: BUSL-1.1
#
# Use of this source code is governed by the Business Source License 1.1
# in the LICENSE file at the root of this repository; on its Change Date
# each version converts to the Mozilla Public License 2.0.

# Give destructive backup/restore and failover drills a unique Compose project,
# volumes, and network. The drill may wipe or kill its own stores; cleanup can
# never address the stable probectl-dev project by name.
set -euo pipefail

cd "$(dirname "$0")/.."

case "${1:-}" in
  backup | failover) drill="$1" ;;
  *)
    echo "usage: $0 {backup|failover}" >&2
    exit 64
    ;;
esac

project_name="probectl-drill-${drill}-$$"
network_name="${project_name}-network"
compose_dev="deploy/compose/dev.yml"
compose_dr="deploy/compose/dr-drill.yml"
compose_override="deploy/compose/isolated.yml"

case "$project_name" in
  probectl-drill-backup-[0-9]* | probectl-drill-failover-[0-9]*) ;;
  *)
    echo "isolated-drill: refusing unsafe project name: $project_name" >&2
    exit 65
    ;;
esac

cleanup() {
  docker compose --project-name "$project_name" \
    -f "$compose_dev" -f "$compose_dr" -f "$compose_override" \
    down -v --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT HUP INT TERM

export COMPOSE_PROJECT_NAME="$project_name"
export PROBECTL_ISOLATED_NETWORK="$network_name"
export PROBECTL_COMPOSE_OVERRIDE_FILE="$compose_override"
# dev.yml intentionally uses this fixed credential. dr-drill.yml also needs it
# during Compose interpolation, so make the disposable harness self-contained
# without weakening the production compose contract.
export POSTGRES_PASSWORD="${POSTGRES_PASSWORD:-probectl}"

echo "isolated-drill: ${drill} in disposable project ${project_name}" >&2
if [ "$drill" = "backup" ]; then
  ./scripts/backup_restore_drill.sh
else
  ./scripts/failover_drill.sh
fi
