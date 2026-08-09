#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

# Run a command against a fresh, disposable copy of the complete dev service
# stack. The unique Compose project is the safety boundary: cleanup can remove
# only volumes created by this invocation, never the shared probectl-dev stack.
set -euo pipefail

cd "$(dirname "$0")/.."

if [ "$#" -eq 0 ]; then
  echo "usage: $0 <command> [args...]" >&2
  exit 64
fi

project_name="probectl-integration-$$"
compose_file="deploy/compose/dev.yml"
compose_override="deploy/compose/isolated.yml"
network_name="${project_name}-network"
case "$project_name" in
  probectl-integration-[0-9]*) ;;
  *)
    echo "isolated-integration: refusing unsafe project name: $project_name" >&2
    exit 65
    ;;
esac

cleanup() {
  PROBECTL_ISOLATED_NETWORK="$network_name" \
    docker compose --project-name "$project_name" \
    -f "$compose_file" -f "$compose_override" \
    down -v --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT HUP INT TERM

echo "isolated-integration: starting disposable project $project_name" >&2
PROBECTL_ISOLATED_NETWORK="$network_name" \
  docker compose --project-name "$project_name" \
  -f "$compose_file" -f "$compose_override" \
  up -d --wait postgres kafka clickhouse prometheus

"$@"
