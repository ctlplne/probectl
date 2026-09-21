#!/usr/bin/env bash
# SPDX-License-Identifier: BUSL-1.1
#
# Use of this source code is governed by the Business Source License 1.1
# in the LICENSE file at the root of this repository; on its Change Date
# each version converts to the Mozilla Public License 2.0.

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

# DPR-094: the disposable stack must not fight the developer's own dev stack for
# host ports. dev.yml publishes through variables, so pick a free port for each
# service and point the wrapped command at those ports; an isolated run then
# works beside a running probectl-dev, and beside another isolated run. Anything
# the caller already exported wins, so a targeted run can still aim elsewhere.
free_port() {
  python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()'
}

PROBECTL_DEV_POSTGRES_PORT="$(free_port)"
PROBECTL_DEV_KAFKA_PORT="$(free_port)"
PROBECTL_DEV_CLICKHOUSE_HTTP_PORT="$(free_port)"
PROBECTL_DEV_CLICKHOUSE_NATIVE_PORT="$(free_port)"
PROBECTL_DEV_PROMETHEUS_PORT="$(free_port)"
PROBECTL_DEV_NATS_PORT="$(free_port)"
PROBECTL_DEV_NATS_MONITOR_PORT="$(free_port)"
export PROBECTL_DEV_POSTGRES_PORT PROBECTL_DEV_KAFKA_PORT \
  PROBECTL_DEV_CLICKHOUSE_HTTP_PORT PROBECTL_DEV_CLICKHOUSE_NATIVE_PORT \
  PROBECTL_DEV_PROMETHEUS_PORT PROBECTL_DEV_NATS_PORT PROBECTL_DEV_NATS_MONITOR_PORT

ch="http://probectl:probectl@localhost:${PROBECTL_DEV_CLICKHOUSE_HTTP_PORT}"
export PROBECTL_DATABASE_URL="${PROBECTL_DATABASE_URL:-postgres://probectl:probectl@localhost:${PROBECTL_DEV_POSTGRES_PORT}/probectl?sslmode=disable}"
export PROBECTL_TEST_KAFKA="${PROBECTL_TEST_KAFKA:-localhost:${PROBECTL_DEV_KAFKA_PORT}}"
export PROBECTL_PROM_URL="${PROBECTL_PROM_URL:-http://localhost:${PROBECTL_DEV_PROMETHEUS_PORT}}"
export PROBECTL_TEST_CLICKHOUSE_URL="${PROBECTL_TEST_CLICKHOUSE_URL:-$ch}"
export PROBECTL_FLOWSTORE_URL="${PROBECTL_FLOWSTORE_URL:-$ch}"
export PROBECTL_PATHSTORE_URL="${PROBECTL_PATHSTORE_URL:-$ch}"
export PROBECTL_OTELSTORE_URL="${PROBECTL_OTELSTORE_URL:-$ch}"
export PROBECTL_EBPFSTORE_URL="${PROBECTL_EBPFSTORE_URL:-$ch}"
# DPR-119: the durable lightweight bus, for `go test -tags integration ./internal/bus`.
export PROBECTL_TEST_NATS="${PROBECTL_TEST_NATS:-nats://localhost:${PROBECTL_DEV_NATS_PORT}}"

echo "isolated-integration: postgres :$PROBECTL_DEV_POSTGRES_PORT kafka :$PROBECTL_DEV_KAFKA_PORT clickhouse :$PROBECTL_DEV_CLICKHOUSE_HTTP_PORT prometheus :$PROBECTL_DEV_PROMETHEUS_PORT" >&2
echo "isolated-integration: starting disposable project $project_name" >&2
PROBECTL_ISOLATED_NETWORK="$network_name" \
  docker compose --project-name "$project_name" \
  -f "$compose_file" -f "$compose_override" \
  up -d --wait postgres kafka clickhouse prometheus nats

"$@"
