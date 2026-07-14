#!/usr/bin/env bash
# Serialize dev-stack integration/e2e runs that share Postgres/Kafka/ClickHouse.
set -euo pipefail

if [ "$#" -lt 2 ]; then
  echo "usage: $0 <holder-name> <command> [args...]" >&2
  exit 2
fi

holder="$1"
shift
lock_dir="${PROBECTL_TEST_STACK_LOCK:-/tmp/probectl-integration-stack.lock}"
holder_file="$lock_dir/holder"

if ! mkdir "$lock_dir" 2>/dev/null; then
  current="unknown"
  if [ -r "$holder_file" ]; then
    current="$(cat "$holder_file" 2>/dev/null || echo unknown)"
  fi
  echo "probectl integration stack is already in use by ${current}; refusing to run ${holder}" >&2
  exit 75
fi

cleanup() {
  rm -f "$holder_file"
  rmdir "$lock_dir" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

printf '%s pid=%s started=%s\n' "$holder" "$$" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$holder_file"
"$@"
