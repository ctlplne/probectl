#!/usr/bin/env bash
# Run the privileged raw-socket path integration lane. The Go test creates a
# multi-hop Linux namespace fixture; this wrapper runs it with root capabilities
# and fails the job if the test ever reports a skip.
set -euo pipefail
cd "$(dirname "$0")/.."

log="${RUNNER_TEMP:-/tmp}/probectl-path-raw-live.log"
set -o pipefail
sudo -E env \
  "PATH=$PATH" \
  "PROBECTL_TEST_REQUIRE_RAW_PATH=1" \
  go test -tags=integration -run '^TestRunRawMultiHop$' -count=1 -v ./internal/path 2>&1 | tee "$log"

if grep -q -- '--- SKIP: TestRunRawMultiHop' "$log"; then
  echo "::error::TestRunRawMultiHop skipped in the privileged CI lane" >&2
  exit 1
fi
