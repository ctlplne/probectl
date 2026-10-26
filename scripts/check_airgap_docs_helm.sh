#!/usr/bin/env bash
# SPDX-License-Identifier: BUSL-1.1
# Use of this source code is governed by the Business Source License 1.1
# in the LICENSE file at the root of this repository; on its Change Date
# each version converts to the Mozilla Public License 2.0.
# Render the actual offline-install values, not a separately maintained fixture.
set -euo pipefail
values="$(mktemp)"
trap 'rm -f "$values"' EXIT
awk '
  /^[[:space:]]*```yaml/ { block=1; next }
  block && /^[[:space:]]*```/ { exit }
  block { sub(/^   /, ""); print }
' docs/ops/air-gap.md > "$values"
test -s "$values"
helm template probectl deploy/helm/probectl -f "$values" \
  --set image.repository=registry.internal/probectl \
  --set-string image.digest=sha256:0000000000000000000000000000000000000000000000000000000000000000 \
  >/dev/null
printf '%s\n' 'air-gap docs: documented minimum values render'
