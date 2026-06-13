#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-probectl-TBD
#
# check_version_consistency.sh (OPS-008) — the shipped artifacts must agree on
# ONE version. The repo-root VERSION file is the single source of truth; this
# gate asserts the compose image pin and the Helm Chart appVersion both equal
# it. The binary version is stamped from the same VERSION file via the Makefile
# (a tagged release overrides it with the tag, which release.yml already asserts
# equals the chart appVersion), so all three converge.
#
# Run: scripts/check_version_consistency.sh    (exits non-zero on any mismatch)
set -euo pipefail

cd "$(dirname "$0")/.."

truth="$(tr -d '[:space:]' < VERSION)"
if [ -z "$truth" ]; then
  echo "::error::VERSION file is empty (OPS-008)"; exit 1
fi

# Helm Chart appVersion (quotes stripped).
appv="$(grep -E '^appVersion:' deploy/helm/probectl/Chart.yaml | head -1 | awk '{print $2}' | tr -d '"')"

# Compose image pin: ghcr.io/.../probectl-control:vX.Y.Z  -> X.Y.Z
compose_tag="$(grep -oE 'probectl-control:v?[0-9]+\.[0-9]+\.[0-9]+' deploy/compose/probectl.yml | head -1 | sed -E 's/.*:v?//')"

fail=0
if [ "$appv" != "$truth" ]; then
  echo "::error::Chart appVersion ($appv) != VERSION ($truth) (OPS-008)"; fail=1
fi
if [ "$compose_tag" != "$truth" ]; then
  echo "::error::compose image tag ($compose_tag) != VERSION ($truth) (OPS-008)"; fail=1
fi

if [ "$fail" -ne 0 ]; then
  echo "version artifacts disagree — bump VERSION, Chart.yaml appVersion, and the compose pin in lockstep."
  exit 1
fi
echo "version consistency OK: VERSION=$truth == Chart appVersion == compose pin"
