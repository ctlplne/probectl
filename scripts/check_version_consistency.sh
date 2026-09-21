#!/usr/bin/env bash
# SPDX-License-Identifier: BUSL-1.1
#
# check_version_consistency.sh (OPS-008) — the shipped artifacts must agree on
# ONE version. The repo-root VERSION file is the single source of truth; this
# gate asserts the Compose image example, Helm Chart appVersion, and OpenAPI
# info.version all equal it. It also refuses a source version older than the
# greatest stable semantic-version tag reachable from HEAD. The binary version
# is stamped from the same VERSION file via the Makefile (a tagged release
# overrides it with the tag, which release.yml already asserts equals the chart
# appVersion), so every shipped surface converges. The gate directly exercises
# that Make resolution path, including its fail-closed cases.
#
# Run: scripts/check_version_consistency.sh    (exits non-zero on any mismatch)
set -euo pipefail

cd "$(dirname "$0")/.."

stable_semver_re='^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$'

is_stable_semver() {
  [[ "$1" =~ $stable_semver_re ]]
}

make_version() {
  env -u VERSION make --no-print-directory print-version "$@"
}

# Return success only when the first stable SemVer is numerically lower than
# the second. This is deliberately numeric: lexical comparison says 0.10.0 is
# lower than 0.9.0, and BSD/macOS sort does not provide GNU sort -V.
semver_lt() {
  local lhs="$1" rhs="$2"
  local lhs_major lhs_minor lhs_patch rhs_major rhs_minor rhs_patch
  IFS=. read -r lhs_major lhs_minor lhs_patch <<< "$lhs"
  IFS=. read -r rhs_major rhs_minor rhs_patch <<< "$rhs"

  if (( lhs_major < rhs_major )); then return 0; fi
  if (( lhs_major > rhs_major )); then return 1; fi
  if (( lhs_minor < rhs_minor )); then return 0; fi
  if (( lhs_minor > rhs_minor )); then return 1; fi
  if (( lhs_patch < rhs_patch )); then return 0; fi
  return 1
}

check_source_not_older() {
  local source_version="$1" released_version="$2"
  if semver_lt "$source_version" "$released_version"; then
    echo "::error::VERSION ($source_version) is older than reachable stable tag v$released_version (OPS-008)" >&2
    return 1
  fi
}

# Planted regression: exercise the exact fail-closed branch on every gate run,
# rather than only trusting the current repository state to happen to be old.
if check_source_not_older 0.4.0 0.5.0 >/dev/null 2>&1; then
  echo "::error::version rollback self-test failed: 0.4.0 was accepted behind v0.5.0 (OPS-008)"
  exit 1
fi
for candidate in 0.5.0 0.6.0; do
  if ! check_source_not_older "$candidate" 0.5.0 >/dev/null 2>&1; then
    echo "::error::version rollback self-test failed: $candidate was rejected against v0.5.0 (OPS-008)"
    exit 1
  fi
done

truth="$(tr -d '[:space:]' < VERSION)"
if [ -z "$truth" ]; then
  echo "::error::VERSION file is empty (OPS-008)"; exit 1
fi
if ! is_stable_semver "$truth"; then
  echo "::error::VERSION ($truth) is not a stable MAJOR.MINOR.PATCH semantic version (OPS-008)"
  exit 1
fi

# Exercise the actual Make resolver. The empty exact-tag override simulates an
# untagged commit and catches the former `git describe | sed || cat VERSION`
# pipeline: sed returned success on empty input, so the file fallback was
# skipped and binaries were stamped with an empty version.
fallback_probe="$(make_version PROBECTL_EXACT_TAG= PROBECTL_VERSION_FILE=9.8.7)"
if [ "$fallback_probe" != "9.8.7" ]; then
  echo "::error::untagged Make fallback resolved $fallback_probe, want 9.8.7 (OPS-008)"
  exit 1
fi
tag_probe="$(make_version VERSION=9.8.6 PROBECTL_EXACT_TAG=v9.8.8 PROBECTL_VERSION_FILE=9.8.7)"
if [ "$tag_probe" != "9.8.8" ]; then
  echo "::error::exact stable tag did not override VERSION input/file: got $tag_probe (OPS-008)"
  exit 1
fi
if make_version PROBECTL_EXACT_TAG= PROBECTL_VERSION_FILE= >/dev/null 2>&1; then
  echo "::error::empty Make version fallback was accepted (OPS-008)"
  exit 1
fi
if make_version PROBECTL_EXACT_TAG= PROBECTL_VERSION_FILE=not-semver >/dev/null 2>&1; then
  echo "::error::malformed VERSION file fallback was accepted (OPS-008)"
  exit 1
fi
if make_version VERSION=not-semver PROBECTL_EXACT_TAG= PROBECTL_VERSION_FILE=9.8.7 >/dev/null 2>&1; then
  echo "::error::malformed explicit VERSION was accepted (OPS-008)"
  exit 1
fi
if make_version PROBECTL_EXACT_TAG=vnot-semver PROBECTL_VERSION_FILE=9.8.7 >/dev/null 2>&1; then
  echo "::error::malformed exact tag was accepted (OPS-008)"
  exit 1
fi

exact_tag="$(git describe --tags --exact-match --match 'v[0-9]*' 2>/dev/null || true)"
expected_make_version="$truth"
if [ -n "$exact_tag" ]; then
  expected_make_version="${exact_tag#v}"
fi
resolved_make_version="$(make_version)"
if [ "$resolved_make_version" != "$expected_make_version" ]; then
  echo "::error::Make resolved version ($resolved_make_version) != expected ($expected_make_version) (OPS-008)"
  exit 1
fi

# Helm Chart appVersion (quotes stripped).
appv="$(grep -E '^appVersion:' deploy/helm/probectl/Chart.yaml | head -1 | awk '{print $2}' | tr -d '"')"

# Compose image pin: ghcr.io/.../probectl-control:vX.Y.Z  -> X.Y.Z
compose_tag="$(grep -oE 'probectl-control:v?[0-9]+\.[0-9]+\.[0-9]+' deploy/compose/probectl.yml | head -1 | sed -E 's/.*:v?//')"

# OpenAPI info.version is a product release version, while /v1 carries the API
# major. Use the JSON parser so a coincidental nested "version" cannot pass.
openapi_version="$(python3 - <<'PY'
import json
from pathlib import Path

document = json.loads(Path("internal/control/openapi.json").read_text())
print(str((document.get("info") or {}).get("version", "")).strip())
PY
)"

fail=0
if [ "$appv" != "$truth" ]; then
  echo "::error::Chart appVersion ($appv) != VERSION ($truth) (OPS-008)"; fail=1
fi
if [ "$compose_tag" != "$truth" ]; then
  echo "::error::compose image tag ($compose_tag) != VERSION ($truth) (OPS-008)"; fail=1
fi
if [ "$openapi_version" != "$truth" ]; then
  echo "::error::OpenAPI info.version ($openapi_version) != VERSION ($truth) (OPS-008)"; fail=1
fi

latest_stable=""
while IFS= read -r tag; do
  candidate="${tag#v}"
  if ! is_stable_semver "$candidate"; then
    continue
  fi
  if [ -z "$latest_stable" ] || semver_lt "$latest_stable" "$candidate"; then
    latest_stable="$candidate"
  fi
done < <(git tag --merged HEAD --list 'v*' 2>/dev/null)

if [ -n "$latest_stable" ] && ! check_source_not_older "$truth" "$latest_stable"; then
  fail=1
fi

if [ "$fail" -ne 0 ]; then
  echo "version artifacts disagree or regress — bump VERSION, Chart.yaml appVersion, the Compose pin, and OpenAPI in lockstep."
  exit 1
fi
if [ -n "$latest_stable" ]; then
  echo "version consistency OK: Make=$resolved_make_version; VERSION=$truth == Chart appVersion == Compose pin == OpenAPI; latest reachable stable tag=v$latest_stable"
else
  echo "version consistency OK: Make=$resolved_make_version; VERSION=$truth == Chart appVersion == Compose pin == OpenAPI; no reachable stable tag"
fi
