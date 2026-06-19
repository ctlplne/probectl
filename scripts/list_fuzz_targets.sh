#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-probectl-TBD
#
# Discover Go fuzz targets under internal/. This is intentionally dependency-free
# so CI can use it before any project tooling is installed.
set -euo pipefail

mode="${1:-table}"

discover() {
  find internal -name '*_test.go' -print | sort | while IFS= read -r file; do
    pkg="./$(dirname "$file")"
    sed -nE 's/^[[:space:]]*func (Fuzz[A-Za-z0-9_]+)[[:space:]]*\(.*/\1/p' "$file" | while IFS= read -r name; do
      [ -n "$name" ] || continue
      printf '%s\t%s\n' "$pkg" "$name"
    done
  done | sort -u -k1,1 -k2,2
}

emit_matrix() {
  local first=1
  printf '['
  while IFS=$'\t' read -r pkg name; do
    if [ "$first" -eq 0 ]; then
      printf ','
    fi
    first=0
    printf '{"pkg":"%s","name":"%s"}' "$pkg" "$name"
  done
  printf ']\n'
}

case "$mode" in
  table)
    discover
    ;;
  --count)
    discover | wc -l | tr -d '[:space:]'
    printf '\n'
    ;;
  --json)
    discover | emit_matrix
    ;;
  --github-output)
    printf 'matrix='
    discover | emit_matrix
    ;;
  *)
    echo "usage: $0 [table|--count|--json|--github-output]" >&2
    exit 2
    ;;
esac
