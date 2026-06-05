#!/usr/bin/env bash
#
# Editions guard (S-T0; CLAUDE.md §2 editions decisions, §6 conventions):
# commercial code lives under ee/ and may import core, but core may NEVER
# import ee/ — the core-only build must work with ee/ absent or inert. This
# guard fails the build on any Go file OUTSIDE ee/ importing the ee/ tree.
#
# Self-test: SELFTEST=1 plants a deliberate violation in a temp file and
# asserts the guard catches it (the gate proves itself, crypto-guard style).
set -euo pipefail

cd "$(dirname "$0")/.."

module='github.com/imfeelingtheagi/probectl'

check() {
  # Match import lines — block-style (optional alias) AND single-line
  # (`import alias "path"`) — referencing the ee/ tree, excluding files that
  # live under ee/ themselves.
  grep -rEn \
    "^[[:space:]]*(import[[:space:]]+)?([A-Za-z_.][A-Za-z0-9_.]*[[:space:]]+)?\"${module}/ee(/[^\"]*)?\"" \
    --include='*.go' . | grep -v '^\./ee/' || true
}

if [ "${SELFTEST:-0}" = "1" ]; then
  tmp="internal/editions_guard_selftest_tmp.go"
  trap 'rm -f "${tmp}"' EXIT
  cat > "${tmp}" <<EOF
package internal

import _ "${module}/ee"
EOF
  if [ -z "$(check)" ]; then
    echo "editions-guard SELF-TEST FAILED: a planted core→ee import was not detected" >&2
    exit 1
  fi
  rm -f "${tmp}"
  trap - EXIT
  echo "editions-guard self-test: OK (planted violation detected)"
fi

violations="$(check)"
if [ -n "${violations}" ]; then
  echo "FORBIDDEN ee/ imports outside ee/ (core may never import the commercial tree):" >&2
  echo "${violations}" >&2
  echo "" >&2
  echo "The dependency is one-way: ee/ imports core, never the reverse (CLAUDE.md §6, editions)." >&2
  exit 1
fi

echo "editions guard: OK (core never imports ee/)"
