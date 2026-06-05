#!/usr/bin/env bash
#
# Editions guard (S-T0/S-T1; CLAUDE.md §2 editions decisions, §6 conventions):
# commercial code lives under ee/ and may import core, but core may NEVER
# import ee/ — the core-only build must work with ee/ absent or inert. This
# guard fails the build on any Go file OUTSIDE ee/ importing the ee/ tree,
# with ONE sanctioned exception: the main.go attach seam — explicitly
# allowlisted hook files that MUST carry the `//go:build !probectl_core`
# constraint, so the core-only build (-tags probectl_core) provably excludes
# every ee/ package.
#
# Self-test: SELFTEST=1 plants (a) a violation in a non-allowlisted file and
# (b) — when the real seam file is absent — an untagged file at the
# allowlisted path, asserting the guard catches both (the gate proves itself,
# crypto-guard style).
set -euo pipefail

cd "$(dirname "$0")/.."

module='github.com/imfeelingtheagi/probectl'

# The sanctioned ee attach seams (one per binary that links ee features).
allowlist='cmd/probectl-control/ee_attach.go'

is_allowlisted() {
  local f="${1#./}"
  for a in ${allowlist}; do
    [ "${f}" = "${a}" ] && return 0
  done
  return 1
}

# Print "file:line:import" for every ee import outside ee/.
find_imports() {
  grep -rEn \
    "^[[:space:]]*(import[[:space:]]+)?([A-Za-z_.][A-Za-z0-9_.]*[[:space:]]+)?\"${module}/ee(/[^\"]*)?\"" \
    --include='*.go' . | grep -v '^\./ee/' || true
}

check() {
  local out=""
  while IFS= read -r line; do
    [ -z "${line}" ] && continue
    local f="${line%%:*}"
    if is_allowlisted "${f}"; then
      # The seam file must be excluded from the core-only build.
      if ! grep -qE '^//go:build .*!probectl_core' "${f}"; then
        out="${out}${f}: allowlisted ee attach seam MISSING the //go:build !probectl_core constraint
"
      fi
    else
      out="${out}${line}
"
    fi
  done <<EOF2
$(find_imports)
EOF2
  printf '%s' "${out}"
}

if [ "${SELFTEST:-0}" = "1" ]; then
  # (a) A non-allowlisted core file importing ee/ must be detected.
  tmp="internal/editions_guard_selftest_tmp.go"
  trap 'rm -f "${tmp}"' EXIT
  cat > "${tmp}" <<EOF
package internal

import _ "${module}/ee"
EOF
  if [ -z "$(check)" ]; then
    echo "editions-guard SELF-TEST FAILED: a planted core->ee import was not detected" >&2
    exit 1
  fi
  rm -f "${tmp}"
  trap - EXIT

  # (b) If the real attach seam is absent, plant an UNTAGGED one and assert
  # the tag requirement bites. (When the real file exists, the live check
  # below enforces the same rule on it.)
  seam="cmd/probectl-control/ee_attach.go"
  if [ ! -f "${seam}" ]; then
    trap 'rm -f "${seam}"' EXIT
    cat > "${seam}" <<EOF
package main

import _ "${module}/ee"
EOF
    if [ -z "$(check)" ]; then
      echo "editions-guard SELF-TEST FAILED: an untagged attach seam was not detected" >&2
      exit 1
    fi
    rm -f "${seam}"
    trap - EXIT
  fi
  echo "editions-guard self-test: OK (planted violations detected)"
fi

violations="$(check)"
if [ -n "${violations}" ]; then
  echo "FORBIDDEN ee/ imports outside ee/ (core may never import the commercial tree):" >&2
  echo "${violations}" >&2
  echo "" >&2
  echo "The dependency is one-way: ee/ imports core, never the reverse." >&2
  echo "The ONLY exception is the allowlisted main.go attach seam, which must" >&2
  echo "carry //go:build !probectl_core (CLAUDE.md §6, editions)." >&2
  exit 1
fi

echo "editions guard: OK (core never imports ee/; the attach seam is tagged)"
