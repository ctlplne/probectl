#!/usr/bin/env bash
# check_dead_seams.sh — the zero-call-site gate (Foundation-Loop T-2c9ab621).
#
# RULE, not a denylist: every exported symbol in internal/ and ee/ must have at
# least one non-test reference outside its own declaration, in at least one
# shipped build context (linux authoritative; darwin/windows CLI passes can
# only rescue). internal/ and ee/ cannot be imported from outside this
# repository's module tree, so the census is complete by construction.
# Deliberate exemptions live in scripts/dead_seams_allowlist.txt with a written
# reason per entry; stale entries fail the gate.
#
# SELFTEST plants both shapes through a compiler overlay — an inert exported
# symbol that must be flagged and a used one that must not be — driven through
# the same analysis the live gate runs.
set -euo pipefail
cd "$(dirname "$0")/.."

if [ "${1:-}" = "SELFTEST" ]; then
  go run ./cmd/probectl-deadseams -selftest
  exit $?
fi

go run ./cmd/probectl-deadseams
