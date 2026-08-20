#!/usr/bin/env bash
# check_wire_bounds.sh — the wire-bounds gate (Foundation-Loop S-9e6855ec).
#
# Decoders that consume untrusted network bytes read them through
# internal/wire's bounded Reader. A function that owns a raw datagram (it
# builds a Reader from its own []byte parameter) may mention that parameter
# only to scope the Reader; every other hand-index or re-slice of it fails.
# That makes the five pre-existing idioms — a private sticky cursor, hand-rolled
# offset arithmetic, one upfront check then unchecked fixed-offset slicing,
# two-pass count-then-decode — unwritable at the place where raw input meets
# offset math.
#
# SELFTEST plants both violation shapes (unchecked slice, unchecked index) in a
# decoder that also uses the Reader, and proves the sanctioned scoping slice and
# a reader-carved helper are NOT flagged — driven through the same analysis the
# live check runs.
set -euo pipefail
cd "$(dirname "$0")/.."

if [ "${1:-}" = "SELFTEST" ]; then
  go test ./internal/cipolicy -run 'TestWireBoundsSelfTestCatchesPlantedIndexing' -count=1
  exit $?
fi

go test ./internal/cipolicy -run 'TestWireBounds' -count=1
