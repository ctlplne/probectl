#!/usr/bin/env bash
# LICENSE-003: stamp a machine-checkable SPDX tag on every first-party Go file
# so provenance is verifiable (the data-room "clean IP" prep).
#
# The tag VALUE is a PLACEHOLDER pending counsel's license choice (Appendix B
# of the remediation plan) — we deliberately do NOT invent a real OSI license.
# When counsel picks one, change CORE_TAG below and re-run: a single value-swap
# finalizes every header. The script is IDEMPOTENT — a file already carrying an
# SPDX-License-Identifier is skipped, so re-runs (and post-codegen runs) are safe.
#
# The tag is inserted as its OWN leading comment block followed by a blank line.
# Per `go help buildconstraint`, a //go:build constraint may be "preceded only
# by blank lines and other line comments", so this never breaks build tags; and
# the trailing blank line keeps it from being mistaken for the package doc.
set -euo pipefail
cd "$(dirname "$0")/.."

CORE_TAG="LicenseRef-probectl-TBD"            # open-core tree (license TBD, counsel)
EE_TAG="LicenseRef-probectl-Commercial-TBD"   # commercial tree (ee/)

stamp() { # stamp <file> <tag>
  local f="$1" tag="$2"
  if grep -q "SPDX-License-Identifier:" "$f"; then
    return 0
  fi
  # Skip GENERATED files: codegen reproduces them verbatim (without a license
  # header), so stamping them would make `make proto` see drift and fail the
  # proto gate. They carry the generator's "// Code generated ... DO NOT EDIT."
  # marker instead, and golangci-lint excludes internal/gen anyway.
  if head -3 "$f" | grep -q "Code generated .* DO NOT EDIT"; then
    return 0
  fi
  local tmp
  tmp="$(mktemp)"
  printf '// SPDX-License-Identifier: %s\n\n' "$tag" >"$tmp"
  cat "$f" >>"$tmp"
  mv "$tmp" "$f"
}

count=0
while IFS= read -r f; do
  stamp "$f" "$CORE_TAG"
  count=$((count + 1))
done < <(find internal cmd pkg -name '*.go' 2>/dev/null)

if [ -d ee ]; then
  while IFS= read -r f; do
    stamp "$f" "$EE_TAG"
    count=$((count + 1))
  done < <(find ee -name '*.go' 2>/dev/null)
fi

echo "add_spdx_headers: processed $count Go files (core=$CORE_TAG, ee=$EE_TAG; existing tags skipped)."
