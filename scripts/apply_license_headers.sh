#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
#
# Apply or verify the MPL-2.0 SPDX identifier + exact Exhibit A notice on
# hand-maintained first-party core source. Generated output is intentionally
# skipped: its generator owns the preamble, and hand-editing it would make the
# corresponding generation drift gate fail.
set -euo pipefail

cd "$(dirname "$0")/.."
MODE="${1:-apply}"
case "${MODE}" in
  apply|--check) ;;
  *) echo "usage: scripts/apply_license_headers.sh [--check]" >&2; exit 2 ;;
esac

is_excluded() {
  case "$1" in
    ee/*|vendor/*|*/vendor/*|dist/*|*/dist/*|node_modules/*|*/node_modules/*) return 0 ;;
    *.pb.go|*.pb.gw.go|*/sdk.gen.go|*/sdk.gen.ts|*_bpfel.go|*_bpfeb.go) return 0 ;;
    *) return 1 ;;
  esac
}

comment_prefix() {
  case "$1" in
    *.py) printf '#';;
    *.go|*.ts|*.tsx) printf '//';;
    *) return 1 ;;
  esac
}

has_header() {
  local file="$1" prefix="$2"
  grep -Fqx "${prefix} SPDX-License-Identifier: MPL-2.0" "${file}" &&
    grep -Fqx "${prefix} This Source Code Form is subject to the terms of the Mozilla Public" "${file}" &&
    grep -Fqx "${prefix} License, v. 2.0. If a copy of the MPL was not distributed with this" "${file}" &&
    grep -Fqx "${prefix} file, You can obtain one at https://mozilla.org/MPL/2.0/." "${file}" &&
    ! grep -Eq '^(//|#) SPDX-License-Identifier: LicenseRef-probectl-TBD$' "${file}"
}

write_header() {
  local prefix="$1"
  printf '%s\n' \
    "${prefix} SPDX-License-Identifier: MPL-2.0" \
    "${prefix}" \
    "${prefix} This Source Code Form is subject to the terms of the Mozilla Public" \
    "${prefix} License, v. 2.0. If a copy of the MPL was not distributed with this" \
    "${prefix} file, You can obtain one at https://mozilla.org/MPL/2.0/." \
    ""
}

apply_one() {
  local file="$1" prefix="$2" tmp
  tmp="$(mktemp "${TMPDIR:-/tmp}/probectl-license-header.XXXXXX")"
  # Strip only legacy/partial SPDX lines. The rest of the file is copied byte
  # for byte, so this pass cannot alter program logic.
  awk '
    !/^(\/\/|#) SPDX-License-Identifier: (LicenseRef-probectl-TBD|MPL-2.0)$/ &&
    !/^(\/\/|#) This Source Code Form is subject to the terms of the Mozilla Public$/ &&
    !/^(\/\/|#) License, v[.] 2[.]0[.] If a copy of the MPL was not distributed with this$/ &&
    !/^(\/\/|#) file, You can obtain one at https:\/\/mozilla[.]org\/MPL\/2[.]0\/[.]$/
  ' "${file}" > "${tmp}.body"
  # Legacy Go/TS headers were followed by a separator blank line. The new
  # canonical header supplies its own separator, so consume exactly one old
  # leading blank instead of leaving gofmt to remove a doubled blank later.
  if [ "$(head -n 1 "${tmp}.body")" = "" ]; then
    tail -n +2 "${tmp}.body" > "${tmp}.trimmed"
    mv "${tmp}.trimmed" "${tmp}.body"
  fi
  if head -n 1 "${tmp}.body" | grep -q '^#!'; then
    head -n 1 "${tmp}.body" > "${tmp}"
    write_header "${prefix}" >> "${tmp}"
    tail -n +2 "${tmp}.body" >> "${tmp}"
  else
    write_header "${prefix}" > "${tmp}"
    cat "${tmp}.body" >> "${tmp}"
  fi
  cat "${tmp}" > "${file}"
  rm -f "${tmp}" "${tmp}.body"
}

checked=0
changed=0
missing=()
missing_count=0
while IFS= read -r -d '' file; do
  is_excluded "${file}" && continue
  prefix="$(comment_prefix "${file}")"
  checked=$((checked + 1))
  if has_header "${file}" "${prefix}"; then
    continue
  fi
  if [ "${MODE}" = "--check" ]; then
    missing+=("${file}")
    missing_count=$((missing_count + 1))
    continue
  fi
  apply_one "${file}" "${prefix}"
  changed=$((changed + 1))
done < <(git ls-files -z -- '*.go' '*.ts' '*.tsx' '*.py')

if [ "${missing_count}" -gt 0 ]; then
  echo "license header gate: ${missing_count} core source file(s) missing the MPL-2.0 SPDX + Exhibit A notice:" >&2
  printf '  %s\n' "${missing[@]}" >&2
  echo "run scripts/apply_license_headers.sh and commit the mechanical header changes" >&2
  exit 1
fi

if [ "${MODE}" = "--check" ]; then
  echo "license header gate: OK (${checked} hand-maintained core source files)"
else
  echo "apply_license_headers: updated ${changed}/${checked} hand-maintained core source files"
fi
