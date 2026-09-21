#!/usr/bin/env bash
# SPDX-License-Identifier: BUSL-1.1
#
# Use of this source code is governed by the Business Source License 1.1
# in the LICENSE file at the root of this repository; on its Change Date
# each version converts to the Mozilla Public License 2.0.
#
# Apply or verify the SPDX identifier and license notice on hand-maintained
# first-party source, by license zone (see LICENSE and LICENSING.md):
#   core (everything outside ee/, pkg/, proto/, examples/): BUSL-1.1 + the
#     Business Source License notice;
#   client tree (pkg/, proto/, examples/): MPL-2.0 + the exact Exhibit A notice.
# ee/ carries its own commercial identifier and is checked by the editions gate.
# Generated output is intentionally skipped: its generator owns the preamble,
# and hand-editing it would make the corresponding generation drift gate fail.
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

# The license zone of a tracked path: "client" for the MPL-2.0 tree, "core"
# for everything else the tool covers.
zone_of() {
  case "$1" in
    pkg/*|proto/*|examples/*) printf 'client' ;;
    *) printf 'core' ;;
  esac
}

has_header() {
  local file="$1" prefix="$2" zone="$3"
  if [ "${zone}" = "client" ]; then
    grep -Fqx "${prefix} SPDX-License-Identifier: MPL-2.0" "${file}" &&
      grep -Fqx "${prefix} This Source Code Form is subject to the terms of the Mozilla Public" "${file}" &&
      grep -Fqx "${prefix} License, v. 2.0. If a copy of the MPL was not distributed with this" "${file}" &&
      grep -Fqx "${prefix} file, You can obtain one at https://mozilla.org/MPL/2.0/." "${file}"
  else
    grep -Fqx "${prefix} SPDX-License-Identifier: BUSL-1.1" "${file}" &&
      grep -Fqx "${prefix} Use of this source code is governed by the Business Source License 1.1" "${file}" &&
      grep -Fqx "${prefix} in the LICENSE file at the root of this repository; on its Change Date" "${file}" &&
      grep -Fqx "${prefix} each version converts to the Mozilla Public License 2.0." "${file}"
  fi
}

write_header() {
  local prefix="$1" zone="$2"
  if [ "${zone}" = "client" ]; then
    printf '%s\n' \
      "${prefix} SPDX-License-Identifier: MPL-2.0" \
      "${prefix}" \
      "${prefix} This Source Code Form is subject to the terms of the Mozilla Public" \
      "${prefix} License, v. 2.0. If a copy of the MPL was not distributed with this" \
      "${prefix} file, You can obtain one at https://mozilla.org/MPL/2.0/." \
      ""
  else
    printf '%s\n' \
      "${prefix} SPDX-License-Identifier: BUSL-1.1" \
      "${prefix}" \
      "${prefix} Use of this source code is governed by the Business Source License 1.1" \
      "${prefix} in the LICENSE file at the root of this repository; on its Change Date" \
      "${prefix} each version converts to the Mozilla Public License 2.0." \
      ""
  fi
}

apply_one() {
  local file="$1" prefix="$2" zone="$3" tmp
  tmp="$(mktemp "${TMPDIR:-/tmp}/probectl-license-header.XXXXXX")"
  # Strip only legacy/partial SPDX lines. The rest of the file is copied byte
  # for byte, so this pass cannot alter program logic.
  awk '
    !/^(\/\/|#) SPDX-License-Identifier: (LicenseRef-probectl-T[B]D|MPL-2.0|BUSL-1.1)$/ &&
    !/^(\/\/|#) This Source Code Form is subject to the terms of the Mozilla Public$/ &&
    !/^(\/\/|#) License, v[.] 2[.]0[.] If a copy of the MPL was not distributed with this$/ &&
    !/^(\/\/|#) file, You can obtain one at https:\/\/mozilla[.]org\/MPL\/2[.]0\/[.]$/ &&
    !/^(\/\/|#) Use of this source code is governed by the Business Source License 1[.]1$/ &&
    !/^(\/\/|#) in the LICENSE file at the root of this repository; on its Change Date$/ &&
    !/^(\/\/|#) each version converts to the Mozilla Public License 2[.]0[.]$/
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
    write_header "${prefix}" "${zone}" >> "${tmp}"
    tail -n +2 "${tmp}.body" >> "${tmp}"
  else
    write_header "${prefix}" "${zone}" > "${tmp}"
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
  zone="$(zone_of "${file}")"
  checked=$((checked + 1))
  if has_header "${file}" "${prefix}" "${zone}"; then
    continue
  fi
  if [ "${MODE}" = "--check" ]; then
    missing+=("${file}")
    missing_count=$((missing_count + 1))
    continue
  fi
  apply_one "${file}" "${prefix}" "${zone}"
  changed=$((changed + 1))
done < <(git ls-files -z -- '*.go' '*.ts' '*.tsx' '*.py')

if [ "${missing_count}" -gt 0 ]; then
  echo "license header gate: ${missing_count} source file(s) missing the SPDX identifier + notice of their license zone (BUSL-1.1 core, MPL-2.0 pkg/ proto/ examples/):" >&2
  printf '  %s\n' "${missing[@]}" >&2
  echo "run scripts/apply_license_headers.sh and commit the mechanical header changes" >&2
  exit 1
fi

# The owner decision applies to every tracked core artifact, not only the
# hand-maintained source extensions above. Generated SDKs, release scripts,
# package metadata, and interop fixtures previously escaped the narrow header
# scan. Match the retired identifier with a character class so the detector
# does not contain (and therefore whitelist) the literal it rejects.
stale_identifiers="$(git grep -n -E 'LicenseRef-probectl-T[B]D' -- . || true)"
if [ -n "${stale_identifiers}" ]; then
  echo "license header gate: retired pre-MPL SPDX identifier remains in tracked files:" >&2
  printf '%s\n' "${stale_identifiers}" >&2
  exit 1
fi

if [ "${MODE}" = "--check" ]; then
  echo "license header gate: OK (${checked} hand-maintained core source files)"
else
  echo "apply_license_headers: updated ${changed}/${checked} hand-maintained core source files"
fi
