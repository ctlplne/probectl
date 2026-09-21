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
# L3 extends the same boundary to file licensing: every commentable
# commercial file identifies LicenseRef-Probectl-Commercial and ee/LICENSE,
# while no core source file may carry that commercial SPDX header.
#
# Self-test: SELFTEST=1 plants (a) a violation in a non-allowlisted file and
# (b) — when the real seam file is absent — an untagged file at the
# allowlisted path, asserting the guard catches both (the gate proves itself,
# crypto-guard style).
set -euo pipefail

cd "$(dirname "$0")/.."

module='github.com/ctlplne/probectl'

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

check_license_headers() {
  local out="" f
  while IFS= read -r f; do
    [ -n "${f}" ] || continue
    case "${f}" in
      ee/LICENSE)
        for required_text in \
          'DRAFT-FOR-COUNSEL' \
          'LicenseRef-Probectl-Commercial' \
          'recipient may view' \
          'right to reproduce, modify, and use' \
          'production without a Valid Commercial License' \
          'Enterprise or MSP entitlement' \
          'separately executed reseller agreement'; do
          if ! grep -Fq "${required_text}" "${f}"; then
            out="${out}${f}: commercial license is missing required boundary text: ${required_text}\n"
          fi
        done
        ;;
      *.go|*.ts|*.tsx|*.css)
        if ! grep -Fq 'SPDX-License-Identifier: LicenseRef-Probectl-Commercial' "${f}" || ! grep -Fq 'ee/LICENSE' "${f}"; then
          out="${out}${f}: commercial source must carry the exact SPDX identifier and point to ee/LICENSE\n"
        fi
        ;;
      *.json|*.md)
        # JSON cannot carry comments, so OpenAPI uses an x-probectl-license
        # field. Markdown uses an HTML comment. Both still contain the exact
        # identifier and ee/LICENSE pointer checked here.
        if ! grep -Fq 'LicenseRef-Probectl-Commercial' "${f}" || ! grep -Fq 'ee/LICENSE' "${f}"; then
          out="${out}${f}: commercial document/contract must identify LicenseRef-Probectl-Commercial and ee/LICENSE\n"
        fi
        ;;
      *)
        out="${out}${f}: unsupported ee/ file type has no commercial-license marker rule\n"
        ;;
    esac
    if [ "${f}" != "ee/LICENSE" ] && grep -Eq 'LicenseRef-probectl-(Commercial-)?TBD|Commercial License — PLACEHOLDER' "${f}"; then
      out="${out}${f}: obsolete placeholder commercial header remains\n"
    fi
  done < <(find ee -type f ! -name '.DS_Store' -print | sort)

  # Core docs may quote the identifier in prose. This pattern matches actual
  # source-comment headers only, so documentation of the rule is not a false
  # positive while a copied commercial header outside ee/ fails closed.
  local core_leaks
  core_leaks="$(grep -rEn \
    '^[[:space:]]*(//|#|/\*|\*)[[:space:]]*SPDX-License-Identifier:[[:space:]]*LicenseRef-Probectl-Commercial([[:space:]]*(\*/|-->))?[[:space:]]*$' \
    --exclude-dir=.git --exclude-dir=ee --exclude-dir=node_modules \
    --exclude-dir=dist --exclude-dir=vendor . || true)"
  if [ -n "${core_leaks}" ]; then
    out="${out}core source carries the ee-only commercial SPDX identifier:\n${core_leaks}\n"
  fi
  printf '%b' "${out}"
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

  # (c) A commercial file without its header and a core file WITH the
  # commercial header must both trip the file-license boundary.
  ee_header_tmp="ee/license_header_selftest_tmp.go"
  trap 'rm -f "${ee_header_tmp}"' EXIT
  printf 'package ee\n' > "${ee_header_tmp}"
  if ! check_license_headers | grep -Fq "${ee_header_tmp}"; then
    echo "editions-guard SELF-TEST FAILED: missing ee commercial header was not detected" >&2
    exit 1
  fi
  rm -f "${ee_header_tmp}"
  trap - EXIT

  core_header_tmp="internal/editions_license_header_selftest_tmp.go"
  trap 'rm -f "${core_header_tmp}"' EXIT
  printf '%s\n' '// SPDX-License-Identifier: LicenseRef-Probectl-Commercial' 'package internal' > "${core_header_tmp}"
  if ! check_license_headers | grep -Fq 'core source carries the ee-only commercial SPDX identifier'; then
    echo "editions-guard SELF-TEST FAILED: commercial SPDX header in core was not detected" >&2
    exit 1
  fi
  rm -f "${core_header_tmp}"
  trap - EXIT

  echo "editions-guard self-test: OK (import + license-boundary planted violations detected)"
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

license_violations="$(check_license_headers)"
if [ -n "${license_violations}" ]; then
  echo "EDITIONS LICENSE HEADER VIOLATIONS:" >&2
  printf '%s\n' "${license_violations}" >&2
  echo "ee/ is commercial source under ee/LICENSE; core source is BUSL-1.1; pkg/, proto/ and examples/ are MPL-2.0." >&2
  exit 1
fi

echo "editions license guard: OK (every ee/ file marked commercial; core has no commercial header)"
