#!/usr/bin/env bash
#
# Package-license guard (SUP-14): the deb/rpm agent packages must declare the
# license of the binary they ship and carry its text. The agents are the
# BUSL-1.1 CORE (MPL-2.0 covers only pkg/, proto/ and examples/, which these
# packages do not ship), so a package that labels itself MPL-2.0 — or that omits
# the LICENSE file — is a distribution-compliance defect a downstream repo (apt,
# yum) propagates.
#
# Self-test: SELFTEST plants a mislabelled nfpm config (and one missing the
# LICENSE) and asserts the guard trips, then asserts a correct config passes.
set -euo pipefail
cd "$(dirname "$0")/.."

nfpm="deploy/packaging/nfpm.yaml"
want="BUSL-1.1"

check() { # check <nfpm-file>  -> 0 ok, 1 defect
  local f="$1" fail=0 lic
  lic="$(grep -E '^license:' "$f" | head -1 | sed -E 's/^license:[[:space:]]*"?([^"]*)"?[[:space:]]*$/\1/')"
  if [ "$lic" != "$want" ]; then
    echo "::error::$f license is '${lic}', want ${want} (the agents are the BUSL-1.1 core — SUP-14)" >&2
    fail=1
  fi
  if ! grep -qE '^[[:space:]]*-[[:space:]]*src:[[:space:]]*\./LICENSE([[:space:]]|$)' "$f"; then
    echo "::error::$f does not bundle ./LICENSE in contents (SUP-14)" >&2
    fail=1
  fi
  # G3: the machine-readable Debian copyright file and the third-party NOTICE
  # ship beside the license, so a repository scanner reads the same license and
  # the linked modules' notices travel with the binary.
  local src
  for src in ./deploy/packaging/copyright ./NOTICE; do
    if ! grep -qE "^[[:space:]]*-[[:space:]]*src:[[:space:]]*${src//./\\.}([[:space:]]|\$)" "$f"; then
      echo "::error::$f does not bundle ${src} in contents (G3)" >&2
      fail=1
    fi
  done
  return "$fail"
}

if [ "${1:-}" = "SELFTEST" ]; then
  bad="$(mktemp)"
  printf 'license: "MPL-2.0"\ncontents:\n  - src: ./dist/x\n' >"$bad"
  if check "$bad" 2>/dev/null; then
    echo "SELFTEST FAILED: a mislabelled / LICENSE-less nfpm config was not caught" >&2
    rm -f "$bad"
    exit 1
  fi
  rm -f "$bad"
  nocopyright="$(mktemp)"
  printf 'license: "BUSL-1.1"\ncontents:\n  - src: ./LICENSE\n    dst: /usr/share/doc/x/LICENSE\n  - src: ./NOTICE\n    dst: /usr/share/doc/x/NOTICE\n' >"$nocopyright"
  if check "$nocopyright" 2>/dev/null; then
    echo "SELFTEST FAILED: an nfpm config without the Debian copyright file was not caught" >&2
    rm -f "$nocopyright"
    exit 1
  fi
  rm -f "$nocopyright"
  good="$(mktemp)"
  printf 'license: "BUSL-1.1"\ncontents:\n  - src: ./LICENSE\n    dst: /usr/share/doc/x/LICENSE\n  - src: ./deploy/packaging/copyright\n    dst: /usr/share/doc/x/copyright\n  - src: ./NOTICE\n    dst: /usr/share/doc/x/NOTICE\n' >"$good"
  if ! check "$good" 2>/dev/null; then
    echo "SELFTEST FAILED: a correct nfpm config was rejected" >&2
    rm -f "$good"
    exit 1
  fi
  rm -f "$good"
  echo "check_package_license SELFTEST OK"
  exit 0
fi

if ! check "$nfpm"; then
  exit 1
fi
echo "check_package_license: OK (nfpm declares ${want} and bundles LICENSE, the Debian copyright file and NOTICE)"
