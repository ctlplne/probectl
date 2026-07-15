#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0
#
# packaging-smoke.sh (OPS-002) — build ONE deb + ONE rpm from a stand-in binary,
# exactly as release.yml does, and assert both artifacts appear with the NUMERIC
# package version. nfpm previously only ran at tag time, so a broken nfpm.yaml
# (the ${VAR}-in-src expansion bug + the v-prefix mismatch) shipped undetected.
# Running this on every PR makes the packaging path prove itself continuously.
set -euo pipefail

command -v nfpm >/dev/null || { echo "::error::nfpm not installed"; exit 1; }
command -v envsubst >/dev/null || { echo "::error::envsubst (gettext-base) not installed"; exit 1; }

AGENT="${AGENT:-agent}"   # the canary agent has a complete unit+config+scripts set
ARCH="${ARCH:-amd64}"
FILE_TAG="${FILE_TAG:-v9.9.9}"            # v-prefixed (as release names binaries); clean numeric so deb/rpm don't normalize it
PKG_VERSION="${FILE_TAG#v}"               # numeric, valid deb/rpm version
export AGENT ARCH FILE_TAG PKG_VERSION

work="$(mktemp -d)"; trap 'rm -rf "$work"' EXIT
mkdir -p "$work/dist"
# Stand-in for the real release binary, named precisely as release.yml writes it.
printf '#!/bin/true\n' > "$work/dist/probectl-${AGENT}_${FILE_TAG}_linux_${ARCH}"

rendered="$work/nfpm.rendered.yaml"
envsubst '${AGENT} ${ARCH} ${FILE_TAG} ${PKG_VERSION}' \
  < deploy/packaging/nfpm.yaml > "$rendered"

# nfpm resolves contents.src relative to CWD; run from repo root with dist there.
ln -sfn "$work/dist" ./dist-smoke 2>/dev/null || true
sed -i "s#\./dist/#${work}/dist/#g" "$rendered"

for pkg in deb rpm; do
    nfpm package -f "$rendered" -p "$pkg" -t "$work/dist"
done

deb="$(ls "$work"/dist/probectl-"${AGENT}"_"${PKG_VERSION}"_*.deb 2>/dev/null || true)"
rpm="$(ls "$work"/dist/probectl-"${AGENT}"-"${PKG_VERSION}"-*.rpm 2>/dev/null || true)"
[ -n "$deb" ] || { echo "::error::OPS-002: no .deb with numeric version ${PKG_VERSION} produced"; exit 1; }
[ -n "$rpm" ] || { echo "::error::OPS-002: no .rpm with numeric version ${PKG_VERSION} produced"; exit 1; }
echo "packaging smoke OK: $(basename "$deb"), $(basename "$rpm")"
