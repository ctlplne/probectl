#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0
#
# packaging-smoke.sh (OPS-002) — build a deb + an rpm from a stand-in binary for
# EVERY agent release.yml packages, exactly as release.yml does, and assert both
# artifacts appear with the NUMERIC package version. nfpm previously only ran at
# tag time, so a broken nfpm.yaml (the ${VAR}-in-src expansion bug + the v-prefix
# mismatch) shipped undetected.
#
# DPR-259: it then only ran for ONE agent — `agent`, chosen because it "has a
# complete unit+config+scripts set" — so it could not see that
# deploy/packaging/config/ebpf-agent.yaml did not exist. v0.6.5 failed at
# `deb/rpm packages (ebpf-agent)` with `matching
# "./deploy/packaging/config/ebpf-agent.yaml": file does not exist`, which also
# means the shipped unit would have started a binary pointing at a missing
# --config. The agent list is now DERIVED from release.yml's matrix, so adding an
# agent there extends this gate instead of quietly widening the blind spot.
set -euo pipefail

command -v nfpm >/dev/null || { echo "::error::nfpm not installed"; exit 1; }
command -v envsubst >/dev/null || { echo "::error::envsubst (gettext-base) not installed"; exit 1; }

# The agents to cover. Default: every agent in release.yml's packages matrix,
# read from the workflow so the two cannot drift. AGENT= still overrides for a
# single-agent run.
release_matrix_agents() {
  sed -n '/^  packages:/,/^  [a-z]/p' .github/workflows/release.yml |
    sed -n 's/^ *agent: \[\(.*\)\] *$/\1/p' |
    tr -d ' ' | tr ',' '\n' | grep .
}
if [ -n "${AGENT:-}" ]; then
  AGENTS="$AGENT"
else
  AGENTS="$(release_matrix_agents)"
  [ -n "$AGENTS" ] || { echo "::error::OPS-002: could not read the packages matrix from release.yml"; exit 1; }
fi
ARCH="${ARCH:-amd64}"
FILE_TAG="${FILE_TAG:-v9.9.9}"            # v-prefixed (as release names binaries); clean numeric so deb/rpm don't normalize it
PKG_VERSION="${FILE_TAG#v}"               # numeric, valid deb/rpm version
export ARCH FILE_TAG PKG_VERSION

built=""
for AGENT in $AGENTS; do
  export AGENT
  work="$(mktemp -d)"
  mkdir -p "$work/dist"
  # Stand-in for the real release binary, named precisely as release.yml writes it.
  printf '#!/bin/true\n' > "$work/dist/probectl-${AGENT}_${FILE_TAG}_linux_${ARCH}"

  rendered="$work/nfpm.rendered.yaml"
  envsubst '${AGENT} ${ARCH} ${FILE_TAG} ${PKG_VERSION}' \
    < deploy/packaging/nfpm.yaml > "$rendered"

  # nfpm resolves contents.src relative to CWD. Render through a second file
  # instead of in-place editing: BSD sed (macOS) requires a backup suffix while
  # GNU sed (CI/Linux) does not, so that form made this gate platform-specific.
  absolute_rendered="$work/nfpm.absolute.yaml"
  sed "s#\./dist/#${work}/dist/#g" "$rendered" > "$absolute_rendered"
  mv "$absolute_rendered" "$rendered"

  for pkg in deb rpm; do
    nfpm package -f "$rendered" -p "$pkg" -t "$work/dist"
  done

  deb="$(ls "$work"/dist/probectl-"${AGENT}"_"${PKG_VERSION}"_*.deb 2>/dev/null || true)"
  rpm="$(ls "$work"/dist/probectl-"${AGENT}"-"${PKG_VERSION}"-*.rpm 2>/dev/null || true)"
  [ -n "$deb" ] || { echo "::error::OPS-002: ${AGENT}: no .deb with numeric version ${PKG_VERSION} produced"; rm -rf "$work"; exit 1; }
  [ -n "$rpm" ] || { echo "::error::OPS-002: ${AGENT}: no .rpm with numeric version ${PKG_VERSION} produced"; rm -rf "$work"; exit 1; }
  built="${built}${built:+ }${AGENT}"
  rm -rf "$work"
done
echo "packaging smoke OK for $(printf '%s\n' $AGENTS | wc -l | tr -d ' ') agent(s): ${built}"
