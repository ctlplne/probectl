#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-probectl-TBD
#
# airgap-bundle.sh (OPS-003) — assemble a single, self-contained tarball an
# operator can carry into an air-gapped network and install offline: all
# digest-pinned, cosign-verified images (docker save), the packaged Helm chart,
# signed release binaries/packages + their signatures, and the offline install
# docs.
# Makes the CLAUDE.md §4 "air-gapped bundle" claim true.
#
#   VERSION=0.2.0 ./scripts/airgap-bundle.sh
set -euo pipefail

VERSION="${VERSION:?set VERSION (e.g. 0.2.0)}"
TAG="${TAG:-v${VERSION#v}}"
IMAGE_PREFIX="${IMAGE_PREFIX:-ghcr.io/imfeelingtheagi}"
OUT="${OUT:-probectl-airgap-${VERSION}}"
COMPONENTS="probectl-control probectl-agent probectl-ebpf-agent probectl-endpoint probectl-flow-agent probectl-device-agent probectl"
VERIFY_COSIGN="${PROBECTL_AIRGAP_VERIFY_COSIGN:-1}"
UNVERIFIED_ACK_VALUE="allow-unverified-airgap-artifacts"
COSIGN_ISSUER="${PROBECTL_COSIGN_ISSUER:-https://token.actions.githubusercontent.com}"
COSIGN_IDENTITY_REGEXP="${PROBECTL_COSIGN_IDENTITY_REGEXP:-^https://github.com/[^/]+/probectl/\.github/workflows/release\.yml@refs/tags/}"

case "${VERIFY_COSIGN}" in
  1|true|TRUE|yes|YES) VERIFY_COSIGN=1 ;;
  0|false|FALSE|no|NO) VERIFY_COSIGN=0 ;;
  *) echo "airgap: PROBECTL_AIRGAP_VERIFY_COSIGN must be true/false" >&2; exit 1 ;;
esac

if [ "${VERIFY_COSIGN}" = "1" ]; then
  command -v cosign >/dev/null 2>&1 || {
    echo "airgap: cosign is required to build a verified bundle; refusing unsigned air-gap artifacts" >&2
    exit 1
  }
else
  if [ "${PROBECTL_AIRGAP_UNVERIFIED_ACK:-}" != "${UNVERIFIED_ACK_VALUE}" ]; then
    echo "airgap: refusing to build an unverified bundle." >&2
    echo "airgap: set PROBECTL_AIRGAP_VERIFY_COSIGN=1 (default), or for break-glass set:" >&2
    echo "airgap:   PROBECTL_AIRGAP_UNVERIFIED_ACK=${UNVERIFIED_ACK_VALUE}" >&2
    exit 1
  fi
  echo "airgap: BREAK-GLASS - building WITHOUT cosign verification; record out-of-band evidence." >&2
fi

verify_blob() {
  file="$1"
  [ -f "$file" ] || { echo "airgap: missing artifact $file" >&2; exit 1; }
  [ "${VERIFY_COSIGN}" = "1" ] || return 0
  [ -f "${file}.sig" ] || { echo "airgap: missing signature ${file}.sig" >&2; exit 1; }
  [ -f "${file}.pem" ] || { echo "airgap: missing certificate ${file}.pem" >&2; exit 1; }
  cosign verify-blob \
    --certificate "${file}.pem" \
    --signature "${file}.sig" \
    --certificate-oidc-issuer "${COSIGN_ISSUER}" \
    --certificate-identity-regexp "${COSIGN_IDENTITY_REGEXP}" \
    "$file" >/dev/null
}

copy_signed() {
  src="$1"
  dest_dir="$2"
  verify_blob "$src"
  cp "$src" "$dest_dir/"
  [ -f "${src}.sig" ] && cp "${src}.sig" "$dest_dir/"
  [ -f "${src}.pem" ] && cp "${src}.pem" "$dest_dir/"
}

verify_image() {
  ref="$1"
  [ "${VERIFY_COSIGN}" = "1" ] || return 0
  cosign verify \
    --certificate-oidc-issuer "${COSIGN_ISSUER}" \
    --certificate-identity-regexp "${COSIGN_IDENTITY_REGEXP}" \
    "$ref" >/dev/null
}

rm -rf "$OUT" && mkdir -p "$OUT/images" "$OUT/charts" "$OUT/bin" "$OUT/packages"
echo "airgap: bundling probectl ${VERSION} -> ${OUT}/" >&2

# 1. Images - pull the release tag, resolve its immutable digest, verify that
#    digest with cosign, then save the verified digest bytes. The far side gets
#    the exact digest ledger in IMAGE-VERIFICATION.txt; a retagged mirror cannot
#    silently alter what was bundled.
: > "$OUT/IMAGE-VERIFICATION.txt"
for c in $COMPONENTS; do
  ref="${IMAGE_PREFIX}/${c}:${VERSION}"
  echo "  image: $ref" >&2
  docker pull "$ref" >/dev/null
  digest_ref="$(docker image inspect "$ref" --format '{{ index .RepoDigests 0 }}' 2>/dev/null || true)"
  case "$digest_ref" in
    *@sha256:*) ;;
    *) echo "airgap: ${ref} did not resolve to an immutable digest" >&2; exit 1 ;;
  esac
  verify_image "$digest_ref"
  printf '%s %s\n' "$c" "$digest_ref" >> "$OUT/IMAGE-VERIFICATION.txt"
  docker save "$digest_ref" -o "$OUT/images/${c}.tar"
done

# 2. Helm chart (versioned, OCI-publishable too — OPS-001). OPS-008: stamp BOTH
#    the chart version and appVersion from $VERSION so the bundled chart targets
#    exactly the images carried alongside it (no appVersion/tag skew).
helm package deploy/helm/probectl --version "$VERSION" --app-version "$VERSION" --destination "$OUT/charts" >/dev/null

# 3. Binaries and packages. The release jobs produce these into dist/, each with
#    <artifact>.sig + <artifact>.pem. Missing signatures fail closed before the
#    bundle is written.
if [ ! -d dist ]; then
  echo "airgap: dist/ is required and must contain signed release artifacts" >&2
  exit 1
fi

copied_binary=0
for f in dist/probectl_"${TAG}"_linux_* dist/probectl-*_"${TAG}"_linux_*; do
  [ -e "$f" ] || continue
  case "$f" in *.sig|*.pem) continue;; esac
  copy_signed "$f" "$OUT/bin"
  copied_binary=1
done
[ "$copied_binary" -eq 1 ] || { echo "airgap: no signed release binaries found for ${TAG}" >&2; exit 1; }

copied_package=0
for f in dist/*.deb dist/*.rpm; do
  [ -e "$f" ] || continue
  case "$f" in *.sig|*.pem) continue;; esac
  copy_signed "$f" "$OUT/packages"
  copied_package=1
done
[ "$copied_package" -eq 1 ] || { echo "airgap: no signed deb/rpm packages found in dist/" >&2; exit 1; }

if [ -f dist/checksums.txt ]; then
  copy_signed dist/checksums.txt "$OUT"
  (cd dist && sha256sum --ignore-missing -c checksums.txt >/dev/null)
fi

# 4. Signatures + the offline procedure.
cp -r deploy/packaging "$OUT/packaging" 2>/dev/null || true
cp docs/ops/air-gap.md "$OUT/INSTALL.md"

# 5. Manifest with digests so the far side can verify nothing was swapped.
{
  echo "probectl air-gap bundle ${VERSION}"
  echo "built: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "images:"
  sed 's/^/  /' "$OUT/IMAGE-VERIFICATION.txt"
  echo "binaries:"
  (cd "$OUT/bin" && sha256sum probectl-* 2>/dev/null || true) | sed 's/^/  /'
  echo "packages:"
  (cd "$OUT/packages" && sha256sum *.deb *.rpm 2>/dev/null || true) | sed 's/^/  /'
} > "$OUT/MANIFEST.txt"

tar -czf "${OUT}.tar.gz" "$OUT"
echo "airgap: wrote ${OUT}.tar.gz" >&2
