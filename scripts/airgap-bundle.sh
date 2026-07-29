#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0
#
# airgap-bundle.sh (OPS-003) — assemble a single, self-contained tarball an
# operator can carry into an air-gapped network and install offline: all
# digest-pinned, cosign-verified images (docker save), the packaged Helm chart,
# signed release binaries/packages + their signatures, and the offline install
# docs.
# Makes the CLAUDE.md §4 "air-gapped bundle" claim true.
#
#   VERSION=0.6.0 DIST=dist ./scripts/airgap-bundle.sh
set -euo pipefail

VERSION="${VERSION:?set VERSION (e.g. 0.6.0)}"
VERSION_NO_V="${VERSION#v}"
TAG="${TAG:-v${VERSION#v}}"
IMAGE_PREFIX="${IMAGE_PREFIX:-ghcr.io/imfeelingtheagi}"
OUT="${OUT:-probectl-airgap-${VERSION}}"
DIST="${DIST:-dist}"
COMPONENTS="probectl-control probectl-agent probectl-ebpf-agent probectl-endpoint probectl-flow-agent probectl-device-agent probectl-cloud-metrics probectl-bgp-analyzer probectl-browser-agent terraform-provider-probectl probectl"
BINARY_COMPONENTS="probectl-control probectl-agent probectl-ebpf-agent probectl-endpoint probectl-flow-agent probectl-device-agent probectl-cloud-metrics terraform-provider-probectl probectl"
RELEASE_ARCHES="amd64 arm64"
EXPECTED_PACKAGE_COUNT=20 # 5 packaged agents × 2 architectures × deb+rpm.
VERIFY_COSIGN="${PROBECTL_AIRGAP_VERIFY_COSIGN:-1}"
UNVERIFIED_ACK_VALUE="allow-unverified-airgap-artifacts"
COSIGN_ISSUER="${PROBECTL_COSIGN_ISSUER:-https://token.actions.githubusercontent.com}"
COSIGN_IDENTITY_REGEXP="${PROBECTL_COSIGN_IDENTITY_REGEXP:-^https://github.com/imfeelingtheagi/probectl/\.github/workflows/release\.yml@refs/tags/${TAG}$}"

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

rm -rf "$OUT" && mkdir -p "$OUT/images" "$OUT/charts" "$OUT/bin" "$OUT/packages" "$OUT/evidence"
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

# 2. Release artifacts. The release jobs produce these into $DIST, each with
#    <artifact>.sig + <artifact>.pem. Missing signatures fail closed before the
#    bundle is written.
if [ ! -d "$DIST" ]; then
  echo "airgap: dist/ is required and must contain signed release artifacts" >&2
  exit 1
fi

# 3. Helm chart. The chart package is signed by release.yml, self-verified after
#    signing, and pushed as a cosign-signed OCI artifact. The air-gap bundle
#    carries the same signed package bytes; it never re-packages an unsigned chart
#    locally because that would bypass the release identity proof.
chart_pkg="${DIST}/probectl-${VERSION_NO_V}.tgz"
copy_signed "$chart_pkg" "$OUT/charts"
chart_digest="${DIST}/probectl-${VERSION_NO_V}.chart-digest.txt"
[ -f "$chart_digest" ] && cp "$chart_digest" "$OUT/charts/"

# 4. Binaries and packages. Check the complete release matrix, not merely "at
# least one": a partial air-gap kit is worse than a loud release failure because
# the missing architecture is discovered only after crossing the air gap.
for arch in $RELEASE_ARCHES; do
  for component in $BINARY_COMPONENTS; do
    binary="${DIST}/${component}_${TAG}_linux_${arch}"
    copy_signed "$binary" "$OUT/bin"
  done
done

copied_package_count=0
for f in "${DIST}"/*.deb "${DIST}"/*.rpm; do
  [ -e "$f" ] || continue
  case "$f" in *.sig|*.pem) continue;; esac
  copy_signed "$f" "$OUT/packages"
  copied_package_count=$((copied_package_count + 1))
done
[ "$copied_package_count" -eq "$EXPECTED_PACKAGE_COUNT" ] || {
  echo "airgap: expected ${EXPECTED_PACKAGE_COUNT} signed deb/rpm packages, found ${copied_package_count}" >&2
  exit 1
}

if [ -f "${DIST}/checksums.txt" ]; then
  copy_signed "${DIST}/checksums.txt" "$OUT"
  (cd "$DIST" && sha256sum --ignore-missing -c checksums.txt >/dev/null)
fi

# 5. Human-readable third-party license inventory. This travels with the
#    air-gap bundle beside the signed artifacts so an offline operator can
#    inspect attribution without reaching back to GitHub or npm/PyPI.
./scripts/gen_third_party.sh >/dev/null
cp NOTICE "$OUT/evidence/NOTICE"
cp docs/third-party-licenses.md "$OUT/evidence/third-party-licenses.md"

# 6. Signatures + the offline procedure.
cp -r deploy/packaging "$OUT/packaging" 2>/dev/null || true
cp docs/ops/air-gap.md "$OUT/INSTALL.md"

# 7. Manifest with digests so the far side can verify nothing was swapped.
{
  echo "probectl air-gap bundle ${VERSION}"
  echo "built: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "images:"
  sed 's/^/  /' "$OUT/IMAGE-VERIFICATION.txt"
  echo "image archives:"
  (cd "$OUT/images" && sha256sum *.tar 2>/dev/null || true) | sed 's/^/  /'
  echo "charts:"
  (cd "$OUT/charts" && sha256sum * 2>/dev/null || true) | sed 's/^/  /'
  echo "binaries:"
  (cd "$OUT/bin" && sha256sum * 2>/dev/null || true) | sed 's/^/  /'
  echo "packages:"
  (cd "$OUT/packages" && sha256sum * 2>/dev/null || true) | sed 's/^/  /'
  echo "evidence:"
  (cd "$OUT/evidence" && sha256sum NOTICE third-party-licenses.md 2>/dev/null || true) | sed 's/^/  /'
} > "$OUT/MANIFEST.txt"

tar -czf "${OUT}.tar.gz" "$OUT"
echo "airgap: wrote ${OUT}.tar.gz" >&2
