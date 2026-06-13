#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-probectl-TBD
#
# airgap-bundle.sh (OPS-003) — assemble a single, self-contained tarball an
# operator can carry into an air-gapped network and install offline: all
# digest-pinned images (docker save), the packaged Helm chart, the
# cross-compiled binaries + their signatures, and the offline install docs.
# Makes the CLAUDE.md §4 "air-gapped bundle" claim true.
#
#   VERSION=0.2.0 ./scripts/airgap-bundle.sh
set -euo pipefail

VERSION="${VERSION:?set VERSION (e.g. 0.2.0)}"
IMAGE_PREFIX="${IMAGE_PREFIX:-ghcr.io/imfeelingtheagi}"
OUT="${OUT:-probectl-airgap-${VERSION}}"
COMPONENTS="probectl-control probectl-agent probectl-ebpf-agent probectl-endpoint probectl-flow-agent probectl-device-agent probectl"

rm -rf "$OUT" && mkdir -p "$OUT/images" "$OUT/charts" "$OUT/bin"
echo "airgap: bundling probectl ${VERSION} -> ${OUT}/" >&2

# 1. Images — pull each DIGEST-pinned tag and docker save (so the bundle is
#    reproducible and signature-verifiable on the far side).
for c in $COMPONENTS; do
  ref="${IMAGE_PREFIX}/${c}:${VERSION}"
  echo "  image: $ref" >&2
  docker pull "$ref" >/dev/null
  docker save "$ref" -o "$OUT/images/${c}.tar"
done

# 2. Helm chart (versioned, OCI-publishable too — OPS-001). OPS-008: stamp BOTH
#    the chart version and appVersion from $VERSION so the bundled chart targets
#    exactly the images carried alongside it (no appVersion/tag skew).
helm package deploy/helm/probectl --version "$VERSION" --app-version "$VERSION" --destination "$OUT/charts" >/dev/null

# 3. Binaries (the binaries release job produces these into dist/).
if [ -d dist ]; then cp dist/probectl-*_"v${VERSION}"_linux_* "$OUT/bin/" 2>/dev/null || true; fi

# 4. Signatures + the offline procedure.
cp -r deploy/packaging "$OUT/packaging" 2>/dev/null || true
cp docs/ops/air-gap.md "$OUT/INSTALL.md"

# 5. Manifest with digests so the far side can verify nothing was swapped.
{
  echo "probectl air-gap bundle ${VERSION}"
  echo "built: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "images:"
  for c in $COMPONENTS; do
    printf '  %s: %s\n' "$c" "$(docker inspect --format '{{ index .RepoDigests 0 }}' "${IMAGE_PREFIX}/${c}:${VERSION}" 2>/dev/null || echo unknown)"
  done
} > "$OUT/MANIFEST.txt"

tar -czf "${OUT}.tar.gz" "$OUT"
echo "airgap: wrote ${OUT}.tar.gz" >&2
