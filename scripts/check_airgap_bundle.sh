#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0
#
# Deterministic, network-free success-path test for the air-gap release bundle.
# Docker and cosign are strict local stubs, while the fixture contains the full
# release matrix: 11 images, 18 Linux binaries, and 20 deb/rpm packages.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
bundle_script="${repo_root}/scripts/airgap-bundle.sh"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

fixture="${tmp}/fixture"
dist="${fixture}/dist"
stub="${tmp}/bin"
log="${tmp}/calls.log"
version="9.9.9"
tag="v${version}"
bundle_name="probectl-airgap-${version}"

mkdir -p \
  "$dist" \
  "$stub" \
  "$fixture/scripts" \
  "$fixture/docs/ops" \
  "$fixture/deploy/packaging"

# The production builder regenerates and copies the committed attribution
# inventory. This local fixture supplies a deterministic generator and content;
# dependency-inventory correctness remains owned by third-party-gate.
printf 'fixture notice\n' > "$fixture/NOTICE"
printf '# Fixture third-party inventory\n' > "$fixture/docs/third-party-licenses.md"
printf '# Fixture offline install\n' > "$fixture/docs/ops/air-gap.md"
printf 'fixture packaging\n' > "$fixture/deploy/packaging/README"
printf '%s\n' \
  '#!/bin/sh' \
  'set -eu' \
  'test -s NOTICE' \
  'test -s docs/third-party-licenses.md' \
  > "$fixture/scripts/gen_third_party.sh"
chmod +x "$fixture/scripts/gen_third_party.sh"

# cosign records every verification; it never reaches Sigstore.
printf '%s\n' \
  '#!/bin/sh' \
  'set -eu' \
  'printf "cosign %s\n" "$*" >> "${AIRGAP_TEST_LOG:?}"' \
  > "$stub/cosign"
chmod +x "$stub/cosign"

# docker simulates pulls, immutable digest resolution, and docker-save archives.
cat > "$stub/docker" <<'SH'
#!/bin/sh
set -eu
printf 'docker %s\n' "$*" >> "${AIRGAP_TEST_LOG:?}"
if [ "${1:-}" = "pull" ]; then
  exit 0
fi
if [ "${1:-}" = "image" ] && [ "${2:-}" = "inspect" ]; then
  printf '%s@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n' "$3"
  exit 0
fi
if [ "${1:-}" = "save" ]; then
  ref="${2:?digest ref}"
  shift 2
  [ "${1:-}" = "-o" ] || exit 2
  printf 'saved %s\n' "$ref" > "${2:?output path}"
  exit 0
fi
exit 2
SH
chmod +x "$stub/docker"

write_signed_fixture() {
  local path="$1"
  printf 'fixture bytes for %s\n' "$(basename "$path")" > "$path"
  printf 'fixture signature\n' > "${path}.sig"
  printf 'fixture certificate\n' > "${path}.pem"
}

write_signed_fixture "$dist/probectl-${version}.tgz"
printf 'ghcr.io/fixture/charts/probectl@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n' \
  > "$dist/probectl-${version}.chart-digest.txt"

binary_components="probectl-control probectl-agent probectl-ebpf-agent probectl-endpoint probectl-flow-agent probectl-device-agent probectl-cloud-metrics terraform-provider-probectl probectl"
for arch in amd64 arm64; do
  for component in $binary_components; do
    write_signed_fixture "$dist/${component}_${tag}_linux_${arch}"
  done
done

package_agents="agent ebpf-agent flow-agent device-agent endpoint"
for arch in amd64 arm64; do
  for agent in $package_agents; do
    write_signed_fixture "$dist/probectl-${agent}_${version}_${arch}.deb"
    write_signed_fixture "$dist/probectl-${agent}-${version}-1.${arch}.rpm"
  done
done

(cd "$dist" && sha256sum probectl_*_linux_* > checksums.txt)
printf 'fixture signature\n' > "$dist/checksums.txt.sig"
printf 'fixture certificate\n' > "$dist/checksums.txt.pem"

(
  cd "$fixture"
  PATH="$stub:$PATH" \
    AIRGAP_TEST_LOG="$log" \
    VERSION="$version" \
    DIST="$dist" \
    OUT="$bundle_name" \
    IMAGE_PREFIX="registry.invalid/probectl" \
    bash "$bundle_script"
)

bundle="${fixture}/${bundle_name}"
archive="${bundle}.tar.gz"
test -s "$archive"
test -s "$bundle/MANIFEST.txt"
test -s "$bundle/IMAGE-VERIFICATION.txt"
test -s "$bundle/charts/probectl-${version}.tgz"
test -s "$bundle/bin/probectl_${tag}_linux_amd64"
test -s "$bundle/bin/probectl-control_${tag}_linux_arm64"
test -s "$bundle/packages/probectl-agent_${version}_amd64.deb"
test -s "$bundle/packages/probectl-endpoint-${version}-1.arm64.rpm"
test -s "$bundle/evidence/NOTICE"
test -s "$bundle/evidence/third-party-licenses.md"
test -s "$bundle/INSTALL.md"

image_count="$(find "$bundle/images" -type f -name '*.tar' | wc -l | tr -d '[:space:]')"
binary_count="$(find "$bundle/bin" -type f ! -name '*.sig' ! -name '*.pem' | wc -l | tr -d '[:space:]')"
package_count="$(find "$bundle/packages" -type f ! -name '*.sig' ! -name '*.pem' | wc -l | tr -d '[:space:]')"
[ "$image_count" -eq 11 ] || { echo "airgap success fixture: image count $image_count != 11" >&2; exit 1; }
[ "$binary_count" -eq 18 ] || { echo "airgap success fixture: binary count $binary_count != 18" >&2; exit 1; }
[ "$package_count" -eq 20 ] || { echo "airgap success fixture: package count $package_count != 20" >&2; exit 1; }

grep -q '^image archives:$' "$bundle/MANIFEST.txt"
grep -q 'probectl-control.tar' "$bundle/MANIFEST.txt"
grep -q "probectl_${tag}_linux_amd64" "$bundle/MANIFEST.txt"
grep -q "probectl-endpoint-${version}-1.arm64.rpm" "$bundle/MANIFEST.txt"
grep -q 'cosign verify-blob' "$log"
grep -q 'cosign verify --certificate-oidc-issuer' "$log"
grep -q 'docker pull registry.invalid/probectl/probectl-control:9.9.9' "$log"
tar -tzf "$archive" | grep -q "${bundle_name}/MANIFEST.txt"

echo "airgap success gate: OK (11 verified images, 18 signed binaries, 20 signed packages, complete offline manifest)"
