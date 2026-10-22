#!/usr/bin/env bash
# SPDX-License-Identifier: BUSL-1.1
#
# Deterministic, network-free success-path test for the air-gap release bundle.
# Docker and cosign are strict local stubs, while the fixture contains the full
# release matrix: 12 images, 20 Linux binaries, 2 charts and 20 deb/rpm packages.
# It first checks that the bundle's component lists are the release's own.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
bundle_script="${repo_root}/scripts/airgap-bundle.sh"
# G1: the bundle's lists must be the release's lists. COMPONENTS is release.yml's
# images matrix less the partner-only images; BINARY_COMPONENTS is what
# build-release-binaries.sh builds. A component added to the release and not to
# the bundle (bmp-listener, until G1) fails here.
release_images() {
  sed -n '/^  images:/,/^  [a-z][a-z0-9-]*:$/p' "${repo_root}/.github/workflows/release.yml" |
    awk '/^ *component:$/ {list=1; next}
         list && /^ *- [a-z]/ {sub(/^ *- /, ""); print; next}
         list && !/^ *- / {list=0}
         /^ *- component: / {sub(/^ *- component: /, ""); print}' |
    grep -vx 'probectl-control-ee' | sort -u
}
script_list() { # <file> <VAR>
  sed -nE "s/^$2=\"\\$\{$2:-([^}]*)\}\"$/\1/p; s/^$2=\"([^\$\"]*)\"$/\1/p" "$1" | head -1 | tr ' ' '\n' | grep . | sort -u
}
want_images="$(release_images)"
have_images="$(script_list "$bundle_script" COMPONENTS)"
want_bins="$(script_list "${repo_root}/scripts/build-release-binaries.sh" BINARIES)"
have_bins="$(script_list "$bundle_script" BINARY_COMPONENTS)"
[ -n "$want_images" ] && [ -n "$want_bins" ] || { echo "airgap gate: could not read the release component lists" >&2; exit 1; }
[ "$want_images" = "$have_images" ] || {
  echo "airgap gate: airgap-bundle.sh COMPONENTS != release.yml images (less partner-only):" >&2
  diff <(printf '%s\n' "$want_images") <(printf '%s\n' "$have_images") >&2 || true
  exit 1
}
[ "$want_bins" = "$have_bins" ] || {
  echo "airgap gate: airgap-bundle.sh BINARY_COMPONENTS != build-release-binaries.sh BINARIES:" >&2
  diff <(printf '%s\n' "$want_bins") <(printf '%s\n' "$have_bins") >&2 || true
  exit 1
}

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

for chart in probectl probectl-agent; do
  write_signed_fixture "$dist/${chart}-${version}.tgz"
  printf 'ghcr.io/fixture/charts/%s@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n' "$chart" \
    > "$dist/${chart}-${version}.chart-digest.txt"
done

binary_components="$want_bins"
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

# The same globs build-release-binaries.sh checksums, so the fixture ledger
# lists every binary the way a real release does.
(cd "$dist" && sha256sum probectl*_linux_* terraform-provider-probectl_* > checksums.txt)
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
test -s "$bundle/charts/probectl-agent-${version}.tgz"
test -s "$bundle/bin/probectl-bmp-listener_${tag}_linux_amd64"
test -s "$bundle/bin/terraform-provider-probectl_${tag}_linux_arm64"
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
[ "$image_count" -eq 12 ] || { echo "airgap success fixture: image count $image_count != 12" >&2; exit 1; }
[ "$binary_count" -eq 20 ] || { echo "airgap success fixture: binary count $binary_count != 20" >&2; exit 1; }
[ "$package_count" -eq 20 ] || { echo "airgap success fixture: package count $package_count != 20" >&2; exit 1; }

grep -q '^image archives:$' "$bundle/MANIFEST.txt"
grep -q 'probectl-control.tar' "$bundle/MANIFEST.txt"
grep -q "probectl_${tag}_linux_amd64" "$bundle/MANIFEST.txt"
grep -q "probectl-endpoint-${version}-1.arm64.rpm" "$bundle/MANIFEST.txt"
grep -q 'cosign verify-blob' "$log"
grep -q 'cosign verify --certificate-oidc-issuer' "$log"
grep -q 'docker pull registry.invalid/probectl/probectl-control:9.9.9' "$log"
grep -q 'docker pull registry.invalid/probectl/probectl-bmp-listener:9.9.9' "$log"
# DPR-212: NOT `tar -tzf … | grep -q …`. grep -q exits at its first match and
# closes the pipe, GNU tar is still writing the rest of a 4,000-entry listing,
# and under `set -o pipefail` the SIGPIPE (exit 141, "tar: stdout: write error")
# takes the whole gate down. It passes on macOS, where bsdtar and the pipe buffer
# behave differently — which is exactly why CI saw it and a developer did not.
# Read the listing once, then search it.
archive_listing="$(tar -tzf "$archive")"
grep -q "${bundle_name}/MANIFEST.txt" <<<"$archive_listing"

# Fail closed when the signed ledger omits a bundled binary (the old probectl*
# glob left terraform-provider-probectl out of checksums.txt).
grep -v 'terraform-provider-probectl_' "$dist/checksums.txt" > "$tmp/checksums.partial"
cp "$tmp/checksums.partial" "$dist/checksums.txt"
rm -rf "$bundle" "$archive"
if (
  cd "$fixture"
  PATH="$stub:$PATH" AIRGAP_TEST_LOG="$log" VERSION="$version" DIST="$dist" \
    OUT="$bundle_name" IMAGE_PREFIX="registry.invalid/probectl" bash "$bundle_script"
) >"$tmp/partial.log" 2>&1; then
  echo "airgap gate: a checksums.txt missing terraform-provider-probectl still built a bundle" >&2
  exit 1
fi
grep -q 'does not list terraform-provider-probectl_' "$tmp/partial.log" || {
  echo "airgap gate: partial-ledger refusal did not name the missing binary" >&2; cat "$tmp/partial.log" >&2; exit 1; }

echo "airgap success gate: OK (12 verified images, 20 signed binaries, 2 signed charts, 20 signed packages, complete signed checksum ledger, lists match the release)"
