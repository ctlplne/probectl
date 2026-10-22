#!/usr/bin/env bash
# SPDX-License-Identifier: BUSL-1.1
#
# Use of this source code is governed by the Business Source License 1.1
# in the LICENSE file at the root of this repository; on its Change Date
# each version converts to the Mozilla Public License 2.0.

# release_anonymous_pull_smoke.sh (G1, RTO-27) — prove that a published
# release can be pulled and verified by someone holding no credentials at all:
# every image the release workflow publishes and both charts, each read
# anonymously and each signature (and each image's SPDX SBOM attestation)
# verified against the release identity.
#
#   scripts/release_anonymous_pull_smoke.sh <registry/owner> <version>
#   scripts/release_anonymous_pull_smoke.sh ghcr.io/ctlplne 0.6.6
#
# The image list is DERIVED from release.yml's images matrix, so a new image is
# smoked the day it ships. Images published to partners only are listed in
# PRIVATE_IMAGES and skipped by design.
#
# Anonymity is enforced, not assumed: crane, cosign and helm each read an empty
# credential store, and nothing here logs in.
#
# Env:
#   COSIGN_VERIFY_FLAGS  verification flags; default is the keyless identity of
#                        release.yml on a tag. A rehearsal passes
#                        "--key cosign.pub --insecure-ignore-tlog=true".
#   PRIVATE_IMAGES       space-separated images that are partner-only.
set -euo pipefail
cd "$(dirname "$0")/.."

prefix="${1:-}"
version="${2:-}"
if [ -z "$prefix" ] || [ -z "$version" ]; then
  echo "usage: release_anonymous_pull_smoke.sh <registry/owner> <version>" >&2
  exit 2
fi
for tool in crane cosign helm; do
  command -v "$tool" >/dev/null || { echo "::error::$tool is not on PATH" >&2; exit 2; }
done

if [ -z "${COSIGN_VERIFY_FLAGS:-}" ]; then
  repo="${GITHUB_REPOSITORY:-ctlplne/probectl}"
  COSIGN_VERIFY_FLAGS="--certificate-oidc-issuer https://token.actions.githubusercontent.com --certificate-identity-regexp ^https://github.com/${repo}/\.github/workflows/release\.yml@refs/tags/"
fi
PRIVATE_IMAGES="${PRIVATE_IMAGES:-probectl-control-ee}"

# The images matrix: the plain component list plus every include entry.
release_images() {
  sed -n '/^  images:/,/^  [a-z][a-z0-9-]*:$/p' .github/workflows/release.yml |
    awk '/^ *component:$/ {list=1; next}
         list && /^ *- [a-z]/ {sub(/^ *- /, ""); print; next}
         list && !/^ *- / {list=0}
         /^ *- component: / {sub(/^ *- component: /, ""); print}' |
    sort -u
}

anon="$(mktemp -d)"
trap 'rm -rf "$anon"' EXIT
mkdir -p "$anon/docker" "$anon/helm"
printf '{}\n' > "$anon/docker/config.json"
export DOCKER_CONFIG="$anon/docker" HELM_REGISTRY_CONFIG="$anon/helm/registry.json"
export HELM_CACHE_HOME="$anon/helm/cache" HELM_CONFIG_HOME="$anon/helm/config"
unset GITHUB_TOKEN GH_TOKEN

images="$(release_images)"
[ -n "$images" ] || { echo "::error::could not read the images matrix from release.yml" >&2; exit 1; }

fail=0
checked=0
for image in $images; do
  case " ${PRIVATE_IMAGES} " in *" ${image} "*) echo "skip ${image} (partner-only by design)"; continue ;; esac
  ref="${prefix}/${image}:${version}"
  if ! digest="$(crane digest "$ref" 2>"$anon/err")"; then
    echo "::error::anonymous read of ${ref} failed: $(tr '\n' ' ' < "$anon/err")" >&2
    fail=1
    continue
  fi
  # A full anonymous pull, layers included, not just the manifest.
  if ! crane pull "${prefix}/${image}@${digest}" "$anon/image.tar" 2>"$anon/err"; then
    echo "::error::anonymous pull of ${ref} failed: $(tr '\n' ' ' < "$anon/err")" >&2
    fail=1
    continue
  fi
  rm -f "$anon/image.tar"
  # shellcheck disable=SC2086 # flags are a word list by design
  if ! cosign verify $COSIGN_VERIFY_FLAGS "${prefix}/${image}@${digest}" >/dev/null 2>"$anon/err"; then
    echo "::error::anonymous signature verification of ${prefix}/${image}@${digest} failed: $(tr '\n' ' ' < "$anon/err")" >&2
    fail=1
    continue
  fi
  # The SPDX SBOM attestation verifies too (G1, TQ-07), anonymously and against
  # the same identity as the image signature.
  # shellcheck disable=SC2086 # flags are a word list by design
  if ! cosign verify-attestation --type spdxjson $COSIGN_VERIFY_FLAGS "${prefix}/${image}@${digest}" >/dev/null 2>"$anon/err"; then
    echo "::error::anonymous SBOM attestation verification of ${prefix}/${image}@${digest} failed: $(tr '\n' ' ' < "$anon/err")" >&2
    fail=1
    continue
  fi
  echo "ok  ${image}@${digest}: pulled, signature and SBOM attestation verified anonymously"
  checked=$((checked + 1))
done

for chart in probectl probectl-agent; do
  if ! out="$(helm pull "oci://${prefix}/charts/${chart}" --version "$version" --destination "$anon" 2>&1)"; then
    echo "::error::anonymous helm pull of ${chart} ${version} failed: ${out}" >&2
    fail=1
    continue
  fi
  digest="$(printf '%s\n' "$out" | awk '/Digest:/ {print $2; exit}')"
  # shellcheck disable=SC2086 # flags are a word list by design
  if [ -z "$digest" ] || ! cosign verify $COSIGN_VERIFY_FLAGS "${prefix}/charts/${chart}@${digest}" >/dev/null 2>"$anon/err"; then
    echo "::error::anonymous signature verification of chart ${chart}@${digest:-?} failed: $(tr '\n' ' ' < "$anon/err" 2>/dev/null)" >&2
    fail=1
    continue
  fi
  echo "ok  charts/${chart}@${digest}: pulled and verified anonymously"
  checked=$((checked + 1))
done

if [ "$fail" -ne 0 ]; then
  echo "anonymous pull smoke: FAILED (a credential-less user cannot pull or verify everything this release published)" >&2
  exit 1
fi
echo "anonymous pull smoke: OK (${checked} artifacts pulled and signature-verified with no credentials)"
