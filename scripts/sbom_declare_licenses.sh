#!/usr/bin/env bash
# SPDX-License-Identifier: BUSL-1.1
#
# Use of this source code is governed by the Business Source License 1.1
# in the LICENSE file at the root of this repository; on its Change Date
# each version converts to the Mozilla Public License 2.0.
#
# Declare probectl's own licenses in a syft SPDX SBOM, then prove it (G3,
# decision D-58). syft writes licenseDeclared NOASSERTION for the first-party
# Go module because a Go binary carries no license; this fills in exactly that
# field from REUSE.toml (via the pinned reuse gate's per-file map) and the files
# each binary links, and leaves every third-party package as syft wrote it.
# See cmd/probectl-sbom-license for the rules.
#
# Usage (from the source checkout the artifacts were built from):
#   scripts/sbom_declare_licenses.sh <sbom.spdx.json> dir <scanned-dir>
#   scripts/sbom_declare_licenses.sh <sbom.spdx.json> image <image-ref> [<platform>]
#
# dir:   the SBOM describes a directory syft scanned (the release dist/).
# image: the SBOM describes an image syft scanned for <platform> (default
#        linux/amd64); the first-party binaries are copied out of that image.
# Either way the SBOM is rewritten in place and must then pass
# `probectl-sbom-license check` (no first-party NOASSERTION, every LicenseRef
# defined), or this script fails.
set -euo pipefail
cd "$(dirname "$0")/.."

[ "$#" -ge 3 ] || { echo "usage: $0 <sbom.spdx.json> dir <scanned-dir> | image <image-ref> [<platform>]" >&2; exit 2; }
sbom="$1" mode="$2" target="$3" platform="${4:-linux/amd64}"
[ -s "$sbom" ] || { echo "::error::sbom-licenses: $sbom is missing or empty" >&2; exit 1; }

work="$(mktemp -d)"
cid=""
cleanup() {
  if [ -n "$cid" ]; then docker rm -f "$cid" >/dev/null 2>&1 || true; fi
  rm -rf "$work"
}
trap cleanup EXIT

# The per-file license map comes from the same gate CI runs, so a release
# cannot declare licenses the REUSE layout does not back.
REUSE_MAP_OUT="$work/reuse-map.json" ./scripts/check_reuse_licensing.sh
go build -o "$work/probectl-sbom-license" ./cmd/probectl-sbom-license
tool="$work/probectl-sbom-license"

case "$mode" in
  dir)
    artifacts="$target"
    ;;
  image)
    artifacts="$work/image-root"
    mkdir -p "$artifacts"
    cid="$(docker create --platform "$platform" "$target")"
    "$tool" binaries -sbom "$sbom" | while IFS= read -r path; do
      case "$path" in /*) ;; *) echo "::error::sbom-licenses: image path '$path' is not absolute" >&2; exit 1 ;; esac
      mkdir -p "$artifacts$(dirname "$path")"
      docker cp "$cid:$path" "$artifacts$path"
    done
    ;;
  *)
    echo "usage: $0 <sbom.spdx.json> dir <scanned-dir> | image <image-ref> [<platform>]" >&2
    exit 2
    ;;
esac

"$tool" annotate -sbom "$sbom" -reuse-map "$work/reuse-map.json" -artifacts "$artifacts"
"$tool" check -sbom "$sbom"
echo "sbom-licenses: $sbom declares probectl's licenses for every first-party package"
