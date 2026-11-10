#!/usr/bin/env bash
# SPDX-License-Identifier: BUSL-1.1
# Exercise the shipped worker files and dependencies, not a source checkout.
# The only mounted input is the existing smoke driver. Its login server and
# Chromium communicate over loopback inside an otherwise offline container.
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
image="${1:?usage: check_browser_image.sh <local-image-tag> [platform] [build|reuse]}"
platform="${2:-linux/amd64}"
case "${3:-build}" in
  build)
    # Default local proof builds the checkout; failures never fall back.
    docker build --platform "$platform" --build-arg COMPONENT=probectl-agent \
      --build-arg EDITION=core -f "$root/deploy/docker/Dockerfile.browser-agent" \
      -t "$image" "$root"
    ;;
  reuse)
    # CI has already verified source/run/edition/archive and loaded by image ID.
    # Keep the functional worker proof on those exact bytes, without rebuilding.
    actual="$(docker image inspect --format '{{.Os}}/{{.Architecture}}' "$image")"
    [[ "$actual" == "$platform" ]] || { echo 'browser image platform mismatch' >&2; exit 1; }
    ;;
  *) echo 'expected build or reuse' >&2; exit 1 ;;
esac
exec docker run --rm --pull never --network none --entrypoint node \
  --volume "$root/browser-worker/smoke.mjs:/worker/smoke.mjs:ro" \
  "$image" /worker/smoke.mjs
