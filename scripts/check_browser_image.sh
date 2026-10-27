#!/usr/bin/env bash
# SPDX-License-Identifier: BUSL-1.1
# Exercise the shipped worker files and dependencies, not a source checkout.
# The only mounted input is the existing smoke driver. Its login server and
# Chromium communicate over loopback inside an otherwise offline container.
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
image="${1:?usage: check_browser_image.sh <local-image-tag> [platform]}"
platform="${2:-linux/amd64}"
# Build from the checkout and its digest-pinned bases before consuming the tag.
# A build failure stops here; never fall back to an older or registry image.
docker build --platform "$platform" --build-arg COMPONENT=probectl-agent \
  --build-arg EDITION=core -f "$root/deploy/docker/Dockerfile.browser-agent" \
  -t "$image" "$root"
exec docker run --rm --pull never --network none --entrypoint node \
  --volume "$root/browser-worker/smoke.mjs:/worker/smoke.mjs:ro" \
  "$image" /worker/smoke.mjs
