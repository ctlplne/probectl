#!/usr/bin/env bash
# SPDX-License-Identifier: BUSL-1.1
# Exercise the shipped worker files and dependencies, not a source checkout.
# The only mounted input is the existing smoke driver. Its login server and
# Chromium communicate over loopback inside an otherwise offline container.
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
image="${1:?usage: check_browser_image.sh <built-browser-agent-image>}"
exec docker run --rm --network none --entrypoint node \
  --volume "$root/browser-worker/smoke.mjs:/worker/smoke.mjs:ro" \
  "$image" /worker/smoke.mjs
