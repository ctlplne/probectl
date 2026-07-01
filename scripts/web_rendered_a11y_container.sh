#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE="${PROBECTL_PLAYWRIGHT_IMAGE:-mcr.microsoft.com/playwright:v1.55.1-noble@sha256:2f29369043d81d6d69a815ceb80760f55e85f5020371ad06a4d996f18503ad1c}"
DOCKER_BIN="${DOCKER:-docker}"

if ! command -v "$DOCKER_BIN" >/dev/null 2>&1; then
  echo "web-rendered-a11y: docker is required for the CI-matching container target" >&2
  echo "web-rendered-a11y: alternatively install a local Chrome/Chromium and run: cd web && npm run a11y:browser" >&2
  exit 127
fi

if ! "$DOCKER_BIN" info >/dev/null 2>&1; then
  echo "web-rendered-a11y: docker is installed but the daemon is not reachable" >&2
  echo "web-rendered-a11y: start Docker, then rerun: make web-rendered-a11y" >&2
  exit 1
fi

echo "web-rendered-a11y: running the CI Playwright image:"
echo "  $IMAGE"

"$DOCKER_BIN" run --rm \
  --user "$(id -u):$(id -g)" \
  --workdir /workspace/web \
  --volume "$ROOT:/workspace" \
  --env HOME=/tmp/probectl-a11y-home \
  --env npm_config_cache=/tmp/probectl-npm-cache \
  "$IMAGE" \
  bash -lc 'npm ci --no-audit --no-fund && npm run a11y:browser'
