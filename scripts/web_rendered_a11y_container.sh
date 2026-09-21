#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE="${PROBECTL_PLAYWRIGHT_IMAGE:-mcr.microsoft.com/playwright:v1.55.1-noble@sha256:2f29369043d81d6d69a815ceb80760f55e85f5020371ad06a4d996f18503ad1c}"
DOCKER_BIN="${DOCKER:-docker}"
A11Y_THEMES="${PROBECTL_A11Y_THEMES:-light,dark}"
SOURCE_SHA="$(git -C "$ROOT" rev-parse HEAD)"
SOURCE_BRANCH="$(git -C "$ROOT" rev-parse --abbrev-ref HEAD)"
if [ -n "$(git -C "$ROOT" status --porcelain)" ]; then
  SOURCE_DIRTY=true
else
  SOURCE_DIRTY=false
fi

[[ "$SOURCE_SHA" =~ ^[0-9a-f]{40}$ ]] || {
  echo "web-rendered-a11y: exact source SHA is unavailable" >&2
  exit 2
}

IFS=',' read -r -a requested_themes <<< "$A11Y_THEMES"
normalized_themes=""
for raw_theme in "${requested_themes[@]}"; do
  theme="${raw_theme//[[:space:]]/}"
  case "$theme" in
    light | dark) ;;
    *)
      echo "web-rendered-a11y: invalid theme '$raw_theme' (known: light, dark)" >&2
      exit 2
      ;;
  esac
  normalized_themes="${normalized_themes:+$normalized_themes,}$theme"
done
A11Y_THEMES="$normalized_themes"

docker_args=(
  run --rm
  --user "$(id -u):$(id -g)"
  --workdir /workspace/web
  --volume "$ROOT:/workspace"
  --tmpfs "/workspace/web/node_modules:rw,exec,uid=$(id -u),gid=$(id -g),mode=0755"
  --tmpfs "/workspace/browser-worker/node_modules:rw,exec,uid=$(id -u),gid=$(id -g),mode=0755"
  --env HOME=/tmp/probectl-a11y-home
  --env npm_config_cache=/tmp/probectl-npm-cache
  --env "PROBECTL_A11Y_THEMES=$A11Y_THEMES"
  --env "PROBECTL_JOURNEY_SOURCE_SHA=$SOURCE_SHA"
  --env "PROBECTL_JOURNEY_SOURCE_BRANCH=$SOURCE_BRANCH"
  --env "PROBECTL_JOURNEY_SOURCE_DIRTY=$SOURCE_DIRTY"
  "$IMAGE"
  bash -lc
  'npm ci --no-audit --no-fund && npm run a11y:browser && node ../scripts/check_web_perf_budgets.mjs && npm run bundle:check && node ../scripts/web_journey_e2e.mjs'
)

if [ "${SELFTEST:-0}" = "1" ]; then
  forwarded=0
  identity_forwarded=0
  for ((i = 0; i < ${#docker_args[@]} - 1; i++)); do
    if [ "${docker_args[$i]}" = "--env" ] &&
      [ "${docker_args[$((i + 1))]}" = "PROBECTL_A11Y_THEMES=$A11Y_THEMES" ]; then
      forwarded=1
    fi
    if [ "${docker_args[$i]}" = "--env" ] &&
      [ "${docker_args[$((i + 1))]}" = "PROBECTL_JOURNEY_SOURCE_SHA=$SOURCE_SHA" ]; then
      identity_forwarded=$((identity_forwarded + 1))
    fi
    if [ "${docker_args[$i]}" = "--env" ] &&
      [ "${docker_args[$((i + 1))]}" = "PROBECTL_JOURNEY_SOURCE_BRANCH=$SOURCE_BRANCH" ]; then
      identity_forwarded=$((identity_forwarded + 1))
    fi
    if [ "${docker_args[$i]}" = "--env" ] &&
      [ "${docker_args[$((i + 1))]}" = "PROBECTL_JOURNEY_SOURCE_DIRTY=$SOURCE_DIRTY" ]; then
      identity_forwarded=$((identity_forwarded + 1))
    fi
  done
  if [ "$forwarded" -ne 1 ]; then
    echo "web-rendered-a11y SELFTEST: theme matrix is not forwarded to docker run" >&2
    exit 1
  fi
  if [ "$identity_forwarded" -ne 3 ]; then
    echo "web-rendered-a11y SELFTEST: exact source identity is not fully forwarded to docker run" >&2
    exit 1
  fi
  echo "web-rendered-a11y SELFTEST: OK (forwarded themes and source identity: $A11Y_THEMES, ${SOURCE_SHA:0:12})"
  exit 0
fi

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
echo "web-rendered-a11y: themes: $A11Y_THEMES"

"$DOCKER_BIN" "${docker_args[@]}"
