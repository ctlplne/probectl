#!/usr/bin/env bash
# check_compose_image_contract.sh — OPS-001 guard for the shipped Compose image.
#
# The shipped all-in-one compose file points certgen + control at one exact
# release image. This gate keeps three things true:
#   1. both services use the same pinned image,
#   2. install docs wire the hard preflight before compose up,
#   3. install docs explain GHCR auth / PROBECTL_IMAGE override when anonymous
#      pull is unavailable,
#   4. an optional anonymous-pull smoke uses the exact compose image and a clean
#      Docker credential directory.
set -euo pipefail
cd "$(dirname "$0")/.."

fail=0
err() {
  echo "::error::compose-image-contract: $*" >&2
  fail=1
}

extract_default_images() {
  local root="$1"
  grep -oE '\$\{PROBECTL_IMAGE:-[^}]+' "$root/deploy/compose/probectl.yml" \
    | sed 's/.*:-//' \
    | sort -u
}

run_checks() {
  local root="$1"
  local images image_count

  local image=""
  images="$(extract_default_images "$root")"
  image_count="$(printf '%s\n' "$images" | sed '/^$/d' | wc -l | tr -d ' ')"
  if [ "$image_count" -ne 1 ]; then
    err "deploy/compose/probectl.yml must have exactly one PROBECTL_IMAGE default; found $image_count"
  else
    image="$(printf '%s\n' "$images" | sed -n '1p')"
  fi

  if [ -n "$image" ]; then
    local ref_count
    ref_count="$(grep -F "\${PROBECTL_IMAGE:-$image}" "$root/deploy/compose/probectl.yml" | wc -l | tr -d ' ')"
    if [ "$ref_count" -ne 2 ]; then
      err "certgen and control must both use the exact compose image ($image); found $ref_count refs"
    fi

    case "$image" in
      ghcr.io/imfeelingtheagi/probectl-control:v[0-9]*.[0-9]*.[0-9]*) ;;
      *) err "compose default must be a pinned probectl-control release tag, got: $image" ;;
    esac
    case "$image" in
      *:latest*) err "compose default must never be :latest" ;;
    esac

    local version truth
    version="${image##*:}"
    version="${version#v}"
    truth="$(tr -d '[:space:]' < "$root/VERSION")"
    if [ "$version" != "$truth" ]; then
      err "compose image version ($version) must match VERSION ($truth)"
    fi

    grep -Fq "$image" "$root/docs/install.md" \
      || err "docs/install.md must name the exact compose image ($image)"
    grep -Fq "$image" "$root/deploy/compose/.env.example" \
      || err "deploy/compose/.env.example must show the exact compose image override ($image)"
  fi

  grep -Fq 'docker login ghcr.io' "$root/docs/install.md" \
    || err "docs/install.md must document GHCR registry authentication"
  grep -Fq 'read:packages' "$root/docs/install.md" \
    || err "docs/install.md must mention the GHCR read:packages scope for private packages"
  grep -Fq 'PROBECTL_IMAGE' "$root/docs/install.md" \
    || err "docs/install.md must document the PROBECTL_IMAGE mirror/local override"
  grep -Fq 'compose_image_preflight.sh' "$root/docs/install.md" \
    || err "docs/install.md must document the hard compose image preflight"
  grep -Fq 'docker login ghcr.io' "$root/deploy/compose/README.md" \
    || err "deploy/compose/README.md must document GHCR registry authentication"
  grep -Fq 'compose_image_preflight.sh' "$root/deploy/compose/README.md" \
    || err "deploy/compose/README.md must document the hard compose image preflight"
  grep -Fq 'PROBECTL_IMAGE' "$root/deploy/compose/.env.example" \
    || err "deploy/compose/.env.example must document the image override"
  grep -Fq 'compose-prod-up: compose-prod-preflight' "$root/Makefile" \
    || err "Makefile compose-prod-up must depend on compose-prod-preflight"
  [ -f "$root/scripts/compose_image_preflight.sh" ] \
    || err "scripts/compose_image_preflight.sh must exist"

  if [ "${PROBECTL_COMPOSE_IMAGE_ANONYMOUS_PULL:-0}" = "1" ]; then
    if [ -z "$image" ]; then
      err "anonymous pull smoke cannot run because the compose image was not parsed"
    elif ! command -v docker >/dev/null 2>&1; then
      err "anonymous pull smoke requested, but docker is not on PATH"
    else
      local tmp rc
      tmp="$(mktemp -d)"
      set +e
      DOCKER_CONFIG="$tmp" docker pull "$image"
      rc=$?
      set -e
      rm -rf "$tmp"
      if [ "$rc" -ne 0 ]; then
        err "anonymous docker pull failed for exact compose image: $image"
      fi
    fi
  fi

  return "$fail"
}

if [ "${1:-}" = "SELFTEST" ]; then
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT
  mkdir -p "$tmp/deploy/compose" "$tmp/docs" "$tmp/scripts"
  echo '0.4.0' > "$tmp/VERSION"
  echo '# no compose preflight' > "$tmp/Makefile"
  echo '# preflight placeholder' > "$tmp/scripts/compose_image_preflight.sh"
  cat > "$tmp/deploy/compose/probectl.yml" <<'YAML'
services:
  certgen:
    image: ${PROBECTL_IMAGE:-ghcr.io/imfeelingtheagi/probectl-control:v0.4.0}
  control:
    image: ${PROBECTL_IMAGE:-ghcr.io/imfeelingtheagi/probectl-control:v0.4.0}
YAML
  echo '# missing registry-auth contract' > "$tmp/docs/install.md"
  echo '# missing registry-auth contract' > "$tmp/deploy/compose/README.md"
  echo '# missing image override' > "$tmp/deploy/compose/.env.example"
  if run_checks "$tmp" 2>/dev/null; then
    echo "SELFTEST FAILED: bad fixture passed" >&2
    exit 1
  fi

  fail=0
  cat > "$tmp/docs/install.md" <<'MD'
Use `ghcr.io/imfeelingtheagi/probectl-control:v0.4.0`.
If GHCR returns 401, run `docker login ghcr.io` with read:packages.
Set `PROBECTL_IMAGE` to use a mirror.
Run `bash scripts/compose_image_preflight.sh` before compose up.
MD
  cat > "$tmp/deploy/compose/README.md" <<'MD'
Use `docker login ghcr.io` if the release package is not anonymous.
Run `bash scripts/compose_image_preflight.sh` before compose up.
MD
  cat > "$tmp/deploy/compose/.env.example" <<'ENV'
# PROBECTL_IMAGE=ghcr.io/imfeelingtheagi/probectl-control:v0.4.0
ENV
  cat > "$tmp/Makefile" <<'MAKE'
compose-prod-up: compose-prod-preflight
MAKE
  run_checks "$tmp"
  if [ "$fail" -ne 0 ]; then
    echo "SELFTEST FAILED: good fixture failed" >&2
    exit 1
  fi
  echo "compose-image-contract SELFTEST: OK"
  exit 0
fi

run_checks "."
if [ "$fail" -ne 0 ]; then
  exit 1
fi
echo "compose-image-contract: OK (docs/auth/mirror contract matches the exact compose image)"
