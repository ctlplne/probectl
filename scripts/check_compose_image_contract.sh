#!/usr/bin/env bash
# check_compose_image_contract.sh — OPS-001 guard for the shipped Compose image.
#
# The shipped all-in-one compose file points certgen + control at one immutable
# release image, or fails closed until the operator supplies one. This gate keeps
# three things true:
#   1. both services use the same digest-pinned image contract,
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
  (grep -oE '\$\{PROBECTL_IMAGE:-[^}]+' "$root/deploy/compose/probectl.yml" || true) \
    | sed 's/.*:-//' \
    | sort -u
}

run_checks() {
  local root="$1"
  local images image_count required_refs

  local image=""
  images="$(extract_default_images "$root")"
  image_count="$(printf '%s\n' "$images" | sed '/^$/d' | wc -l | tr -d ' ')"
  required_refs="$(grep -c '\${PROBECTL_IMAGE:?' "$root/deploy/compose/probectl.yml" || true)"
  if [ "$image_count" -eq 0 ]; then
    if [ "$required_refs" -ne 2 ]; then
      err "deploy/compose/probectl.yml must either use one digest default twice or require PROBECTL_IMAGE for both certgen/control; found $required_refs required refs"
    fi
  elif [ "$image_count" -ne 1 ]; then
    err "deploy/compose/probectl.yml must have exactly one PROBECTL_IMAGE default when a default exists; found $image_count"
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
      ghcr.io/imfeelingtheagi/probectl-control:v[0-9]*.[0-9]*.[0-9]*@sha256:*) ;;
      *) err "compose default must be a digest-pinned probectl-control release, got: $image" ;;
    esac

    grep -Fq "$image" "$root/docs/install.md" \
      || err "docs/install.md must name the exact compose image ($image)"
    grep -Fq "$image" "$root/deploy/compose/.env.example" \
      || err "deploy/compose/.env.example must show the exact compose image override ($image)"
  else
    grep -Fq 'no mutable image default' "$root/docs/install.md" \
      || err "docs/install.md must say production Compose has no mutable image default"
    grep -Fq 'PROBECTL_IMAGE=ghcr.io/imfeelingtheagi/probectl-control:v0.4.0@sha256:<release-digest>' "$root/deploy/compose/.env.example" \
      || err "deploy/compose/.env.example must show a digest-pinned PROBECTL_IMAGE placeholder"
    grep -Fq 'PROBECTL_ALLOW_TAG_IMAGE=i-understand-this-is-mutable' "$root/deploy/compose/.env.example" \
      || err "deploy/compose/.env.example must document the explicit tag-only acknowledgement"
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
      err "anonymous pull smoke requested, but production Compose has no default image; set PROBECTL_COMPOSE_IMAGE_ANONYMOUS_PULL only for digest-default releases"
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
  cat > "$tmp/deploy/compose/probectl.yml" <<'YAML'
services:
  certgen:
    image: "${PROBECTL_IMAGE:?set PROBECTL_IMAGE}"
  control:
    image: "${PROBECTL_IMAGE:?set PROBECTL_IMAGE}"
YAML
  cat > "$tmp/docs/install.md" <<'MD'
The shipped compose stack has no mutable image default.
If GHCR returns 401, run `docker login ghcr.io` with read:packages.
Set `PROBECTL_IMAGE` to use a mirror.
Run `bash scripts/compose_image_preflight.sh` before compose up.
MD
  cat > "$tmp/deploy/compose/README.md" <<'MD'
Use `docker login ghcr.io` if the release package is not anonymous.
Run `bash scripts/compose_image_preflight.sh` before compose up.
MD
  cat > "$tmp/deploy/compose/.env.example" <<'ENV'
# PROBECTL_IMAGE=ghcr.io/imfeelingtheagi/probectl-control:v0.4.0@sha256:<release-digest>
# PROBECTL_ALLOW_TAG_IMAGE=i-understand-this-is-mutable
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
