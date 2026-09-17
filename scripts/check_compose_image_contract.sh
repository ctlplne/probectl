#!/usr/bin/env bash
# check_compose_image_contract.sh — OPS-001 guard for the shipped Compose image.
#
# The shipped all-in-one compose file points certgen + control at one immutable
# release image, or fails closed until the operator supplies one. This gate keeps
# five things true:
#   1. both services use the same digest-pinned image contract,
#   2. install docs wire the hard preflight before compose up,
#   3. install docs explain GHCR auth / PROBECTL_IMAGE override when anonymous
#      pull is unavailable,
#   4. an optional anonymous-pull smoke uses the exact compose image and a clean
#      Docker credential directory,
#   5. certgen invokes the distroless control binary directly, without /bin/sh.
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
  local images image_count required_refs version expected_prefix expected_placeholder certgen

  local image=""
  if [ ! -f "$root/VERSION" ]; then
    err "VERSION is required to validate the Compose release image"
    version=""
  else
    version="$(tr -d '[:space:]' < "$root/VERSION")"
  fi
  if [[ ! "$version" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]; then
    err "VERSION must contain one stable MAJOR.MINOR.PATCH version, got: ${version:-<empty>}"
  fi
  expected_prefix="ghcr.io/ctlplne/probectl-control:v${version}@sha256:"
  expected_placeholder="${expected_prefix}<release-digest>"

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
      "$expected_prefix"*) ;;
      *) err "compose default must be the VERSION-matched digest-pinned release ($expected_prefix...), got: $image" ;;
    esac

    grep -Fq "$image" "$root/docs/install.md" \
      || err "docs/install.md must name the exact compose image ($image)"
    grep -Fq "$image" "$root/deploy/compose/.env.example" \
      || err "deploy/compose/.env.example must show the exact compose image override ($image)"
  else
    grep -Fq 'no mutable image default' "$root/docs/install.md" \
      || err "docs/install.md must say production Compose has no mutable image default"
    grep -Fq "PROBECTL_IMAGE=$expected_placeholder" "$root/deploy/compose/.env.example" \
      || err "deploy/compose/.env.example must show the VERSION-matched digest placeholder ($expected_placeholder)"
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

  certgen="$(sed -n '/^  certgen:[[:space:]]*$/,/^  control:[[:space:]]*$/p' "$root/deploy/compose/probectl.yml")"
  if [ -z "$certgen" ]; then
    err "deploy/compose/probectl.yml must contain the certgen service"
  else
    grep -Fq '/bin/sh' <<<"$certgen" \
      && err "certgen uses the distroless control image and must not invoke /bin/sh"
    grep -qE '^[[:space:]]+entrypoint:' <<<"$certgen" \
      && err "certgen must keep the distroless image entrypoint (/usr/local/bin/app)"
    grep -Fq 'command: ["gen-cert", "--if-missing", "/certs"]' <<<"$certgen" \
      || err "certgen must directly invoke gen-cert --if-missing /certs"
  fi

  # DPR-008: the certificate directory is env-selectable on every /certs mount
  # (certgen, postgres, control) and documented; a hard-wired named volume
  # would send operators back to "somehow copy files into a Docker volume".
  tls_mounts="$(grep -c '\${PROBECTL_TLS_DIR:-certs}:/certs' "$root/deploy/compose/probectl.yml" || true)"
  [ "$tls_mounts" -ge 3 ] \
    || err "deploy/compose/probectl.yml must mount \${PROBECTL_TLS_DIR:-certs}:/certs for certgen, postgres and control (found $tls_mounts)"
  grep -Eq '^PROBECTL_TLS_DIR=' "$root/deploy/compose/.env.example" \
    || err "deploy/compose/.env.example must document PROBECTL_TLS_DIR (bring-your-own certificate directory)"
  grep -Fq 'PROBECTL_TLS_DIR' "$root/docs/install.md" \
    || err "docs/install.md must explain PROBECTL_TLS_DIR for CA-issued certificates"
  # DPR-006: a licensed (Enterprise/MSP) deployment has a shipped install path.
  [ -f "$root/deploy/compose/license.yml" ] \
    || err "deploy/compose/license.yml (license overlay) must exist"
  grep -Fq 'PROBECTL_LICENSE_FILE: /etc/probectl/license.json' "$root/deploy/compose/license.yml" \
    || err "deploy/compose/license.yml must set PROBECTL_LICENSE_FILE for the control service"
  grep -Fq '${PROBECTL_LICENSE_PATH:?' "$root/deploy/compose/license.yml" \
    || err "deploy/compose/license.yml must require PROBECTL_LICENSE_PATH (no silent Community fallback)"
  grep -Eq '^PROBECTL_LICENSE_PATH=' "$root/deploy/compose/.env.example" \
    || err "deploy/compose/.env.example must document PROBECTL_LICENSE_PATH"
  grep -Fq 'PROBECTL_COMPOSE_OVERLAYS' "$root/Makefile" \
    || err "Makefile compose-prod-up must accept PROBECTL_COMPOSE_OVERLAYS (license.yml)"
  grep -Fq 'license.yml' "$root/docs/install.md" \
    || err "docs/install.md must show how to install a license with deploy/compose/license.yml"
  # DPR-010: every other documented PROBECTL_* key has a shipped, optional,
  # never-committed home (control.env) instead of a hand-edited compose file.
  control_block="$(sed -n '/^  control:[[:space:]]*$/,/^volumes:[[:space:]]*$/p' "$root/deploy/compose/probectl.yml")"
  grep -Fq 'path: ./control.env' <<<"$control_block" \
    || err "deploy/compose/probectl.yml control service must load the optional ./control.env"
  grep -Fq 'required: false' <<<"$control_block" \
    || err "deploy/compose/probectl.yml control.env must be optional (required: false)"
  [ -f "$root/deploy/compose/control.env.example" ] \
    || err "deploy/compose/control.env.example must exist"
  grep -Fq 'control.env' "$root/docs/install.md" \
    || err "docs/install.md must explain deploy/compose/control.env for extra PROBECTL_* keys"

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
  echo '9.8.7' > "$tmp/VERSION"
  echo '# no compose preflight' > "$tmp/Makefile"
  echo '# preflight placeholder' > "$tmp/scripts/compose_image_preflight.sh"
  cat > "$tmp/deploy/compose/probectl.yml" <<'YAML'
services:
  certgen:
    image: ${PROBECTL_IMAGE:-ghcr.io/ctlplne/probectl-control:v0.4.0}
  control:
    image: ${PROBECTL_IMAGE:-ghcr.io/ctlplne/probectl-control:v0.4.0}
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
  postgres:
    volumes:
      - ${PROBECTL_TLS_DIR:-certs}:/certs:ro
  certgen:
    image: "${PROBECTL_IMAGE:?set PROBECTL_IMAGE}"
    command: ["gen-cert", "--if-missing", "/certs"]
    volumes:
      - ${PROBECTL_TLS_DIR:-certs}:/certs
  control:
    image: "${PROBECTL_IMAGE:?set PROBECTL_IMAGE}"
    env_file:
      - path: ./control.env
        required: false
    volumes:
      - ${PROBECTL_TLS_DIR:-certs}:/certs:ro
volumes:
  certs: {}
YAML
  cat > "$tmp/deploy/compose/license.yml" <<'YAML'
services:
  control:
    environment:
      PROBECTL_LICENSE_FILE: /etc/probectl/license.json
    volumes:
      - ${PROBECTL_LICENSE_PATH:?set PROBECTL_LICENSE_PATH}:/etc/probectl/license.json:ro
YAML
  cat > "$tmp/docs/install.md" <<'MD'
The shipped compose stack has no mutable image default.
If GHCR returns 401, run `docker login ghcr.io` with read:packages.
Set `PROBECTL_IMAGE` to use a mirror.
Run `bash scripts/compose_image_preflight.sh` before compose up.
Set PROBECTL_TLS_DIR for a CA-issued certificate. Install a license with license.yml.
Other PROBECTL_* keys go in deploy/compose/control.env.
MD
  echo '# example' > "$tmp/deploy/compose/control.env.example"
  cat > "$tmp/deploy/compose/README.md" <<'MD'
Use `docker login ghcr.io` if the release package is not anonymous.
Run `bash scripts/compose_image_preflight.sh` before compose up.
MD
  cat > "$tmp/deploy/compose/.env.example" <<'ENV'
# PROBECTL_IMAGE=ghcr.io/ctlplne/probectl-control:v9.8.7@sha256:<release-digest>
# PROBECTL_ALLOW_TAG_IMAGE=i-understand-this-is-mutable
PROBECTL_TLS_DIR=
PROBECTL_LICENSE_PATH=
ENV
  cat > "$tmp/Makefile" <<'MAKE'
PROBECTL_COMPOSE_OVERLAYS ?=
compose-prod-up: compose-prod-preflight
MAKE
  run_checks "$tmp"
  if [ "$fail" -ne 0 ]; then
    echo "SELFTEST FAILED: good fixture failed" >&2
    exit 1
  fi

  expect_fixture_failure() {
    local label="$1"
    fail=0
    if run_checks "$tmp" >/dev/null 2>&1; then
      echo "SELFTEST FAILED: $label fixture passed" >&2
      exit 1
    fi
  }

  cat > "$tmp/deploy/compose/probectl.yml" <<'YAML'
services:
  certgen:
    image: "${PROBECTL_IMAGE:?set PROBECTL_IMAGE}"
    entrypoint: ["/bin/sh", "-c"]
    command: ["test -f /certs/tls.crt || /usr/local/bin/app gen-cert /certs"]
  control:
    image: "${PROBECTL_IMAGE:?set PROBECTL_IMAGE}"
YAML
  expect_fixture_failure "distroless-shell"

  cat > "$tmp/deploy/compose/probectl.yml" <<'YAML'
services:
  postgres:
    volumes:
      - ${PROBECTL_TLS_DIR:-certs}:/certs:ro
  certgen:
    image: "${PROBECTL_IMAGE:?set PROBECTL_IMAGE}"
    command: ["gen-cert", "--if-missing", "/certs"]
    volumes:
      - ${PROBECTL_TLS_DIR:-certs}:/certs
  control:
    image: "${PROBECTL_IMAGE:?set PROBECTL_IMAGE}"
    env_file:
      - path: ./control.env
        required: false
    volumes:
      - ${PROBECTL_TLS_DIR:-certs}:/certs:ro
volumes:
  certs: {}
YAML

  cat > "$tmp/deploy/compose/.env.example" <<'ENV'
# PROBECTL_IMAGE=ghcr.io/ctlplne/probectl-control:v9.8.6@sha256:<release-digest>
# PROBECTL_ALLOW_TAG_IMAGE=i-understand-this-is-mutable
PROBECTL_TLS_DIR=
PROBECTL_LICENSE_PATH=
ENV
  expect_fixture_failure "wrong-version"

  # DPR-008: a hard-wired named certs volume must fail the contract.
  cat > "$tmp/deploy/compose/.env.example" <<'ENV'
# PROBECTL_IMAGE=ghcr.io/ctlplne/probectl-control:v9.8.7@sha256:<release-digest>
# PROBECTL_ALLOW_TAG_IMAGE=i-understand-this-is-mutable
PROBECTL_TLS_DIR=
PROBECTL_LICENSE_PATH=
ENV
  cat > "$tmp/deploy/compose/probectl.yml" <<'YAML'
services:
  postgres:
    volumes:
      - certs:/certs:ro
  certgen:
    image: "${PROBECTL_IMAGE:?set PROBECTL_IMAGE}"
    command: ["gen-cert", "--if-missing", "/certs"]
    volumes:
      - certs:/certs
  control:
    image: "${PROBECTL_IMAGE:?set PROBECTL_IMAGE}"
    env_file:
      - path: ./control.env
        required: false
    volumes:
      - certs:/certs:ro
volumes:
  certs: {}
YAML
  expect_fixture_failure "hardwired-certs-volume"

  # DPR-006: a missing license overlay must fail the contract.
  cat > "$tmp/deploy/compose/probectl.yml" <<'YAML'
services:
  postgres:
    volumes:
      - ${PROBECTL_TLS_DIR:-certs}:/certs:ro
  certgen:
    image: "${PROBECTL_IMAGE:?set PROBECTL_IMAGE}"
    command: ["gen-cert", "--if-missing", "/certs"]
    volumes:
      - ${PROBECTL_TLS_DIR:-certs}:/certs
  control:
    image: "${PROBECTL_IMAGE:?set PROBECTL_IMAGE}"
    env_file:
      - path: ./control.env
        required: false
    volumes:
      - ${PROBECTL_TLS_DIR:-certs}:/certs:ro
volumes:
  certs: {}
YAML
  mv "$tmp/deploy/compose/license.yml" "$tmp/deploy/compose/license.yml.off"
  expect_fixture_failure "missing-license-overlay"
  mv "$tmp/deploy/compose/license.yml.off" "$tmp/deploy/compose/license.yml"

  cat > "$tmp/deploy/compose/.env.example" <<'ENV'
# PROBECTL_IMAGE=ghcr.io/ctlplne/probectl-control:v9.8.7
# PROBECTL_ALLOW_TAG_IMAGE=i-understand-this-is-mutable
ENV
  expect_fixture_failure "tag-only"

  cat > "$tmp/deploy/compose/.env.example" <<'ENV'
# PROBECTL_ALLOW_TAG_IMAGE=i-understand-this-is-mutable
ENV
  expect_fixture_failure "missing-image"

  cat > "$tmp/deploy/compose/.env.example" <<'ENV'
# PROBECTL_IMAGE=ghcr.io/ctlplne/probectl-control:v9.8.7@sha256:<release-digest>
# PROBECTL_ALLOW_TAG_IMAGE=i-understand-this-is-mutable
PROBECTL_TLS_DIR=
PROBECTL_LICENSE_PATH=
ENV
  fail=0
  run_checks "$tmp"
  if [ "$fail" -ne 0 ]; then
    echo "SELFTEST FAILED: good fixture did not recover after negative cases" >&2
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
