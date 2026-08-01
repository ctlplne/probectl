#!/usr/bin/env bash
# compose_image_preflight.sh - fail fast when the shipped compose image cannot
# be pulled anonymously and no local/mirrored override is present.
set -euo pipefail

ROOT="${PROBECTL_REPO_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
COMPOSE_FILE="${PROBECTL_COMPOSE_FILE:-$ROOT/deploy/compose/probectl.yml}"
ENV_FILE="${PROBECTL_COMPOSE_ENV_FILE:-$ROOT/deploy/compose/.env}"

trim() {
  local value="$1"
  value="${value#"${value%%[![:space:]]*}"}"
  value="${value%"${value##*[![:space:]]}"}"
  printf '%s' "$value"
}

env_file_image() {
  local file="$1"
  env_file_value "$file" "PROBECTL_IMAGE"
}

env_file_allow_tag() {
  local file="$1"
  env_file_value "$file" "PROBECTL_ALLOW_TAG_IMAGE"
}

env_file_value() {
  local file="$1" key="$2"
  local line value
  [ -f "$file" ] || return 0
  while IFS= read -r line; do
    line="${line%%#*}"
    case "$line" in
      "$key"=*)
        value="${line#*=}"
        value="$(trim "$value")"
        value="${value%\"}"
        value="${value#\"}"
        value="${value%\'}"
        value="${value#\'}"
        [ -n "$value" ] && printf '%s\n' "$value"
        return 0
        ;;
    esac
  done < "$file"
}

compose_default_image() {
  local images count
  images="$(
    (grep -oE '\$\{PROBECTL_IMAGE:-[^}]+' "$COMPOSE_FILE" || true) \
      | sed 's/.*:-//' \
      | sort -u
  )"
  count="$(printf '%s\n' "$images" | sed '/^$/d' | wc -l | tr -d ' ')"
  if [ "$count" -eq 0 ]; then
    return 0
  fi
  if [ "$count" -ne 1 ]; then
    echo "compose preflight: expected exactly one PROBECTL_IMAGE default in $COMPOSE_FILE, found $count" >&2
    return 2
  fi
  printf '%s\n' "$images" | sed -n '1p'
}

resolve_image() {
  if [ -n "${PROBECTL_IMAGE:-}" ]; then
    printf '%s\n' "$PROBECTL_IMAGE"
    return 0
  fi
  local from_env
  from_env="$(env_file_image "$ENV_FILE" || true)"
  if [ -n "$from_env" ]; then
    printf '%s\n' "$from_env"
    return 0
  fi
  compose_default_image
}

allow_tag_ack() {
  local from_env
  if [ "${PROBECTL_ALLOW_TAG_IMAGE:-}" = "i-understand-this-is-mutable" ]; then
    return 0
  fi
  from_env="$(env_file_allow_tag "$ENV_FILE" || true)"
  [ "$from_env" = "i-understand-this-is-mutable" ]
}

validate_image_ref() {
  local image="$1"
  case "$image" in
    *@sha256:*) return 0 ;;
  esac
  if allow_tag_ack; then
    echo "compose preflight: tag-only image allowed by explicit operator acknowledgement: $image"
    return 0
  fi
  cat >&2 <<EOF
compose preflight: PROBECTL_IMAGE must be digest-pinned for production Compose:
  $image

Use an immutable ref such as:
  ghcr.io/ctlplne/probectl-control:v0.4.0@sha256:<release-digest>

For a local or mirrored tag-only image, set:
  PROBECTL_ALLOW_TAG_IMAGE=i-understand-this-is-mutable
EOF
  return 2
}

print_failure_help() {
  local image="$1"
  cat >&2 <<EOF
compose preflight: cannot pull or find the compose image:
  $image

Pick one path, then rerun make compose-prod-up:

1. Authenticate to GHCR for the pinned release image:
   echo "\$GHCR_TOKEN" | docker login ghcr.io -u "\$GITHUB_USER" --password-stdin

2. Use a mirrored or internally published image:
   PROBECTL_IMAGE=registry.internal/probectl-control:v0.4.0@sha256:<release-digest> make compose-prod-up

3. Build the control-plane image locally from this checkout:
   docker build -f deploy/docker/Dockerfile --build-arg COMPONENT=probectl-control -t probectl-control:local .
   PROBECTL_IMAGE=probectl-control:local PROBECTL_ALLOW_TAG_IMAGE=i-understand-this-is-mutable make compose-prod-up
EOF
}

run_preflight() {
  local image
  image="$(resolve_image)"
  if [ -z "$image" ]; then
    echo "compose preflight: set PROBECTL_IMAGE to a digest-pinned release image before running production Compose" >&2
    echo "  example: PROBECTL_IMAGE=ghcr.io/ctlplne/probectl-control:v0.4.0@sha256:<release-digest>" >&2
    return 2
  fi
  validate_image_ref "$image"
  if ! command -v docker >/dev/null 2>&1; then
    echo "compose preflight: docker is required for deploy/compose/probectl.yml" >&2
    print_failure_help "$image"
    return 1
  fi
  if docker image inspect "$image" >/dev/null 2>&1; then
    echo "compose preflight: image already local: $image"
    return 0
  fi
  echo "compose preflight: image not local; checking pull access for $image"
  if docker pull "$image" >/dev/null; then
    echo "compose preflight: pulled image: $image"
    return 0
  fi
  print_failure_help "$image"
  return 1
}

run_selftest() {
  local tmp root script docker_log
  tmp="$(mktemp -d)"
  trap "rm -rf '$tmp'" EXIT
  root="$tmp/root"
  script="$0"
  docker_log="$tmp/docker.log"
  mkdir -p "$root/deploy/compose" "$tmp/bin"
  cat > "$root/deploy/compose/probectl.yml" <<'YAML'
services:
  certgen:
    image: "${PROBECTL_IMAGE:?set PROBECTL_IMAGE}"
  control:
    image: "${PROBECTL_IMAGE:?set PROBECTL_IMAGE}"
YAML
  cat > "$tmp/bin/docker" <<'SH'
#!/usr/bin/env bash
echo "$*" >> "${DOCKER_LOG:?}"
if [ "$1 $2" = "image inspect" ]; then
  exit "${INSPECT_RC:-1}"
fi
if [ "$1" = "pull" ]; then
  exit "${PULL_RC:-1}"
fi
exit 99
SH
  chmod +x "$tmp/bin/docker"

  PROBECTL_IMAGE="ghcr.io/ctlplne/probectl-control:v0.4.0@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" \
    DOCKER_LOG="$docker_log" INSPECT_RC=0 PULL_RC=1 PATH="$tmp/bin:$PATH" PROBECTL_REPO_ROOT="$root" bash "$script" >/dev/null
  : > "$docker_log"
  PROBECTL_IMAGE="ghcr.io/ctlplne/probectl-control:v0.4.0@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" \
    DOCKER_LOG="$docker_log" INSPECT_RC=1 PULL_RC=0 PATH="$tmp/bin:$PATH" PROBECTL_REPO_ROOT="$root" bash "$script" >/dev/null
  grep -Fq 'pull ghcr.io/ctlplne/probectl-control:v0.4.0@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' "$docker_log" || {
    echo "SELFTEST FAILED: pull path did not use the compose image" >&2
    return 1
  }
  : > "$docker_log"
  cat > "$root/deploy/compose/.env" <<'ENV'
PROBECTL_IMAGE=registry.internal/probectl-control:v0.4.0@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
ENV
  DOCKER_LOG="$docker_log" INSPECT_RC=0 PULL_RC=1 PATH="$tmp/bin:$PATH" PROBECTL_REPO_ROOT="$root" bash "$script" >/dev/null
  grep -Fq 'image inspect registry.internal/probectl-control:v0.4.0@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb' "$docker_log" || {
    echo "SELFTEST FAILED: .env image override was not used" >&2
    return 1
  }
  cat > "$root/deploy/compose/.env" <<'ENV'
PROBECTL_IMAGE=probectl-control:local
ENV
  set +e
  output="$(DOCKER_LOG="$docker_log" INSPECT_RC=0 PULL_RC=1 PATH="$tmp/bin:$PATH" PROBECTL_REPO_ROOT="$root" bash "$script" 2>&1 >/dev/null)"
  rc=$?
  set -e
  if [ "$rc" -eq 0 ] || ! grep -Fq "must be digest-pinned" <<<"$output"; then
    echo "SELFTEST FAILED: tag-only image passed without acknowledgement" >&2
    return 1
  fi
  cat > "$root/deploy/compose/.env" <<'ENV'
PROBECTL_IMAGE=probectl-control:local
PROBECTL_ALLOW_TAG_IMAGE=i-understand-this-is-mutable
ENV
  DOCKER_LOG="$docker_log" INSPECT_RC=0 PULL_RC=1 PATH="$tmp/bin:$PATH" PROBECTL_REPO_ROOT="$root" bash "$script" >/dev/null
  grep -Fq 'image inspect probectl-control:local' "$docker_log" || {
    echo "SELFTEST FAILED: tag-only acknowledgement was not honored" >&2
    return 1
  }
  set +e
  output="$(DOCKER_LOG="$docker_log" INSPECT_RC=1 PULL_RC=1 PATH="$tmp/bin:$PATH" PROBECTL_REPO_ROOT="$root" bash "$script" 2>&1 >/dev/null)"
  rc=$?
  set -e
  if [ "$rc" -eq 0 ]; then
    echo "SELFTEST FAILED: failed pull passed" >&2
    return 1
  fi
  for want in "docker login ghcr.io" "PROBECTL_IMAGE=registry.internal/probectl-control:v0.4.0@sha256:<release-digest>" "docker build -f deploy/docker/Dockerfile"; do
    if ! grep -Fq "$want" <<<"$output"; then
      echo "SELFTEST FAILED: missing failure help: $want" >&2
      return 1
    fi
  done
  echo "compose-image-preflight SELFTEST: OK"
}

if [ "${1:-}" = "SELFTEST" ]; then
  run_selftest
else
  run_preflight
fi
