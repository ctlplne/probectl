#!/usr/bin/env bash
# supply-pins gate (SUPPLY-001/002/006, Sprint 23): every mutable input is
# pinned. Fails on:
#   - ":latest" image refs under deploy/ (a clearly-labeled local-dev line
#     may opt out with "# local-dev-ok")
#   - `go install ...` in CI without an exact @vX.Y.Z
#   - `pip install` in CI/Makefile without exact ==pins, --require-hashes,
#     or --no-deps
#   - npm/Python manifest dependency ranges (`^`, `~`, `>=`, etc.) in direct
#     dependency manifests (lockfiles still pin the transitive tree)
# SELFTEST: check_supply_pins.sh SELFTEST exercises the failure paths.
set -euo pipefail
cd "$(dirname "$0")/.."

fail=0

go_install_record_is_unpinned() {
  local record="$1"
  local code rest segment boundary token target_seen
  local -a tokens

  # grep -nH records are path:line:source. Inspect source only, and remove the
  # comment tail before deciding whether the record contains an install.
  code="${record#*:}"
  code="${code#*:}"
  code="${code%%#*}"
  [[ "$code" == *"go install "* ]] || return 1

  # A version elsewhere on the YAML/shell record proves nothing about the
  # installed package. Isolate each go-install command, then require every
  # target token in that command to carry its own exact suffix. This parser is
  # deliberately conservative: an empty or ambiguous command fails closed.
  rest="$code"
  while [[ "$rest" == *"go install "* ]]; do
    rest="${rest#*go install }"
    segment="$rest"
    for boundary in '&&' '||' ';' '|'; do
      if [[ "$segment" == *"$boundary"* ]]; then
        segment="${segment%%"$boundary"*}"
      fi
    done

    read -r -a tokens <<< "$segment"
    target_seen=0
    for token in "${tokens[@]}"; do
      # Build flags are not install targets. Require flags with values to use
      # -flag=value; a separate value is intentionally treated as an ambiguous
      # target and rejected rather than guessed around.
      [[ "$token" == -* ]] && continue
      [[ "$token" == *'>'* || "$token" == *'<'* ]] && break
      token="${token#\"}"; token="${token%\"}"
      token="${token#\'}"; token="${token%\'}"
      target_seen=1
      [[ "$token" =~ ^[^@[:space:]]+@v[0-9]+\.[0-9]+\.[0-9]+$ ]] || return 0
    done
    [[ "$target_seen" -eq 1 ]] || return 0
  done
  return 1
}

if [[ "${1:-}" == "SELFTEST" ]]; then
  tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
  echo 'image: ghcr.io/x/y:latest' > "$tmp/bad.yml"
  grep -q ':latest' "$tmp/bad.yml" || { echo "SELFTEST broken"; exit 1; }
  cat > "$tmp/go-installs.yml" <<'YAML'
jobs:
  tools:
    steps:
      - run: go install example.com/unpinned/tool
      - run: go install example.com/pinned/tool@v1.2.3
      - run: echo example.com/unrelated@v9.9.9 && go install example.com/unpinned/before
      - run: go install example.com/unpinned/after && echo example.com/unrelated@v9.9.9
      # go install example.com/comment-only/tool
YAML
  bad_go_installs=0
  while IFS= read -r line; do
    if go_install_record_is_unpinned "$line"; then
      bad_go_installs=$((bad_go_installs + 1))
    fi
  done < <(grep -nH 'go install ' "$tmp/go-installs.yml" || true)
  if [[ "$bad_go_installs" -eq 3 ]]; then :; else echo "SELFTEST broken (go install pin)"; exit 1; fi
  go_install_record_is_unpinned 'fixture.yml:1:echo example.com/unrelated@v9.9.9 && go install example.com/unpinned/before' \
    || { echo "SELFTEST broken (unrelated version before go install)"; exit 1; }
  go_install_record_is_unpinned 'fixture.yml:2:go install example.com/unpinned/after && echo example.com/unrelated@v9.9.9' \
    || { echo "SELFTEST broken (unrelated version after go install)"; exit 1; }
  if go_install_record_is_unpinned 'fixture.yml:3:go install example.com/pinned/tool@v1.2.3'; then
    echo "SELFTEST broken (exact go install target rejected)"
    exit 1
  fi
  echo 'pip install ruff' > "$tmp/bad.sh"
  if grep -E 'pip install' "$tmp/bad.sh" | grep -vqE '(==|--require-hashes|--no-deps|-r [^ ]+\.lock)'; then :; else echo "SELFTEST broken"; exit 1; fi
  cat > "$tmp/package.json" <<'JSON'
{
  "dependencies": {
    "left-pad": "^1.3.0"
  }
}
JSON
  if awk '/"dependencies"[[:space:]]*:[[:space:]]*\{/ {in_deps=1; next} in_deps && /\}/ {in_deps=0; next} in_deps {spec=$0; sub(/^[^:]*:[[:space:]]*"/, "", spec); sub(/".*$/, "", spec); if (spec !~ /^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$/) bad=1} END {exit bad ? 0 : 1}' "$tmp/package.json"; then :; else echo "SELFTEST broken (npm manifest range)"; exit 1; fi
  cat > "$tmp/pyproject.toml" <<'TOML'
[project]
dependencies = [
  "structlog>=24.1.0",
]
TOML
  if awk '/^[[:space:]]*(dependencies|dev)[[:space:]]*=[[:space:]]*\[/ {in_deps=1; next} in_deps && /^[[:space:]]*\]/ {in_deps=0; next} in_deps && /"/ {spec=$0; sub(/^[^"]*"/, "", spec); sub(/".*$/, "", spec); if (spec !~ /==/) bad=1} END {exit bad ? 0 : 1}' "$tmp/pyproject.toml"; then :; else echo "SELFTEST broken (python manifest range)"; exit 1; fi
  echo 'apt-get install -y clang llvm bpftool' > "$tmp/bad.dockerfile"
  if grep -qE '(^| )clang( |$)' "$tmp/bad.dockerfile"; then :; else echo "SELFTEST broken (clang pin)"; exit 1; fi
  echo '# syntax=docker/dockerfile:1' > "$tmp/Dockerfile"
  if grep -Eq '^# syntax=.*docker/dockerfile:[^ @]+($|[[:space:]])' "$tmp/Dockerfile" && ! grep -q '@sha256:' "$tmp/Dockerfile"; then :; else echo "SELFTEST broken (BuildKit frontend pin)"; exit 1; fi
  cat > "$tmp/bad-toolchain.yml" <<'YAML'
jobs:
  ebpf:
    steps:
      - run: sudo apt-get install -y clang llvm linux-tools-generic
YAML
  if grep -Eq 'apt-get install .* (clang|llvm|bpftool|linux-tools-generic)' "$tmp/bad-toolchain.yml"; then :; else echo "SELFTEST broken (workflow ebpf toolchain pin)"; exit 1; fi
  # SUPPLY-003: camelCase *Image: keys (e.g. installerImage:) must be reachable
  # by the digest scan — the case-sensitive `image:` scan in (5) misses them.
  line='installerImage: busybox:1.36'; val="${line#*[Ii]mage:}"; val="$(echo "$val" | tr -d '[:space:]')"
  if echo "$val" | grep -q '@sha256:'; then echo "SELFTEST broken (installerImage extract)"; exit 1; fi
  echo "$val" | grep -q ':' || { echo "SELFTEST broken (installerImage tag)"; exit 1; }
  # SUPPLY-002: workflow `container:` images must be reachable too.
  line='container: mcr.microsoft.com/playwright:v1.55.1-noble'; val="${line#*container:}"; val="$(echo "$val" | tr -d '[:space:]')"
  if echo "$val" | grep -q '@sha256:'; then echo "SELFTEST broken (container extract)"; exit 1; fi
  echo "$val" | grep -q ':' || { echo "SELFTEST broken (container tag)"; exit 1; }
  # SUPPLY-001: a production Compose PROBECTL_IMAGE default that is tag-only is
  # still mutable even when it is not :latest.
  cat > "$tmp/probectl.yml" <<'YAML'
services:
  control:
    image: ${PROBECTL_IMAGE:-ghcr.io/imfeelingtheagi/probectl-control:v0.4.0}
YAML
  if grep -oE '\$\{PROBECTL_IMAGE:-[^}]+' "$tmp/probectl.yml" | sed 's/.*:-//' | awk 'index($0,"@sha256:")==0 { bad=1 } END { exit bad ? 0 : 1 }'; then :; else echo "SELFTEST broken (compose tag default)"; exit 1; fi
  echo "supply-pins SELFTEST: OK"
  exit 0
fi

# 1) :latest image refs under deploy/ (comments stripped; explicit
#    local-dev opt-outs allowed with "local-dev-ok").
while IFS= read -r line; do
  echo "$line" | grep -q 'local-dev-ok' && continue
  code="${line#*:}"; code="${code%%#*}" # strip file:line prefix piece + trailing comment
  echo "$code" | grep -q ':latest' || continue
  echo "FORBIDDEN :latest image ref (pin a release; SUPPLY-001):"
  echo "  $line"
  fail=1
done < <(grep -rn ':latest' deploy/ --include='*.yml' --include='*.yaml' || true)

# 1b) Production Compose must not ship a tag-only PROBECTL_IMAGE default. It may
#     either require PROBECTL_IMAGE (fail-closed) or provide a digest-pinned
#     default. A version tag like :v0.4.0 is still mutable registry state.
while IFS= read -r line; do
  val="${line#*:-}"
  val="${val%%\}*}"
  val="$(echo "$val" | tr -d '[:space:]"'\''')"
  echo "$val" | grep -q '@sha256:' && continue
  echo "TAG-ONLY production Compose PROBECTL_IMAGE default (require PROBECTL_IMAGE or digest-pin it; SUPPLY-001):"
  echo "  $line"
  fail=1
done < <(grep -rn '\${PROBECTL_IMAGE:-' deploy/compose/probectl.yml || true)

# 2) go install without an exact version in workflows/Makefile.
while IFS= read -r line; do
  go_install_record_is_unpinned "$line" || continue
  echo "UNPINNED go install (want @vX.Y.Z):"
  echo "  $line"
  fail=1
done < <(grep -rnH 'go install ' .github/workflows Makefile || true)

# 3) pip install without exact pins / hashes / no-deps / a lockfile.
while IFS= read -r line; do
  echo "$line" | grep -qE '(==|--require-hashes|--no-deps|-r [^ ]*requirements[^ ]*\.lock|install uv==)' && continue
  echo "UNPINNED pip install (want ==X.Y.Z, --require-hashes, or --no-deps):"
  echo "  $line"
  fail=1
done < <(grep -rn 'pip install' .github/workflows Makefile | grep -v '^\s*#' || true)

# 3b) Direct package manifests must declare exact top-level dependency pins.
#     Lockfiles pin the resolved transitive tree, but a range in package.json /
#     pyproject.toml still tells humans and package managers "floating intent".
#     Keep the manifest, policy, and gate saying the same thing (CODE-006).
for manifest in web/package.json browser-worker/package.json; do
  [[ -f "$manifest" ]] || continue
  while IFS= read -r line; do
    echo "UNPINNED npm manifest dependency (want exact X.Y.Z, no ^/~/>=):"
    echo "  $line"
    fail=1
  done < <(awk '
    /"(dependencies|devDependencies|optionalDependencies|peerDependencies)"[[:space:]]*:[[:space:]]*\{/ { in_deps=1; next }
    in_deps && /^[[:space:]]*\}/ { in_deps=0; next }
    in_deps && /^[[:space:]]*"[^"]+"[[:space:]]*:/ {
      spec=$0
      sub(/^[^:]*:[[:space:]]*"/, "", spec)
      sub(/".*$/, "", spec)
      if (spec !~ /^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$/) {
        printf "%s:%d:%s\n", FILENAME, FNR, $0
      }
    }' "$manifest")
done

if [[ -f analyzer/pyproject.toml ]]; then
  while IFS= read -r line; do
    echo "UNPINNED Python manifest dependency (want exact name==X.Y.Z):"
    echo "  $line"
    fail=1
  done < <(awk '
    /^[[:space:]]*(dependencies|dev)[[:space:]]*=[[:space:]]*\[/ { in_deps=1; next }
    in_deps && /^[[:space:]]*\]/ { in_deps=0; next }
    in_deps && /"/ {
      spec=$0
      sub(/^[^"]*"/, "", spec)
      sub(/".*$/, "", spec)
      if (spec !~ /==/) {
        printf "%s:%d:%s\n", FILENAME, FNR, $0
      }
    }' analyzer/pyproject.toml)
fi

# 4) eBPF toolchain pinning (SUPPLY-003): the BPF compiler and bpftool produce
#    kernel-loadable bytes, so they must not come from mutable runner apt state.
#    Dockerfile.ebpf owns the exact toolchain stage: digest-pinned base, signed
#    Debian snapshot, and exact clang/llvm/bpftool package versions.
if [[ -f deploy/docker/Dockerfile.ebpf ]]; then
  for want in \
    'AS ebpf-toolchain' \
    'ARG DEBIAN_SNAPSHOT=20260702T000000Z' \
    'ARG CLANG_14_VERSION=1:14.0.6-12' \
    'ARG LLVM_14_VERSION=1:14.0.6-12' \
    'ARG BPFTOOL_VERSION=7.1.0+6.1.174-1' \
    'snapshot.debian.org/archive/debian/${DEBIAN_SNAPSHOT}' \
    'snapshot.debian.org/archive/debian-security/${DEBIAN_SNAPSHOT}' \
    '"clang-14=${CLANG_14_VERSION}"' \
    '"llvm-14=${LLVM_14_VERSION}"' \
    '"bpftool=${BPFTOOL_VERSION}"'; do
    if ! grep -Fq "$want" deploy/docker/Dockerfile.ebpf; then
      echo "eBPF Dockerfile missing pinned toolchain contract piece (SUPPLY-003): $want"
      fail=1
    fi
  done
  while IFS= read -r raw; do
    code="${raw#*:}"; code="${code%%#*}"   # strip file:line prefix + trailing comment
    stripped="${code#"${code%%[![:space:]]*}"}"
    [[ "$stripped" == \#* ]] && continue   # skip full-comment lines
    code="${code//\\/ }"                  # drop the line-continuation backslash
    for tok in $code; do
      if [[ "$tok" == clang || "$tok" == llvm ]]; then
        echo "UNPINNED clang/llvm on the eBPF build path (want clang-NN / llvm-NN; SUPPLY-001):"
        echo "  $raw"
        fail=1
      fi
    done
  done < <(grep -rni 'clang' deploy/docker/Dockerfile.ebpf 2>/dev/null; grep -rni 'llvm' deploy/docker/Dockerfile.ebpf 2>/dev/null || true)
fi

# 4c) BuildKit frontend pinning. Dockerfile `# syntax=` is itself an external
#     image pull before any stage starts. Treat it like a build dependency:
#     tag-only docker/dockerfile frontends are mutable and must be digest-pinned.
while IFS= read -r line; do
  echo "$line" | grep -q '@sha256:' && continue
  echo "TAG-ONLY BuildKit frontend (digest-pin # syntax=docker/dockerfile; SUPPLY-005):"
  echo "  $line"
  fail=1
done < <(grep -rnE '^# syntax=.*docker/dockerfile:[^ @]+($|[[:space:]])' deploy/docker --include='Dockerfile*' || true)

# 4b) Workflow apt installs may still install runner infrastructure such as
#     qemu, but not clang/llvm/bpftool/linux-tools for the eBPF object build.
#     Those must run through scripts/run-ebpf-toolchain.sh so release and CI use
#     the same pinned toolchain stage.
while IFS= read -r raw; do
  code="${raw#*:}"; code="${code%%#*}"
  stripped="${code#"${code%%[![:space:]]*}"}"
  [[ "$stripped" == \#* ]] && continue
  echo "$code" | grep -q 'apt-get install' || continue
  for tok in $code; do
    case "$tok" in
      clang|llvm|bpftool|linux-tools-common|linux-tools-generic)
        echo "UNPINNED eBPF toolchain install in workflow (run scripts/run-ebpf-toolchain.sh instead; SUPPLY-003):"
        echo "  $raw"
        fail=1
        ;;
    esac
  done
done < <(grep -rnE 'apt-get install.*(clang|llvm|bpftool|linux-tools)' .github/workflows --include='*.yml' --include='*.yaml' || true)

# 5) SUPPLY-006: tag-only (non-digest) image refs under deploy/helm. A `:tag`
#    with no `@sha256:` is mutable — the restore Job once fell back to a bare
#    postgres:16. Flag any concrete image ref that is not digest-pinned. Skips
#    template expressions ({{ ... }}), empty defaults (image: ""), and lines
#    opting out with "# tag-only-ok".
while IFS= read -r line; do
  echo "$line" | grep -q 'tag-only-ok' && continue
  val="${line#*image:}"; val="${val%%#*}"          # value after image:, drop comment
  val="$(echo "$val" | tr -d '[:space:]"'\''')"     # strip ws + quotes
  [[ -z "$val" ]] && continue                        # image: "" default
  echo "$val" | grep -q '{{' && continue             # helm template expression
  echo "$val" | grep -q '@sha256:' && continue       # digest-pinned — good
  echo "$val" | grep -q ':' || continue              # no tag at all (rare); skip
  echo "TAG-ONLY image ref under deploy/helm (digest-pin it; SUPPLY-006):"
  echo "  $line"
  fail=1
done < <(grep -rn 'image:' deploy/helm --include='*.yaml' --include='*.yml' | grep -v '^\s*#' || true)

# 6) SUPPLY-003: camelCase image keys under deploy/helm — e.g. `installerImage:`
#    (capital-I 'Image') — slip past the case-sensitive `image:` scan in (5).
#    The agent seccomp-installer runs a PRIVILEGED initContainer on every node,
#    so a tag-hijack executes code before the agent starts. Require a digest pin
#    on every `<name>Image:` value under deploy/helm.
while IFS= read -r line; do
  echo "$line" | grep -q 'tag-only-ok' && continue
  val="${line#*[Ii]mage:}"; val="${val%%#*}"          # value after *Image:, drop comment
  val="$(echo "$val" | tr -d '[:space:]"'\''')"        # strip ws + quotes
  [[ -z "$val" ]] && continue                          # empty default
  echo "$val" | grep -q '{{' && continue               # helm template expression
  echo "$val" | grep -q '@sha256:' && continue         # digest-pinned — good
  echo "$val" | grep -q ':' || continue                # no tag at all; skip
  echo "TAG-ONLY camelCase image ref under deploy/helm (digest-pin it; SUPPLY-003):"
  echo "  $line"
  fail=1
done < <(grep -rnE '[A-Za-z]+Image:' deploy/helm --include='*.yaml' --include='*.yml' | grep -v '^\s*#' || true)

# 7) SUPPLY-002: CI `container:` job images run outside the deploy/ scan. A
#    tag-only `container:` (e.g. the Playwright browser-worker) is a mutable
#    input — a pin-gate blind-spot. Require a digest pin on every concrete
#    `container:` image value in the workflows (string form; the nested mapping
#    form `container:\n  image:` is left for a future deploy-style scan).
while IFS= read -r line; do
  echo "$line" | grep -q 'tag-only-ok' && continue
  val="${line#*container:}"; val="${val%%#*}"          # value after container:, drop comment
  val="$(echo "$val" | tr -d '[:space:]"'\''')"        # strip ws + quotes
  [[ -z "$val" ]] && continue                          # mapping form / empty — skip
  echo "$val" | grep -q '{{' && continue               # ${{ }} expression
  echo "$val" | grep -q '@sha256:' && continue         # digest-pinned — good
  echo "$val" | grep -q ':' || continue                # no tag (rare); skip
  echo "TAG-ONLY container: image in workflows (digest-pin it; SUPPLY-002):"
  echo "  $line"
  fail=1
done < <(grep -rnE '^[[:space:]]*container:[[:space:]]*[^[:space:]]' .github/workflows --include='*.yml' --include='*.yaml' | grep -v '^\s*#' || true)

if [[ $fail -ne 0 ]]; then
  echo
  echo "supply-pins gate FAILED — pin the inputs above (docs/dependency-policy.md)."
  exit 1
fi
echo "supply-pins gate: OK (no :latest, no unpinned installs/manifests, no tag-only helm/container/BuildKit frontend image)"
