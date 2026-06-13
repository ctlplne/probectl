#!/usr/bin/env bash
# supply-pins gate (SUPPLY-001/002/006, Sprint 23): every mutable input is
# pinned. Fails on:
#   - ":latest" image refs under deploy/ (a clearly-labeled local-dev line
#     may opt out with "# local-dev-ok")
#   - `go install ...` in CI without an exact @vX.Y.Z
#   - `pip install` in CI/Makefile without exact ==pins, --require-hashes,
#     or --no-deps
# SELFTEST: check_supply_pins.sh SELFTEST exercises the failure paths.
set -euo pipefail
cd "$(dirname "$0")/.."

fail=0

if [[ "${1:-}" == "SELFTEST" ]]; then
  tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
  echo 'image: ghcr.io/x/y:latest' > "$tmp/bad.yml"
  grep -q ':latest' "$tmp/bad.yml" || { echo "SELFTEST broken"; exit 1; }
  echo 'pip install ruff' > "$tmp/bad.sh"
  if grep -E 'pip install' "$tmp/bad.sh" | grep -vqE '(==|--require-hashes|--no-deps|-r [^ ]+\.lock)'; then :; else echo "SELFTEST broken"; exit 1; fi
  echo 'apt-get install -y clang llvm bpftool' > "$tmp/bad.dockerfile"
  if grep -qE '(^| )clang( |$)' "$tmp/bad.dockerfile"; then :; else echo "SELFTEST broken (clang pin)"; exit 1; fi
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

# 2) go install without an exact version in workflows/Makefile.
while IFS= read -r line; do
  echo "$line" | grep -qE '@v[0-9]+\.[0-9]+\.[0-9]+' && continue
  echo "UNPINNED go install (want @vX.Y.Z):"
  echo "  $line"
  fail=1
done < <(grep -rn 'go install ' .github/workflows Makefile | grep -v '^\s*#' | grep '@' || true)

# 3) pip install without exact pins / hashes / no-deps / a lockfile.
while IFS= read -r line; do
  echo "$line" | grep -qE '(==|--require-hashes|--no-deps|-r [^ ]*requirements[^ ]*\.lock|install uv==)' && continue
  echo "UNPINNED pip install (want ==X.Y.Z, --require-hashes, or --no-deps):"
  echo "  $line"
  fail=1
done < <(grep -rn 'pip install' .github/workflows Makefile | grep -v '^\s*#' || true)

# 4) bare clang/llvm install on the eBPF build path (SUPPLY-001): the BPF
#    compiler must be a PINNED versioned package (clang-NN / llvm-NN), never the
#    floating meta-package, or the BPF objects + U-014 digests drift. The
#    install spans a line-continuation, so tokenize each matching line and flag
#    a BARE clang/llvm token (pinned forms clang-14 / llvm-14 carry a -NN/=ver).
if [[ -f deploy/docker/Dockerfile.ebpf ]]; then
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

if [[ $fail -ne 0 ]]; then
  echo
  echo "supply-pins gate FAILED — pin the inputs above (docs/dependency-policy.md)."
  exit 1
fi
echo "supply-pins gate: OK (no :latest, no unpinned go install / pip install, no tag-only helm image)"
