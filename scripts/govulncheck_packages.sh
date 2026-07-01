#!/usr/bin/env bash
# Resolve real Go packages with `go list`, then run govulncheck on that
# concrete package set. This avoids raw ./... filesystem walking tripping over
# ignored local OS/editor files in empty directories.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
go_cmd="${GO:-go}"
govulncheck_version="${GOVULNCHECK_VERSION:-v1.1.4}"

split_module_dirs() {
  local dirs="${GO_MODULE_DIRS:-. test}"
  # shellcheck disable=SC2206 # GO_MODULE_DIRS is intentionally Make-style words.
  module_dirs=($dirs)
}

list_packages_for_module() {
  local module_dir="$1"
  local abs_dir
  if [[ "$module_dir" = /* ]]; then
    abs_dir="$module_dir"
  else
    abs_dir="$repo_root/$module_dir"
  fi
  (cd "$abs_dir" && "$go_cmd" list -f '{{.ImportPath}}' ./...)
}

selftest() {
  local tmp packages
  tmp="$(mktemp -d)"
  trap "rm -rf '$tmp'" EXIT

  mkdir -p "$tmp/pkg/real" "$tmp/pkg/empty"
  printf '.DS_Store\n' > "$tmp/.gitignore"
  printf 'module example.com/govuln-selftest\n\ngo 1.26.4\n' > "$tmp/go.mod"
  printf 'package real\n\nfunc OK() bool { return true }\n' > "$tmp/pkg/real/real.go"
  : > "$tmp/pkg/empty/.DS_Store"

  packages="$(GOWORK=off list_packages_for_module "$tmp")"
  grep -Fxq 'example.com/govuln-selftest/pkg/real' <<<"$packages" || {
    echo "govulncheck package discovery self-test: real package was not listed" >&2
    exit 1
  }
  if grep -Eq 'empty|DS_Store' <<<"$packages"; then
    echo "govulncheck package discovery self-test: ignored empty OS-file directory leaked into package list" >&2
    exit 1
  fi
  echo "govulncheck package discovery self-test OK"
}

if [[ "${SELFTEST:-}" == "1" ]]; then
  selftest
  exit 0
fi

declare -a module_dirs
split_module_dirs

packages_file="$(mktemp)"
trap 'rm -f "$packages_file"' EXIT

for module_dir in "${module_dirs[@]}"; do
  list_packages_for_module "$module_dir" >>"$packages_file"
done

declare -a packages
while IFS= read -r package; do
  packages+=("$package")
done < <(grep -v '^$' "$packages_file" | sort -u)
if [[ "${#packages[@]}" -eq 0 ]]; then
  echo "govulncheck package discovery found no Go packages" >&2
  exit 1
fi

echo "govulncheck: scanning ${#packages[@]} Go packages from ${module_dirs[*]}"
"$go_cmd" run "golang.org/x/vuln/cmd/govulncheck@$govulncheck_version" "${packages[@]}"
