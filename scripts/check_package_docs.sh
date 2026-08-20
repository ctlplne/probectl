#!/usr/bin/env bash
#
# Package-doc guard (Foundation-Loop K-f492c9b1): every package under
# internal/ and ee/ must state its purpose (and the invariant it owns) in a
# godoc package comment — `// Package <name> ...` for libraries, `// Command
# <name> ...` for main packages. The best packages in this tree (tenantlife,
# chmigrate, fairness) already do this; the guard makes it the floor, so a
# second engineer reading unfamiliar code always finds the owner's intent.
#
# RULE, not a list: any directory (recursive) containing non-test .go files
# is a package and must carry the comment. Generated trees (*/gen/*) and
# testdata are exempt by class.
#
# Self-test: SELFTEST builds a scratch tree containing a documented and an
# undocumented package, asserts the guard names exactly the undocumented
# one, then asserts the documented-only tree passes (and the real tree must
# already pass before planting means anything).
set -euo pipefail
cd "$(dirname "$0")/.."

# check_tree <root>: report packages lacking a package/command doc comment.
check_tree() {
  local root="$1" fail=0 dir
  while IFS= read -r dir; do
    case "$dir" in
      */gen|*/gen/*|*/testdata|*/testdata/*) continue ;;
    esac
    # a package = a dir with at least one non-test .go file
    if ! ls "$dir"/*.go >/dev/null 2>&1; then continue; fi
    local has_src=0 f
    for f in "$dir"/*.go; do
      case "$f" in *_test.go) continue ;; esac
      has_src=1; break
    done
    [ "$has_src" = 1 ] || continue
    if ! grep -l -E '^// (Package|Command) [A-Za-z0-9_]' "$dir"/*.go >/dev/null 2>&1; then
      echo "package-docs: $dir has no package doc comment stating its purpose/invariant" >&2
      fail=1
    fi
  done < <(find "$root/internal" "$root/ee" -type d 2>/dev/null | LC_ALL=C sort)
  return $fail
}

selftest() {
  local tmp
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' RETURN

  # the real tree must already pass, or planting proves nothing
  if ! check_tree . >/dev/null 2>&1; then
    echo "package-docs SELFTEST FAILED: the real tree does not pass" >&2
    check_tree . || true
    return 1
  fi

  mkdir -p "$tmp/internal/goodpkg" "$tmp/internal/badpkg" "$tmp/ee"
  cat > "$tmp/internal/goodpkg/doc.go" <<'EOF'
// Package goodpkg is a selftest fixture; its invariant is being documented.
package goodpkg
EOF
  cat > "$tmp/internal/badpkg/thing.go" <<'EOF'
package badpkg
EOF
  local out
  if out="$(check_tree "$tmp" 2>&1)"; then
    echo "package-docs SELFTEST FAILED: planted undocumented package passed" >&2
    return 1
  fi
  case "$out" in
    *badpkg*) : ;;
    *) echo "package-docs SELFTEST FAILED: wrong package reported: $out" >&2; return 1 ;;
  esac
  case "$out" in
    *goodpkg*) echo "package-docs SELFTEST FAILED: documented package was flagged" >&2; return 1 ;;
  esac
  rm -rf "$tmp/internal/badpkg"
  if ! check_tree "$tmp" >/dev/null 2>&1; then
    echo "package-docs SELFTEST FAILED: clean fixture tree did not pass" >&2
    return 1
  fi
  echo "package-docs selftest OK (planted undocumented package caught; documented tree passes)"
}

if [ "${1:-}" = "SELFTEST" ] || [ "${SELFTEST:-0}" = "1" ]; then
  selftest
  exit 0
fi

if check_tree .; then
  echo "package-docs OK (every internal/ and ee/ package states its purpose)"
else
  echo "package-docs: FAIL — add a '// Package <name> ...' (or '// Command <name> ...') doc comment stating the package's purpose and the invariant it owns." >&2
  exit 1
fi
