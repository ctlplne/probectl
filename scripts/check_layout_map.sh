#!/usr/bin/env bash
#
# Layout-map guard (Foundation-Loop T-88d13cd2): docs/repository-layout.md is
# the canonical package map. It used to document roughly thirty internal
# packages while the tree held eighty-two — the first page a contributor reads
# described a different codebase.
#
# RULE, both directions: every top-level package under internal/ and ee/
# must appear in the map, and every mapped name must exist as a package
# directory. Entries are `name (one-line purpose)` separated by `·`.
#
# Self-test: SELFTEST builds a fixture map from the real tree, then plants
# (a) a real package deleted from the map and (b) a ghost entry naming a
# package that does not exist, asserting the guard catches both, and that
# the unmodified real map passes.
set -euo pipefail
cd "$(dirname "$0")/.."

# extract_section <file> <section>: entry names from a fenced map section
# (from the line starting `<section>/` up to the next unindented section).
extract_section() {
  local file="$1" section="$2"
  # Portability: BSD awk rejects '/' inside a bracket class in a regex
  # literal, and BSD tr is byte-oriented over the multibyte '·' — so the
  # section-exit class avoids '/', and the separator split uses awk gsub.
  awk -v sec="$section" '
    $0 ~ "^" sec "/" { insec = 1 }
    insec && $0 !~ "^" sec "/" && $0 ~ /^[a-z.][a-zA-Z0-9_.-]*\// { insec = 0 }
    insec { print }
  ' "$file" \
    | sed -E "s|^$section/||" \
    | awk '{ gsub(/·/, "\n") } 1' \
    | sed -E 's/\([^)]*\)//g; s/^[[:space:]]+//; s/[[:space:]]+$//' \
    | awk 'NF { print $1 }' \
    | LC_ALL=C sort -u
}

list_dirs() { # list_dirs <root-dir> — portable: BSD find has no -printf
  find "$1" -mindepth 1 -maxdepth 1 -type d | sed 's|.*/||' | LC_ALL=C sort -u
}

check_map() { # check_map <layout-map> <tree-root>
  local file="$1" root="$2" fail=0 section
  for section in internal ee; do
    local mapped actual missing ghost
    mapped="$(extract_section "$file" "$section")"
    actual="$(list_dirs "$root/$section")"
    missing="$(comm -13 <(echo "$mapped") <(echo "$actual"))"
    ghost="$(comm -23 <(echo "$mapped") <(echo "$actual"))"
    if [ -n "$missing" ]; then
      echo "layout-map: $section/ package(s) missing from docs/repository-layout.md: $(echo "$missing" | tr '\n' ' ')" >&2
      fail=1
    fi
    if [ -n "$ghost" ]; then
      echo "layout-map: docs/repository-layout.md names nonexistent $section/ package(s): $(echo "$ghost" | tr '\n' ' ')" >&2
      fail=1
    fi
  done
  return $fail
}

selftest() {
  local tmp
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' RETURN

  # The real map must pass against the real tree first (anti-vacuous base).
  if ! check_map docs/repository-layout.md . >/dev/null 2>&1; then
    echo "layout-map SELFTEST FAILED: the real map does not match the real tree" >&2
    check_map docs/repository-layout.md . || true
    return 1
  fi

  # (a) plant a deletion: drop one real package name from a fixture map.
  # (space-anchored match, not \b — BSD sed has no \b)
  local victim
  victim="$(list_dirs internal | head -1)"
  sed "s/ ${victim} (/ ${victim}-DELETED (/" docs/repository-layout.md > "$tmp/missing.md"
  if check_map "$tmp/missing.md" . >/dev/null 2>&1; then
    echo "layout-map SELFTEST FAILED: deleting '$victim' from the map was not caught" >&2
    return 1
  fi

  # (b) plant a ghost: an entry naming a package that does not exist.
  sed "s|^internal/   |internal/   ghostpkg (does not exist) · |" docs/repository-layout.md > "$tmp/ghost.md"
  if check_map "$tmp/ghost.md" . >/dev/null 2>&1; then
    echo "layout-map SELFTEST FAILED: ghost entry was not caught" >&2
    return 1
  fi

  echo "layout-map selftest OK (planted deletion and planted ghost both caught; real map passes)"
}

if [ "${1:-}" = "SELFTEST" ] || [ "${SELFTEST:-0}" = "1" ]; then
  selftest
  exit 0
fi

if check_map docs/repository-layout.md .; then
  echo "layout-map OK (docs/repository-layout.md matches internal/ and ee/ exactly, both directions)"
else
  echo "layout-map: FAIL — docs/repository-layout.md and the tree disagree; update the map (with a one-line purpose) or remove the stale entry." >&2
  exit 1
fi
