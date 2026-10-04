#!/usr/bin/env bash
# check_repo_hygiene.sh — repo-hygiene ratchet (AIRCA-005 / CODE-004 / RED-005).
#
# The audit found editor-backup and sandbox-scratch litter sitting in the
# working tree (e.g. internal/config/config.go.1148314986887221806) and warned
# that such files must never get committed, and that .git/info/exclude must not
# be used to MASK tracked junk from `git status`. This gate fails if any of the
# following are TRACKED (committed) in the repo:
#   - editor/scratch backups:  *.go.<digits>, *.orig, *.bak, *.rej, *.trash*
#   - a non-empty .git/info/exclude (a local mask that can hide stray files)
#
# It is a fast, dependency-free string scan over `git ls-files`. SELFTEST mode
# synthesizes a fake match list and asserts the detector trips (anti-vacuous).
set -euo pipefail
cd "$(dirname "$0")/.."

# Pattern matched against tracked paths. Kept in one place so the self-test
# can reuse it.
litter_re='\.go\.[0-9]{6,}$|\.orig$|\.bak$|\.rej$|(^|/)[^/]*\.trash'

scan() { # scan <newline-separated-file-list>
  grep -E "$litter_re" <<<"$1" || true
}

# TQ-11: tracked executables/objects are build artifacts that must never live in
# the source tree (a 23 MB Mach-O once rode in at the root, invisible to this
# gate). detect_executables reads a NUL-separated path list on stdin and prints
# any file whose content MIME type is an executable or object.
executable_mime_re='application/x-mach-binary|application/x-executable|application/x-pie-executable|application/x-sharedlib|application/x-object|application/x-dosexec|application/x-elf'
# Fail CLOSED if the detector's dependency is missing — a silent no-op would
# leave committed binaries undetected (TQ-11). `file` is present on the CI
# runners and in the toolchain images.
if ! command -v file >/dev/null 2>&1; then
  echo "::error::check_repo_hygiene needs the 'file' utility to detect tracked binaries (TQ-11); install it on this runner" >&2
  exit 1
fi
detect_executables() {
  # -N (no-pad): emit "path: mime" with a single space regardless of how many
  # files are inspected, so the match below is reliable for 1 or 1000 files.
  xargs -0 file --mime-type -N \
    | grep -E ": (${executable_mime_re})\$" \
    | sed 's/: [^:]*$//' || true
}

if [ "${1:-}" = "SELFTEST" ]; then
  fake=$'internal/config/config.go.1148314986887221806\nee/provider/service.go.431374146706970878\nweb/src/app.tsx\nfoo.orig\n.git/info/exclude.trash'
  hits="$(scan "$fake")"
  expected=3 # the two .go.<digits>, foo.orig (the .trash one is .git/* path, excluded by ls-files in real runs but caught here too -> 4? guard explicitly)
  # We assert the detector finds the known-bad lines; exact count is the
  # number of synthetic litter lines (4), proving it is not a no-op.
  n="$(printf '%s\n' "$hits" | grep -c . || true)"
  if [ "$n" -lt 3 ]; then
    echo "SELFTEST FAILED: hygiene detector did not trip on synthetic litter (found $n)" >&2
    exit 1
  fi
  # TQ-11: the executable detector must trip on a planted binary. Copy a real
  # system executable (ELF on Linux/CI, Mach-O locally) and assert it is caught.
  tmpbin="$(mktemp)"
  cp "$(command -v true)" "$tmpbin" 2>/dev/null || cp /bin/sh "$tmpbin"
  caught="$(printf '%s\0' "$tmpbin" | detect_executables)"
  rm -f "$tmpbin"
  if [ -z "$caught" ]; then
    echo "SELFTEST FAILED: executable detector did not trip on a planted binary" >&2
    exit 1
  fi
  echo "check_repo_hygiene SELFTEST OK ($n synthetic litter lines detected; planted binary caught)"
  exit 0
fi

fail=0

tracked="$(git ls-files)"
litter="$(scan "$tracked")"
if [ -n "$litter" ]; then
  echo "::error::committed editor-backup / scratch litter (AIRCA-005/CODE-004 — remove and add to .gitignore):" >&2
  printf '  %s\n' $litter >&2
  fail=1
fi

# TQ-11: no tracked executables/object files anywhere in the tree.
binaries="$(git ls-files -z | detect_executables)"
if [ -n "$binaries" ]; then
  echo "::error::tracked executable/object binaries — build artifacts belong in the build output, not the source tree (TQ-11); remove with 'git rm --cached' and .gitignore them:" >&2
  printf '  %s\n' $binaries >&2
  fail=1
fi

# A populated .git/info/exclude can locally mask stray files from `git status`,
# defeating the hygiene check (RED-005). The repo ships none; flag a non-empty one.
if [ -s .git/info/exclude ]; then
  if grep -qvE '^\s*(#|$)' .git/info/exclude; then
    echo "::error::.git/info/exclude has active rules — it can mask stray files from git status (RED-005). Use .gitignore (tracked) instead." >&2
    fail=1
  fi
fi

if [ "$fail" -ne 0 ]; then
  exit 1
fi
echo "check_repo_hygiene: clean (no committed backup/scratch litter; no masking exclude)"
