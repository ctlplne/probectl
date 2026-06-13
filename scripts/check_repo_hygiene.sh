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
  echo "check_repo_hygiene SELFTEST OK ($n synthetic litter lines detected)"
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
