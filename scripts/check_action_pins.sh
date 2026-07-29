#!/usr/bin/env bash
# check_action_pins.sh — supply-chain gate for GitHub Actions (U-007).
#
# Every `uses:` in .github/workflows must reference a full 40-hex commit SHA
# (`owner/repo@<sha> # <tag>`), never a mutable tag or branch. Local composite
# actions (`uses: ./…`) are exempt; docker:// refs must pin a sha256 digest.
# Pins are bumped manually — re-pin to the new commit SHA and update the
# trailing "# <tag>" comment; this gate rejects any non-SHA ref regardless.
set -euo pipefail

cd "$(dirname "$0")/.."

if ! go run ./cmd/probectl-workflow-policy actions .github/workflows; then
  echo "" >&2
  echo "check_action_pins: floating action refs found. Pin with:" >&2
  echo "  git ls-remote https://github.com/<owner>/<repo> 'refs/tags/<tag>^{}'" >&2
  exit 1
fi
echo "check_action_pins: every workflow action is SHA-pinned."
