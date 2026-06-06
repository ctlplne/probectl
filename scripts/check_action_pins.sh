#!/usr/bin/env bash
# check_action_pins.sh — supply-chain gate for GitHub Actions (U-007).
#
# Every `uses:` in .github/workflows must reference a full 40-hex commit SHA
# (`owner/repo@<sha> # <tag>`), never a mutable tag or branch. Local composite
# actions (`uses: ./…`) are exempt; docker:// refs must pin a sha256 digest.
# Dependabot (.github/dependabot.yml, github-actions ecosystem) keeps the pins
# fresh and rewrites the trailing tag comment.
set -euo pipefail

cd "$(dirname "$0")/.."

fail=0
while IFS= read -r line; do
  file=${line%%:*}
  rest=${line#*:}
  lineno=${rest%%:*}
  ref=$(echo "${rest#*:}" | sed -E 's/^[-[:space:]]*uses:[[:space:]]*//; s/["'"'"']//g; s/[[:space:]]+#.*$//; s/[[:space:]]*$//')

  # Local composite actions are part of this repo — nothing to pin.
  [[ $ref == ./* ]] && continue

  if [[ $ref == docker://* ]]; then
    if [[ $ref != *@sha256:* ]]; then
      echo "UNPINNED (docker, want @sha256:<digest>): $file:$lineno: $ref" >&2
      fail=1
    fi
    continue
  fi

  if ! [[ $ref =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+@[0-9a-f]{40}$ ]]; then
    echo "UNPINNED (want owner/repo@<40-hex-sha> # <tag>): $file:$lineno: $ref" >&2
    fail=1
  fi
done < <(grep -rnE '^[[:space:]-]*uses:' .github/workflows --include='*.yml' --include='*.yaml')

if [[ $fail -ne 0 ]]; then
  echo "" >&2
  echo "check_action_pins: floating action refs found. Pin with:" >&2
  echo "  git ls-remote https://github.com/<owner>/<repo> 'refs/tags/<tag>^{}'" >&2
  exit 1
fi
echo "check_action_pins: every workflow action is SHA-pinned."
