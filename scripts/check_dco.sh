#!/usr/bin/env bash
# LICENSE-004 / GOV-002: require a Developer Certificate of Origin (DCO 1.1)
# sign-off on every commit in a PR — a `Signed-off-by: Name <email>` trailer
# (added by `git commit -s`). Dependency-free (git + grep), so there is no
# third-party action to pin.
#
# This gate applies GOING FORWARD only. The ~230 historical unsigned commits and
# the dev@netctl.local provenance are a retroactive chain-of-title item for
# counsel (Appendix B of docs/diligence/REMEDIATION-PLAN-v2.md) — not gated here.
set -euo pipefail

base="${BASE_SHA:-${1:-}}"
head="${HEAD_SHA:-${2:-HEAD}}"
if [ -z "$base" ]; then
  echo "check_dco: BASE_SHA (or arg 1) is required — the PR base commit SHA" >&2
  exit 2
fi

missing=0
checked=0
while IFS= read -r sha; do
  [ -z "$sha" ] && continue
  checked=$((checked + 1))
  body="$(git show -s --format=%B "$sha")"
  if ! printf '%s\n' "$body" | grep -qiE '^[[:space:]]*Signed-off-by:[[:space:]]+.+<.+@.+>'; then
    subj="$(git show -s --format=%s "$sha")"
    echo "DCO: commit ${sha:0:12} \"${subj}\" is missing a 'Signed-off-by:' trailer (use git commit -s)" >&2
    missing=$((missing + 1))
  fi
done < <(git rev-list --no-merges "${base}..${head}")

if [ "$missing" -gt 0 ]; then
  echo "check_dco: $missing of $checked commit(s) missing a DCO sign-off — see CONTRIBUTING.md (Developer Certificate of Origin)." >&2
  exit 1
fi
echo "check_dco: all $checked commit(s) in ${base}..${head} carry a DCO sign-off."
