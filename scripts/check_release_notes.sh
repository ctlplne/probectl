#!/usr/bin/env bash
# SPDX-License-Identifier: BUSL-1.1
#
# Regression fixture for exhaustive release-note accounting. It builds a tiny
# local git history so no network or repository-history assumption is involved.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
generator="${repo_root}/scripts/release_notes.sh"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

git -C "$tmp" init -q
git -C "$tmp" config user.name "probectl release fixture"
git -C "$tmp" config user.email "release-fixture@probectl.invalid"

commit_subject() {
  local subject="$1"
  git -C "$tmp" commit --allow-empty -q -m "$subject"
}

commit_subject "chore: fixture baseline"
git -C "$tmp" tag v1.0.0
commit_subject "feat(core): add fixture feature"
commit_subject "Delete docs/audit/ebpf-capture-redaction.md"
commit_subject "fix: preserve fixture output"

output="$tmp/notes.md"
(
  cd "$tmp"
  bash "$generator" v1.0.0 HEAD > "$output"
)

expected="$(git -C "$tmp" rev-list --no-merges --count v1.0.0..HEAD)"
actual="$(grep -c '^- ' "$output")"
[ "$actual" -eq "$expected" ] || {
  echo "release notes gate: output accounts for ${actual}/${expected} commits" >&2
  cat "$output" >&2
  exit 1
}

for subject in \
  "feat(core): add fixture feature" \
  "Delete docs/audit/ebpf-capture-redaction.md" \
  "fix: preserve fixture output"; do
  count="$(grep -Fxc -- "- ${subject}" "$output" || true)"
  [ "$count" -eq 1 ] || {
    printf 'release notes gate: %q appears %s times; want exactly 1\n' "$subject" "$count" >&2
    exit 1
  }
done

awk '
  /^### / { section = $0 }
  /feat\(core\): add fixture feature/ && section == "### Features" { feature = 1 }
  /Delete docs\/audit\/ebpf-capture-redaction.md/ && section == "### Other changes" { other = 1 }
  END { exit !(feature && other) }
' "$output" || {
  echo "release notes gate: conventional/unconventional section assignment is wrong" >&2
  cat "$output" >&2
  exit 1
}

echo "release notes gate: OK (${actual} fixture commits, each emitted exactly once)"
