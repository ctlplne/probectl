#!/usr/bin/env bash
#
# verify-branch-protection (Sprint 1: TEST-002, SUPPLY-007): the committed
# ruleset (.github/rulesets/main.json) is the source of truth; this script
# fails CI if the LIVE rules on the default branch have drifted from it.
#
# It reads GET /repos/{repo}/rules/branches/{branch} — the *effective* rules
# endpoint, readable with the default GITHUB_TOKEN (contents: read), so no
# admin PAT is needed. If the repo has no active ruleset yet, this fails with
# import instructions: that is the point — protection must exist, not just be
# described.
set -euo pipefail

REPO="${GITHUB_REPOSITORY:?GITHUB_REPOSITORY not set}"
BRANCH="${PROTECTED_BRANCH:-main}"
TOKEN="${GITHUB_TOKEN:?GITHUB_TOKEN not set}"
COMMITTED="${RULESET_FILE:-.github/rulesets/main.json}"

live="$(curl -sS --fail-with-body \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Accept: application/vnd.github+json" \
  -H "X-GitHub-Api-Version: 2022-11-28" \
  "https://api.github.com/repos/${REPO}/rules/branches/${BRANCH}")" || {
  echo "branch-protection: FAIL — could not read live rules for ${REPO}@${BRANCH}" >&2
  exit 1
}

COMMITTED="$COMMITTED" LIVE_JSON="$live" python3 - <<'PY'
import json, os, sys

committed = json.load(open(os.environ["COMMITTED"]))
live = json.loads(os.environ["LIVE_JSON"])  # list of effective rule objects

def fail(msg):
    print(f"branch-protection: DRIFT — {msg}", file=sys.stderr)
    print("Fix: Settings → Rules → Rulesets → New/Import ruleset → upload "
          ".github/rulesets/main.json (or edit the live ruleset to match), "
          "then re-run.", file=sys.stderr)
    sys.exit(1)

if not live:
    fail("no active rules on the default branch — the committed ruleset is not imported/enforced")

live_by_type = {}
for r in live:
    live_by_type.setdefault(r.get("type"), []).append(r.get("parameters") or {})

# 1. Every committed rule type must be live.
for rule in committed["rules"]:
    t = rule["type"]
    if t not in live_by_type:
        fail(f"committed rule type {t!r} is not active on {os.environ.get('PROTECTED_BRANCH','main')}")

# 2. PR review: dismiss-stale must hold; approval count must be >= committed.
want_pr = next(r["parameters"] for r in committed["rules"] if r["type"] == "pull_request")
got_pr = live_by_type["pull_request"][0]
if not got_pr.get("dismiss_stale_reviews_on_push", False):
    fail("pull_request rule does not dismiss stale approvals on push")
if got_pr.get("required_approving_review_count", 0) < want_pr["required_approving_review_count"]:
    fail("live required_approving_review_count is below the committed value")

# 3. Required status checks: every committed context must be required live.
want_checks = {c["context"] for r in committed["rules"] if r["type"] == "required_status_checks"
               for c in r["parameters"]["required_status_checks"]}
got_checks = set()
for params in live_by_type.get("required_status_checks", []):
    for c in params.get("required_status_checks", []):
        got_checks.add(c.get("context"))
missing = sorted(want_checks - got_checks)
if missing:
    fail(f"required checks missing from live protection: {', '.join(missing)}")

extra = sorted(got_checks - want_checks)
if extra:
    # Stricter-than-committed is allowed but surfaced, so the file gets updated.
    print(f"branch-protection: NOTE — live requires extra checks not in the committed file: {', '.join(extra)}")

print(f"branch-protection: OK — live rules on the default branch match {os.environ['COMMITTED']} "
      f"({len(want_checks)} required checks, PR review with stale-dismissal).")
PY
