#!/usr/bin/env bash
#
# Contract-links guard (Foundation-Loop T-e4bb9062): AGENTS.md and CLAUDE.md
# are the first files any agent or human reads. A reference in them that
# points at nothing misdirects every reader — the retired harness/ program
# proved it by leaving the contract's very first instruction dangling.
#
# RULE, not a denylist: EVERY markdown link target and EVERY backtick-quoted
# token that looks like a relative path (contains '/', or ends in a doc
# extension) in the contract files must exist on disk. Tokens containing
# glob/placeholder characters (* ? < > | $ { } ( ) space) are non-literal
# and ignored. A new dangling reference fails without this script changing.
#
# Out-of-repo references (the structural backlog files) are workspace scaffolding
# deliberately not shipped with the product: they are enforced when that
# workspace layout is present (`../backlog.json` exists) and skipped with a
# printed notice in a bare clone (CI), where parent artifacts are absent by design.
#
# Self-test: SELFTEST plants (a) a dangling backtick path and (b) a dangling
# markdown link in a scratch file and asserts the guard reports BOTH, then
# asserts a clean scratch file passes (the check_editions_imports.sh
# crypto-guard pattern: the gate proves it can fail before it is trusted).
set -euo pipefail

cd "$(dirname "$0")/.."

contract_files="AGENTS.md CLAUDE.md"

# extract_refs <file>: candidate references, one per line.
extract_refs() {
  local f="$1"
  # markdown link targets: [text](target)
  grep -oE '\]\([^)]+\)' "$f" 2>/dev/null | sed -E 's/^\]\(//; s/\)$//' || true
  # inline backtick-quoted tokens
  grep -oE '`[^`]+`' "$f" 2>/dev/null | sed -E 's/^`//; s/`$//' || true
}

# looks_like_path <token>: 0 iff the token is a literal relative path claim.
looks_like_path() {
  local t="$1"
  case "$t" in
    http://*|https://*|mailto:*|'#'*) return 1 ;;
  esac
  # Absolute paths are URL routes or host-filesystem claims, not repo files.
  case "$t" in
    /*) return 1 ;;
  esac
  # Module/VCS identifiers are external-dependency claims, not file claims
  # (capability claims are the docs-claims gate's jurisdiction, not this one's).
  case "$t" in
    github.com/*|gitlab.com/*|golang.org/*|google.golang.org/*|k8s.io/*|sigs.k8s.io/*) return 1 ;;
  esac
  case "$t" in
    *'*'*|*'?'*|*'<'*|*'>'*|*'|'*|*'$'*|*'{'*|*'}'*|*'('*|*')'*|*' '*|*$'\t'*|-*) return 1 ;;
  esac
  case "$t" in
    */*) return 0 ;;
    *.md|*.sh|*.json|*.html|*.yml|*.yaml|*.toml|*.sql) return 0 ;;
    *) return 1 ;;
  esac
}

# check_file <file>: report every dangling reference; return 1 if any.
check_file() {
  local f="$1" fail=0 workspace_present=0 ref target
  [ -f "$f" ] || { echo "contract-links: contract file missing: $f" >&2; return 1; }
  [ -f "../backlog.json" ] && workspace_present=1
  while IFS= read -r ref; do
    [ -n "$ref" ] || continue
    looks_like_path "$ref" || continue
    target="${ref%%#*}"   # strip anchors
    target="${target%/}"  # a trailing slash means directory; existence check is the same
    [ -n "$target" ] || continue
    case "$target" in
      ../*)
        if [ "$workspace_present" = 1 ]; then
          [ -e "$target" ] || { echo "$f: dangling out-of-repo reference: $ref" >&2; fail=1; }
        else
          echo "note: $f: out-of-repo reference '$ref' not checked (bare clone; workspace siblings absent by design)"
        fi
        ;;
      *)
        [ -e "$target" ] || { echo "$f: dangling reference: $ref" >&2; fail=1; }
        ;;
    esac
  done < <(extract_refs "$f" | LC_ALL=C sort -u)
  return "$fail"
}

selftest() {
  local tmp rc
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' RETURN

  # (a)+(b): plant a dangling backtick path AND a dangling markdown link.
  cat >"$tmp/planted.md" <<'PLANT'
Read `docs/this-file-does-not-exist.selftest.md` first.
Then see [the seed](docs/also-missing.selftest.md) for details.
A healthy reference: `docs/` and `Makefile` stay resolvable.
PLANT
  rc=0
  out="$(check_file "$tmp/planted.md" 2>&1)" || rc=$?
  if [ "$rc" -eq 0 ]; then
    echo "contract-links SELFTEST FAILED: planted dangling references were not caught" >&2
    return 1
  fi
  case "$out" in
    *this-file-does-not-exist.selftest.md*) : ;;
    *) echo "contract-links SELFTEST FAILED: backtick shape not reported: $out" >&2; return 1 ;;
  esac
  case "$out" in
    *also-missing.selftest.md*) : ;;
    *) echo "contract-links SELFTEST FAILED: markdown-link shape not reported: $out" >&2; return 1 ;;
  esac

  # clean file passes
  cat >"$tmp/clean.md" <<'PLANT'
Read `Makefile` and `docs/` and follow [contributing](CONTRIBUTING.md).
Non-literal tokens are ignored: `PROBECTL_*`, `probectl.<type>.results|events`, `-tags probectl_core`.
PLANT
  if ! check_file "$tmp/clean.md" >/dev/null 2>&1; then
    echo "contract-links SELFTEST FAILED: clean file did not pass" >&2
    return 1
  fi
  echo "contract-links selftest OK (planted backtick + markdown-link shapes both caught; clean file passes)"
}

if [ "${1:-}" = "SELFTEST" ] || [ "${SELFTEST:-0}" = "1" ]; then
  selftest
  exit 0
fi

overall=0
for f in $contract_files; do
  check_file "$f" || overall=1
done
if [ "$overall" -ne 0 ]; then
  echo "contract-links: FAIL — a contract file references a path that does not exist." >&2
  echo "Fix the reference or restore the target; do not leave the contract misdirecting readers." >&2
  exit 1
fi
echo "contract-links OK ($contract_files: every path-shaped reference resolves)"
