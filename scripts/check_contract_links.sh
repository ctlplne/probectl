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
# Out-of-repo references are workspace scaffolding deliberately not shipped with
# the product, so they are enforced only when that workspace is actually present
# and skipped with a printed notice in a bare clone (CI), where parent artifacts
# are absent by design.
#
# DPR-173: the presence probe used to be `[ -f ../backlog.json ]` — one of the
# very files this guard exists to check. When that file was retired the guard
# silently switched ITSELF off and stopped reporting the dangling reference to
# it, along with every other out-of-repo reference, for six weeks. A gate whose
# enable-condition is one of its own subjects cannot fail in the case it was
# written for. The probe is now independent of any single reference: the
# workspace counts as present when ANY out-of-repo reference resolves, or when
# the repository is not alone in its parent directory (a bare CI checkout is).
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
# workspace_present <file...>: 0 iff the surrounding workspace is present, so
# out-of-repo references must resolve. Deliberately NOT keyed on any one path.
workspace_present() {
  local f ref target
  for f in "$@"; do
    [ -f "$f" ] || continue
    while IFS= read -r ref; do
      [ -n "$ref" ] || continue
      looks_like_path "$ref" || continue
      case "$ref" in ../*) : ;; *) continue ;; esac
      target="${ref%%#*}"; target="${target%/}"
      [ -e "$target" ] && return 0
    done < <(extract_refs "$f" | LC_ALL=C sort -u)
  done
  # No out-of-repo reference resolved. A bare CI checkout is alone in its parent;
  # a real workspace has siblings, and then a reference resolving to nothing is a
  # dangling reference rather than an absent-by-design one.
  [ "$(ls -A .. 2>/dev/null | wc -l | tr -d ' ')" -gt 1 ] && return 0
  return 1
}

check_file() {
  local f="$1" fail=0 workspace_present=${2:-0} ref target
  [ -f "$f" ] || { echo "contract-links: contract file missing: $f" >&2; return 1; }
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
  if ! check_file "$tmp/clean.md" 1 >/dev/null 2>&1; then
    echo "contract-links SELFTEST FAILED: clean file did not pass" >&2
    return 1
  fi

  # (c) DPR-173: the out-of-repo probe must not be disable-able by the very
  # reference it is checking. Plant a workspace with ONE resolving sibling and
  # ONE dangling sibling, and assert the dangling one is reported.
  mkdir -p "$tmp/ws/repo" "$tmp/ws/present-sibling"
  cat >"$tmp/ws/repo/planted.md" <<'PLANT'
Live programme: `../present-sibling/` · retired state: `../gone.json`
PLANT
  rc=0
  out="$( cd "$tmp/ws/repo" && { p=0; workspace_present planted.md && p=1; check_file planted.md "$p"; } 2>&1 )" || rc=$?
  if [ "$rc" -eq 0 ] || [ "${out#*gone.json}" = "$out" ]; then
    echo "contract-links SELFTEST FAILED: a dangling sibling was not reported in a present workspace: $out" >&2
    return 1
  fi

  # (d) and the bare-clone case still skips: nothing resolves AND the repo is
  # alone in its parent, which is what a CI checkout looks like.
  mkdir -p "$tmp/bare/repo"
  cat >"$tmp/bare/repo/planted.md" <<'PLANT'
Retired state: `../gone.json`
PLANT
  if ( cd "$tmp/bare/repo" && workspace_present planted.md ); then
    echo "contract-links SELFTEST FAILED: a bare clone was treated as a present workspace" >&2
    return 1
  fi

  echo "contract-links selftest OK (planted backtick + markdown-link shapes both caught; clean file passes; a dangling sibling fails in a present workspace and is skipped in a bare clone)"
}

if [ "${1:-}" = "SELFTEST" ] || [ "${SELFTEST:-0}" = "1" ]; then
  selftest
  exit 0
fi

overall=0
present=0
if workspace_present $contract_files; then present=1; fi
for f in $contract_files; do
  check_file "$f" "$present" || overall=1
done
if [ "$overall" -ne 0 ]; then
  echo "contract-links: FAIL — a contract file references a path that does not exist." >&2
  echo "Fix the reference or restore the target; do not leave the contract misdirecting readers." >&2
  exit 1
fi
echo "contract-links OK ($contract_files: every path-shaped reference resolves)"
