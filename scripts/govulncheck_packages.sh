#!/usr/bin/env bash
# Resolve real Go packages with `go list`, then run govulncheck on that
# concrete package set. This avoids raw ./... filesystem walking tripping over
# ignored local OS/editor files in empty directories.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
go_cmd="${GO:-go}"
govulncheck_version="${GOVULNCHECK_VERSION:-v1.8.0}"

split_module_dirs() {
  local dirs="${GO_MODULE_DIRS:-. test}"
  # shellcheck disable=SC2206 # GO_MODULE_DIRS is intentionally Make-style words.
  module_dirs=($dirs)
}

list_packages_for_module() {
  local module_dir="$1"
  local abs_dir
  if [[ "$module_dir" = /* ]]; then
    abs_dir="$module_dir"
  else
    abs_dir="$repo_root/$module_dir"
  fi
  (cd "$abs_dir" && "$go_cmd" list -f '{{.ImportPath}}' ./...)
}

selftest() {
  local tmp packages
  tmp="$(mktemp -d)"
  trap "rm -rf '$tmp'" EXIT

  mkdir -p "$tmp/pkg/real" "$tmp/pkg/empty"
  printf '.DS_Store\n' > "$tmp/.gitignore"
  printf 'module example.com/govuln-selftest\n\ngo 1.26.9\n' > "$tmp/go.mod"
  printf 'package real\n\nfunc OK() bool { return true }\n' > "$tmp/pkg/real/real.go"
  : > "$tmp/pkg/empty/.DS_Store"

  packages="$(GOWORK=off list_packages_for_module "$tmp")"
  grep -Fxq 'example.com/govuln-selftest/pkg/real' <<<"$packages" || {
    echo "govulncheck package discovery self-test: real package was not listed" >&2
    exit 1
  }
  if grep -Eq 'empty|DS_Store' <<<"$packages"; then
    echo "govulncheck package discovery self-test: ignored empty OS-file directory leaked into package list" >&2
    exit 1
  fi
  echo "govulncheck package discovery self-test OK"
}

# --- SUP-21: module-level vulnerable-dependency gate --------------------------
#
# The call-level scan above only FAILS on vulnerabilities govulncheck proves are
# reachable; a known-vulnerable module that we ship but never call exits 0 there
# (it is printed as an informational "found but not called" note). That let
# golang.org/x/crypto@v0.55.0 (GO-2026-6354/6355) and github.com/cilium/ebpf@
# v0.21.0 (GO-2026-6238) ride along in every shipped binary. This gate closes
# that hole: it runs `govulncheck -scan module` against each SHIPPED release
# binary and fails when a finding's advisory has an available fix — i.e. there
# is a newer module version to upgrade to. Advisories with no fix anywhere (for
# example GO-2026-5932, the permanently-unmaintained golang.org/x/crypto/openpgp
# package) are reported and tolerated, because there is nothing to bump to.
#
# The shipped set is DERIVED from scripts/build-release-binaries.sh's BINARIES
# default so the two cannot drift: adding a release binary there automatically
# widens this gate.

shipped_release_binaries() {
  # Extract the BINARIES="${BINARIES:-...}" default list from the release build
  # script. Keeping this derived (not a second hand-maintained list) means a new
  # shipped binary is scanned here the moment it is added to the release build.
  local brb="$repo_root/scripts/build-release-binaries.sh"
  [ -f "$brb" ] || { echo "::error::SUP-21: $brb not found; cannot determine shipped binaries" >&2; exit 1; }
  sed -n 's/^BINARIES="${BINARIES:-\(.*\)}"$/\1/p' "$brb" | tr ' ' '\n' | grep .
}

shipped_main_dir() {
  # Map a shipped binary name to its `package main` directory. Every shipped
  # binary lives under cmd/<name> (or ee/cmd/<name> for commercial ones); an
  # unknown layout is treated as drift and fails the gate rather than being
  # silently skipped.
  local name="$1"
  if [ -d "$repo_root/cmd/$name" ]; then
    printf '%s\n' "$repo_root/cmd/$name"
  elif [ -d "$repo_root/ee/cmd/$name" ]; then
    printf '%s\n' "$repo_root/ee/cmd/$name"
  else
    echo "::error::SUP-21: shipped binary '$name' has no cmd/<name> or ee/cmd/<name> package — update scripts/govulncheck_packages.sh for the new layout" >&2
    exit 1
  fi
}

judge_module_report() {
  # Parse a concatenated-JSON govulncheck report (one or more `-format json`
  # runs catenated) and exit non-zero if any FINDING references an advisory that
  # has at least one fixed version. govulncheck's own exit code is useless here:
  # it returns non-zero whenever a module vuln is present, including the no-fix
  # advisories we must tolerate, so we judge from the JSON instead.
  local report="$1"
  GOVULN_REPORT="$report" python3 - <<'PY'
import json, os, sys
blob = open(os.environ["GOVULN_REPORT"], encoding="utf-8").read()
dec = json.JSONDecoder()
i, n, objs = 0, len(blob), []
while i < n:
    while i < n and blob[i] in " \t\r\n":
        i += 1
    if i >= n:
        break
    try:
        obj, end = dec.raw_decode(blob, i)
    except json.JSONDecodeError:
        break
    objs.append(obj)
    i = end

# An advisory has an available fix if ANY affected range carries a `fixed` event.
osv_has_fix = {}
for o in objs:
    rec = o.get("osv")
    if not rec:
        continue
    osv_has_fix[rec["id"]] = any(
        ev.get("fixed")
        for aff in rec.get("affected", [])
        for rng in aff.get("ranges", [])
        for ev in rng.get("events", [])
    )

fix_available, no_fix = {}, {}
for o in objs:
    f = o.get("finding")
    if not f:
        continue
    oid = f.get("osv")
    mod = next(
        (f"{t.get('module','?')}@{t.get('version','?')}"
         for t in f.get("trace", []) if t.get("module")),
        "?",
    )
    bucket = fix_available if osv_has_fix.get(oid, False) else no_fix
    bucket.setdefault(oid, set()).add(mod)

for oid, mods in sorted(no_fix.items()):
    print(f"SUP-21: tolerating {oid} — no fix available (present in {sorted(mods)})")

if fix_available:
    for oid, mods in sorted(fix_available.items()):
        print(f"::error::SUP-21: shipped binary carries fix-available vulnerability "
              f"{oid} in {sorted(mods)} — bump the module (see https://pkg.go.dev/vuln/{oid})")
    sys.exit(1)

print(f"SUP-21: module-level scan clean across shipped binaries "
      f"({len(no_fix)} no-fix advisory/ies tolerated)")
PY
}

module_level_gate() {
  local -a binaries
  while IFS= read -r b; do
    binaries+=("$b")
  done < <(shipped_release_binaries)
  [ "${#binaries[@]}" -gt 0 ] || { echo "::error::SUP-21: no shipped binaries parsed from build-release-binaries.sh" >&2; exit 1; }

  local report
  report="$(mktemp)"
  echo "govulncheck: module-level scan of ${#binaries[@]} shipped binaries (${binaries[*]})"
  local dir name
  for name in "${binaries[@]}"; do
    dir="$(shipped_main_dir "$name")"
    echo ">> module scan: $name ($dir)" >&2
    # govulncheck -scan module fetches nothing to compile, but still loads the
    # package to resolve the build list; the eBPF agent's default (non-ebpf)
    # build already links github.com/cilium/ebpf, so the vulnerable version is
    # visible without the ebpf build tag or generated objects.
    ( cd "$dir" && "$go_cmd" run "golang.org/x/vuln/cmd/govulncheck@$govulncheck_version" \
        -scan module -format json ) >>"$report" 2>/dev/null || true
  done
  judge_module_report "$report"
  rm -f "$report"
}

module_gate_selftest() {
  # Prove the JSON judge fails on a fix-available finding and tolerates a no-fix
  # one — the planted-defect check that keeps this gate honest if the real scan
  # ever stops emitting findings.
  local tmp
  tmp="$(mktemp)"
  # Case 1: a finding whose advisory has a fixed version -> must FAIL.
  cat > "$tmp" <<'JSON'
{"osv":{"id":"GO-TEST-FIX","affected":[{"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.2.3"}]}]}]}}
{"finding":{"osv":"GO-TEST-FIX","trace":[{"module":"example.com/vuln","version":"v1.0.0"}]}}
JSON
  if judge_module_report "$tmp" >/dev/null 2>&1; then
    echo "module-gate self-test: a fix-available finding did NOT fail the judge" >&2
    rm -f "$tmp"; exit 1
  fi
  # Case 2: a finding whose advisory has NO fix anywhere -> must be tolerated.
  cat > "$tmp" <<'JSON'
{"osv":{"id":"GO-TEST-NOFIX","affected":[{"ranges":[{"type":"SEMVER","events":[{"introduced":"0"}]}]}]}}
{"finding":{"osv":"GO-TEST-NOFIX","trace":[{"module":"example.com/unmaintained","version":"v1.0.0"}]}}
JSON
  if ! judge_module_report "$tmp" >/dev/null 2>&1; then
    echo "module-gate self-test: a no-fix advisory was wrongly treated as a failure" >&2
    rm -f "$tmp"; exit 1
  fi
  rm -f "$tmp"
  echo "govulncheck module-gate self-test OK"
}

if [[ "${SELFTEST:-}" == "1" ]]; then
  selftest
  module_gate_selftest
  exit 0
fi

declare -a module_dirs
split_module_dirs

packages_file="$(mktemp)"
trap 'rm -f "$packages_file"' EXIT

for module_dir in "${module_dirs[@]}"; do
  list_packages_for_module "$module_dir" >>"$packages_file"
done

declare -a packages
while IFS= read -r package; do
  packages+=("$package")
done < <(grep -v '^$' "$packages_file" | sort -u)
if [[ "${#packages[@]}" -eq 0 ]]; then
  echo "govulncheck package discovery found no Go packages" >&2
  exit 1
fi

echo "govulncheck: scanning ${#packages[@]} Go packages from ${module_dirs[*]}"
"$go_cmd" run "golang.org/x/vuln/cmd/govulncheck@$govulncheck_version" "${packages[@]}"

# SUP-21: close the not-reachable-but-shipped hole after the call-level scan.
module_level_gate
