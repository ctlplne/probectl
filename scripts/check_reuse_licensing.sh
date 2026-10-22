#!/usr/bin/env bash
# SPDX-License-Identifier: BUSL-1.1
#
# Use of this source code is governed by the Business Source License 1.1
# in the LICENSE file at the root of this repository; on its Change Date
# each version converts to the Mozilla Public License 2.0.
#
# REUSE licensing gate (G3, decision D-58): machine-readable, per-file licensing
# that can never drift from the legal texts.
#
# GitHub's license detector cannot name BUSL-1.1, so the repository header says
# NOASSERTION; that is expected. What a scanner CAN rely on is the REUSE layout
# (https://reuse.software/spec-3.3/): LICENSES/<SPDX-id>.txt plus REUSE.toml.
# This gate keeps that layout honest:
#
#   1. COPIES. LICENSES/BUSL-1.1.txt and LICENSES/MPL-2.0.txt are byte-identical
#      to their sections of LICENSE (the BSL with its parameters; the MPL with
#      both Exhibits), and LICENSES/LicenseRef-Probectl-Commercial.txt is
#      byte-identical to ee/LICENSE. Every other LICENSES/ text is an unmodified
#      SPDX text whose SHA-256 is pinned below. LICENSE and ee/LICENSE are
#      counsel's text and the source of truth; never edit the copies by hand —
#      regenerate them with `scripts/check_reuse_licensing.sh sync`.
#   2. LINT. `reuse lint` passes, run from the digest-pinned fsfe/reuse image
#      over exactly the files git tracks (plus new, not-ignored files).
#   3. TREES. Every file's resulting license is the license of the tree LICENSE
#      puts it in: ee/ -> LicenseRef-Probectl-Commercial; pkg/, proto/,
#      examples/ -> MPL-2.0; everything else -> BUSL-1.1. A file may differ only
#      through a REUSE.toml annotation with precedence "override" (third-party
#      and separately licensed files), and no such annotation may reach ee/.
#
# Usage:
#   scripts/check_reuse_licensing.sh            run the gate
#   scripts/check_reuse_licensing.sh SELFTEST   plant each defect, prove it fails
#   scripts/check_reuse_licensing.sh sync       rewrite the three probectl
#                                               copies in LICENSES/ from LICENSE
#                                               and ee/LICENSE
# Env:
#   REUSE_CONTAINER_PREFIX  name prefix of the throwaway reuse containers.
#   REUSE_MAP_OUT=<file>  also write {path: SPDX expression} for every file, the
#                         input cmd/probectl-sbom-license uses to declare
#                         first-party licenses in release SBOMs.
#
# Needs docker (the pinned reuse image) and python3 >= 3.11 (tomllib).
set -euo pipefail
cd "$(dirname "$0")/.."

# reuse 6.2.0 (REUSE Specification 3.3), by multi-arch index digest. Bump the
# tag and the digest together (Renovate's digest manager tracks this line):
# docker buildx imagetools inspect fsfe/reuse:<ver>
REUSE_IMAGE="fsfe/reuse:6.2.0@sha256:85462a75c0f8efda09ddd190b92816b70e7662577c8427429e11e1b9f25a992e"
REUSE_VERSION="${REUSE_IMAGE#*:}"
REUSE_VERSION="${REUSE_VERSION%%@*}"

# Unmodified SPDX license-list texts (as `reuse download <id>` writes them) for
# third-party and separately licensed files; see REUSE.toml for who uses each.
THIRD_PARTY_TEXTS="
Apache-2.0 074e6e32c86a4c0ef8b3ed25b721ca23aca83df277cd88106ef7177c354615ff
BSD-2-Clause f32fb3b417a194167cfad068223fc975ba96c5960513a10f66a3c28720aec1df
BSD-3-Clause 5a93d5831e1297ab10fe643e1a631e83be392896da14ee2951285a79012df69d
GPL-2.0-only aaf135472f81c5b4a0dca9367e5bb5e9750032b5bebe5442b36e4c0a47430df3
ISC 521c6f0ed8e64736684f89843d16a4df6b4b7449acbcfc6ca6630a3037ca8c53
LGPL-2.1-only 5749785c8bdefafcb5d798270ed0a967036fe2ca63dcedade1627565dfef81d2
OFL-1.1 8eea8287e5876b539670cadb82e99f9a7afddec6f6730811be1daf25d2e9bcfd
"

die() { echo "::error::reuse-gate: $*" >&2; exit 1; }

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1
  else shasum -a 256 "$1" | cut -d' ' -f1; fi
}

# extract_section <license-file> <first line>: the LICENSE section (between the
# full-width dashed separators) whose first line is <first line>, without the
# blank lines around it. Exits 3 when no section starts with that line.
extract_section() {
  awk -v HEAD="$2" '
    /^-{70,}$/ { sec++; next }
    { line[sec, ++n[sec]] = $0 }
    END {
      for (s = 0; s <= sec; s++) {
        a = 1; b = n[s]
        while (a <= b && line[s, a] == "") a++
        while (b >= a && line[s, b] == "") b--
        if (a <= b && line[s, a] == HEAD) {
          for (i = a; i <= b; i++) print line[s, i]
          exit 0
        }
      }
      exit 3
    }' "$1"
}

# check_copies <root>: prints one line per drifted, missing or unknown text.
check_copies() {
  local r="$1" tmp id want got f known
  tmp="$(mktemp)"
  for pair in "BUSL-1.1|Business Source License 1.1" "MPL-2.0|Mozilla Public License Version 2.0"; do
    id="${pair%%|*}"
    if ! extract_section "$r/LICENSE" "${pair#*|}" >"$tmp"; then
      echo "LICENSE has no section starting with '${pair#*|}'"
    elif ! cmp -s "$tmp" "$r/LICENSES/$id.txt"; then
      echo "LICENSES/$id.txt is not byte-identical to its section of LICENSE"
    fi
  done
  rm -f "$tmp"
  if ! cmp -s "$r/ee/LICENSE" "$r/LICENSES/LicenseRef-Probectl-Commercial.txt"; then
    echo "LICENSES/LicenseRef-Probectl-Commercial.txt is not byte-identical to ee/LICENSE"
  fi
  while read -r id want; do
    [ -n "$id" ] || continue
    if [ ! -f "$r/LICENSES/$id.txt" ]; then
      echo "LICENSES/$id.txt is missing"
      continue
    fi
    got="$(sha256_of "$r/LICENSES/$id.txt")"
    [ "$got" = "$want" ] || echo "LICENSES/$id.txt is not the pinned SPDX text (sha256 $got, want $want)"
  done <<<"$THIRD_PARTY_TEXTS"
  for f in "$r"/LICENSES/*; do
    id="$(basename "$f" .txt)"
    case "$id" in BUSL-1.1|MPL-2.0|LicenseRef-Probectl-Commercial) continue ;; esac
    known=no
    while read -r k _; do [ "$k" = "$id" ] && known=yes; done <<<"$THIRD_PARTY_TEXTS"
    [ "$known" = yes ] || echo "LICENSES/$(basename "$f") is not a probectl copy or a pinned SPDX text"
  done
}

# stage <root> <dest>: copy exactly the files git tracks (plus new files that
# are not ignored) so build output, node_modules and local junk never reach
# the lint, and so a git worktree lints the same as a clone.
stage() {
  local r="$1" d="$2"
  mkdir -p "$d"
  (cd "$r" && git ls-files -z --cached --others --exclude-standard |
    while IFS= read -r -d '' f; do
      if [ -e "$f" ] || [ -L "$f" ]; then printf '%s\0' "$f"; fi
    done | tar --null -T - -cf -) | tar -xf - -C "$d"
}

# reuse_lint <staged-dir> <json-out>: the pinned reuse, human report on failure.
reuse_lint() {
  local d="$1" out="$2" rc=0
  command -v docker >/dev/null 2>&1 || die "docker is required to run the pinned reuse image (${REUSE_IMAGE})"
  docker run --rm --network none --name "${REUSE_CONTAINER_PREFIX:-probectl-reuse-gate}-$$-${RANDOM}" \
    -v "$d:/data:ro" "$REUSE_IMAGE" lint --json >"$out" || rc=$?
  if [ "$rc" -ne 0 ]; then
    docker run --rm --network none --name "${REUSE_CONTAINER_PREFIX:-probectl-reuse-gate}-$$-${RANDOM}" \
      -v "$d:/data:ro" "$REUSE_IMAGE" lint >&2 || true
    return 1
  fi
}

# check_trees <REUSE.toml> <lint-json> [map-out]: the per-file tree rule.
check_trees() {
  REUSE_EXPECT_VERSION="$REUSE_VERSION" python3 -I - "$@" <<'PY'
import json, re, sys
if sys.version_info < (3, 11):
    sys.exit("reuse-gate: python3 >= 3.11 is required (tomllib)")
import tomllib

toml_path, lint_path = sys.argv[1], sys.argv[2]
map_out = sys.argv[3] if len(sys.argv) > 3 else ""
BUSL, MPL, COMM = "BUSL-1.1", "MPL-2.0", "LicenseRef-Probectl-Commercial"
errs = []

def tree_of(path):
    top = path.split("/", 1)[0]
    if top == "ee":
        return COMM
    if top in ("pkg", "proto", "examples"):
        return MPL
    return BUSL

def glob_re(pattern):
    # REUSE.toml globbing: "**" spans directories, "*" does not, "\\*" is a
    # literal star.
    out, i = "", 0
    while i < len(pattern):
        if pattern.startswith("\\*", i):
            out += re.escape("*"); i += 2
        elif pattern.startswith("**", i):
            out += ".*"; i += 2
        elif pattern[i] == "*":
            out += "[^/]*"; i += 1
        else:
            out += re.escape(pattern[i]); i += 1
    return re.compile(out + r"\Z")

with open(toml_path, "rb") as fh:
    doc = tomllib.load(fh)
anns = doc.get("annotations", [])
norm = []
for a in anns:
    paths = a.get("path")
    paths = [paths] if isinstance(paths, str) else list(paths or [])
    norm.append((paths, a.get("SPDX-License-Identifier"), a.get("precedence", "closest")))

TREES = {("**",): BUSL, ("examples/**", "pkg/**", "proto/**"): MPL, ("ee/**",): COMM}
if doc.get("version") != 1:
    errs.append("REUSE.toml must declare version = 1")
if not norm or tuple(norm[0][0]) != ("**",):
    errs.append('the first REUSE.toml annotation must be the core tree, path = "**"')
seen, exceptions, after_trees = set(), [], False
for idx, (paths, lic, prec) in enumerate(norm):
    key = tuple(sorted(paths))
    if key in TREES:
        if after_trees:
            errs.append(f"tree annotation {list(key)} must come before every override annotation")
        if key in seen:
            errs.append(f"tree annotation {list(key)} is declared twice")
        seen.add(key)
        if lic != TREES[key]:
            errs.append(f"tree annotation {list(key)} declares {lic!r}; LICENSE gives that tree {TREES[key]}")
        if prec != "closest":
            errs.append(f'tree annotation {list(key)} must use precedence "closest" so per-file SPDX headers keep their license')
        continue
    after_trees = True
    for p in paths:
        if p == "ee" or p.startswith("ee/") or p.startswith("*") or p.startswith("\\*"):
            errs.append(f"annotation path {p!r} reaches ee/ or the whole tree; only the ee/** tree annotation may")
    if prec != "override":
        errs.append(f'annotation {paths} is not a tree annotation, so it must use precedence "override"')
    if lic and COMM in lic:
        errs.append(f"annotation {paths} declares {COMM}, which only the ee/** tree may carry")
    exceptions.append(([glob_re(p) for p in paths], lic, paths))
for key in TREES:
    if key not in seen:
        errs.append(f"REUSE.toml is missing the tree annotation {list(key)}")

with open(lint_path, encoding="utf-8") as fh:
    lint = json.load(fh)
import os
want_version = os.environ.get("REUSE_EXPECT_VERSION", "")
if want_version and lint.get("reuse_tool_version") != want_version:
    errs.append(f"the lint ran reuse {lint.get('reuse_tool_version')!r}, not the pinned {want_version}")
if lint.get("reuse_spec_version") != "3.3":
    errs.append(f"the lint checked REUSE Specification {lint.get('reuse_spec_version')!r}, want 3.3")
files = {}
for f in lint.get("files", []):
    exprs = sorted({e["value"] for e in f.get("spdx_expressions", [])})
    files[f["path"]] = exprs

counts = {BUSL: 0, MPL: 0, COMM: 0}
for path, exprs in sorted(files.items()):
    exc = None
    for regs, lic, paths in exceptions:
        if any(r.match(path) for r in regs):
            exc = (lic, paths)  # the last match wins, as in REUSE
    if tree_of(path) == COMM:
        # ee/ carries no third-party or separately licensed file: nothing may
        # move an ee/ file off the commercial license, an override included.
        counts[COMM] += 1
        if exprs != [COMM]:
            errs.append(f"{path}: license {exprs}, but LICENSE puts it in the {COMM} tree")
        continue
    if exc is not None:
        if exprs != [exc[0]]:
            errs.append(f"{path}: license {exprs}, but its override annotation {exc[1]} declares {exc[0]!r}")
        continue
    want = tree_of(path)
    counts[want] += 1
    if exprs != [want]:
        errs.append(f"{path}: license {exprs}, but LICENSE puts it in the {want} tree")
for lic, n in counts.items():
    if n == 0:
        errs.append(f"no file resolved to the {lic} tree; the lint output looks vacuous")

if errs:
    for e in errs[:200]:
        print(f"::error::reuse-gate: {e}", file=sys.stderr)
    if len(errs) > 200:
        print(f"::error::reuse-gate: ... and {len(errs) - 200} more", file=sys.stderr)
    sys.exit(1)
if map_out:
    with open(map_out, "w", encoding="utf-8") as fh:
        json.dump({
            "reuse_tool_version": lint.get("reuse_tool_version"),
            "reuse_spec_version": lint.get("reuse_spec_version"),
            "files": {p: (e[0] if len(e) == 1 else " AND ".join(f"({x})" for x in e)) for p, e in sorted(files.items())},
        }, fh, indent=1, sort_keys=True)
        fh.write("\n")
print(f"reuse-gate: {len(files)} files, {counts[BUSL]} BUSL-1.1 / {counts[MPL]} MPL-2.0 / "
      f"{counts[COMM]} {COMM} by tree, {len(files) - sum(counts.values())} third-party or separately licensed by override")
PY
}

# gate <root> [map-out]
gate() {
  local r="$1" map="${2:-}" work drift
  drift="$(check_copies "$r")"
  if [ -n "$drift" ]; then
    printf '::error::reuse-gate: %s\n' "$drift" >&2
    echo "LICENSE and ee/LICENSE are the source of truth; regenerate the copies with: scripts/check_reuse_licensing.sh sync" >&2
    return 1
  fi
  work="$(mktemp -d)"
  stage "$r" "$work/tree"
  if ! reuse_lint "$work/tree" "$work/lint.json"; then
    rm -rf "$work"
    echo "::error::reuse-gate: reuse lint (${REUSE_VERSION}) failed. A file that only QUOTES an SPDX tag wraps the quotation in REUSE-IgnoreStart/REUSE-IgnoreEnd; a third-party file gets an override annotation in REUSE.toml." >&2
    return 1
  fi
  if ! check_trees "$r/REUSE.toml" "$work/lint.json" ${map:+"$map"}; then
    rm -rf "$work"
    return 1
  fi
  rm -rf "$work"
}

case "${1:-}" in
  sync)
    extract_section LICENSE "Business Source License 1.1" >LICENSES/BUSL-1.1.txt
    extract_section LICENSE "Mozilla Public License Version 2.0" >LICENSES/MPL-2.0.txt
    cp ee/LICENSE LICENSES/LicenseRef-Probectl-Commercial.txt
    echo "reuse-gate: LICENSES/ copies regenerated from LICENSE and ee/LICENSE"
    ;;
  SELFTEST)
    # REUSE-IgnoreStart (the plants below quote SPDX tags on purpose)
    st="$(mktemp -d)"
    trap 'rm -rf "$st"' EXIT
    # The real tree is the good fixture: it must pass before a plant counts.
    stage . "$st/good"
    (cd "$st/good" && git init -q && git add -A) >/dev/null
    gate "$st/good" >/dev/null || { echo "reuse-gate SELFTEST FAILED: the unplanted tree does not pass" >&2; exit 1; }

    # (a) one changed byte in each copied text is drift.
    for t in BUSL-1.1 MPL-2.0 LicenseRef-Probectl-Commercial; do
      rm -rf "$st/a"; mkdir -p "$st/a/ee"
      cp "$st/good/LICENSE" "$st/a/LICENSE"; cp "$st/good/ee/LICENSE" "$st/a/ee/LICENSE"
      cp -R "$st/good/LICENSES" "$st/a/LICENSES"
      python3 -I -c 'import sys; p=sys.argv[1]; b=bytearray(open(p,"rb").read()); i=len(b)//2; b[i]=ord("#") if b[i]!=ord("#") else ord("%"); open(p,"wb").write(b)' "$st/a/LICENSES/$t.txt"
      check_copies "$st/a" | grep -Fq "LICENSES/$t.txt is not byte-identical" ||
        { echo "reuse-gate SELFTEST FAILED: a one-byte edit to LICENSES/$t.txt was not caught" >&2; exit 1; }
    done
    # ... and so is an edited pinned SPDX text, or an unpinned extra text.
    rm -rf "$st/a"; mkdir -p "$st/a/ee"
    cp "$st/good/LICENSE" "$st/a/LICENSE"; cp "$st/good/ee/LICENSE" "$st/a/ee/LICENSE"
    cp -R "$st/good/LICENSES" "$st/a/LICENSES"
    printf 'x' >>"$st/a/LICENSES/ISC.txt"
    printf 'text\n' >"$st/a/LICENSES/MIT.txt"
    out="$(check_copies "$st/a")"
    grep -Fq "LICENSES/ISC.txt is not the pinned SPDX text" <<<"$out" &&
      grep -Fq "LICENSES/MIT.txt is not a probectl copy" <<<"$out" ||
      { echo "reuse-gate SELFTEST FAILED: an edited or unpinned SPDX text was not caught" >&2; exit 1; }

    # (b) an ee/ file mapped to BUSL-1.1 must fail: through the tree annotation,
    # through a stray override, and through a file's own header.
    plant() { # plant <name> <python edit run inside a copy of the good tree>
      rm -rf "${st:?}/$1"; cp -R "$st/good" "$st/$1"
      (cd "$st/$1" && python3 -I -c "$2")
    }
    plant ee-tree 'p = "REUSE.toml"; s = open(p).read(); old = "path = \"ee/**\"\nprecedence = \"closest\"\nSPDX-FileCopyrightText = \"the probectl contributors and applicable rights holders\"\nSPDX-License-Identifier = \"LicenseRef-Probectl-Commercial\""; assert old in s; open(p, "w").write(s.replace(old, old.replace("LicenseRef-Probectl-Commercial", "BUSL-1.1")))'
    gate "$st/ee-tree" 2>"$st/err" && { echo "reuse-gate SELFTEST FAILED: REUSE.toml mapping ee/** to BUSL-1.1 passed the gate" >&2; exit 1; }
    # Both rules must bite on their own: the structural one names the
    # annotation, the per-file one names the ee/ files that lost their license.
    grep -Fq "tree annotation ['ee/**'] declares 'BUSL-1.1'" "$st/err" &&
      grep -Eq "ee/[^:]+: license \['BUSL-1.1'\], but LICENSE puts it in the LicenseRef-Probectl-Commercial tree" "$st/err" ||
      { echo "reuse-gate SELFTEST FAILED: the ee/** -> BUSL-1.1 mapping was not caught by both rules" >&2; cat "$st/err" >&2; exit 1; }
    plant ee-override 'open("REUSE.toml", "a").write("\n[[annotations]]\npath = \"ee/README.md\"\nprecedence = \"override\"\nSPDX-FileCopyrightText = \"2026 certctl LLC\"\nSPDX-License-Identifier = \"BUSL-1.1\"\n")'
    gate "$st/ee-override" 2>"$st/err" && { echo "reuse-gate SELFTEST FAILED: an override mapping an ee/ file to BUSL-1.1 passed the gate" >&2; exit 1; }
    grep -Fq "annotation path 'ee/README.md' reaches ee/" "$st/err" &&
      grep -Fq "ee/README.md: license ['BUSL-1.1'], but LICENSE puts it in the LicenseRef-Probectl-Commercial tree" "$st/err" ||
      { echo "reuse-gate SELFTEST FAILED: the ee/ override was not caught by both rules" >&2; cat "$st/err" >&2; exit 1; }
    plant ee-header 'import glob; f = sorted(glob.glob("ee/**/*.go", recursive=True))[0]; s = open(f).read(); assert "SPDX-License-Identifier: LicenseRef-Probectl-Commercial" in s; open(f, "w").write(s.replace("SPDX-License-Identifier: LicenseRef-Probectl-Commercial", "SPDX-License-Identifier: BUSL-1.1", 1))'
    gate "$st/ee-header" 2>"$st/err" && { echo "reuse-gate SELFTEST FAILED: an ee/ file with a BUSL-1.1 header passed the gate" >&2; exit 1; }
    grep -Eq "ee/[^:]+\.go: license \['BUSL-1.1'\], but LICENSE puts it in the LicenseRef-Probectl-Commercial tree" "$st/err" ||
      { echo "reuse-gate SELFTEST FAILED: the ee/ file with a BUSL-1.1 header was not caught" >&2; cat "$st/err" >&2; exit 1; }

    # (c) a file reuse cannot license at all fails the lint itself.
    plant unlicensed 'open("internal/reuse_selftest.txt","w").write("SPDX-License-Identifier: not a license expression (\n")'
    (cd "$st/unlicensed" && git add -A) >/dev/null
    gate "$st/unlicensed" 2>"$st/err" && { echo "reuse-gate SELFTEST FAILED: an invalid SPDX expression passed reuse lint" >&2; exit 1; }
    grep -Fq "reuse lint (${REUSE_VERSION}) failed" "$st/err" ||
      { echo "reuse-gate SELFTEST FAILED: the invalid expression failed for the wrong reason" >&2; cat "$st/err" >&2; exit 1; }

    # REUSE-IgnoreEnd
    echo "reuse-gate SELFTEST OK (copy drift x5; ee/ mapped to BUSL-1.1 by tree, override and header; invalid expression)"
    ;;
  "")
    gate . "${REUSE_MAP_OUT:-}"
    echo "reuse-gate: OK (LICENSES/ copies match LICENSE and ee/LICENSE; reuse ${REUSE_VERSION} lint passes; every file carries its tree's license or a declared override)"
    ;;
  *)
    echo "usage: scripts/check_reuse_licensing.sh [SELFTEST|sync]" >&2
    exit 2
    ;;
esac
