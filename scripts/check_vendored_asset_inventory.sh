#!/usr/bin/env bash
# SPDX-License-Identifier: BUSL-1.1
#
# SUPPLY-009 + G-bc21fbb0: prove every declared shipped data/font asset
# exists, remains byte-identical to its recorded provenance digest, and
# appears in both generated attribution surfaces — and discover assets by
# CONTENT CLASS across the whole tracked tree, not by directory glob. An
# asset vendored anywhere is either declared third-party
# (third_party/vendored-assets.json) or declared first-party with an origin
# (third_party/first-party-assets.json); fonts and geodata must be
# third-party-declared. Undeclared assets, stale declarations, and
# reason-less first-party entries all fail.
#
# Self-tests (always run, plus available via the SELFTEST argument):
#  - a synthetic file list plants a font OUTSIDE the historically-globbed
#    directories and asserts the classifier refuses it undeclared;
#  - a planted missing-file manifest exercises the generator's fail-closed
#    path without moving or editing a real runtime asset.
set -euo pipefail

cd "$(dirname "$0")/.."

manifest="third_party/vendored-assets.json"
firstparty="third_party/first-party-assets.json"

# classify_and_check <files-list-file> <manifest> <first-party>
# The rule: font/geodata classes must be third-party-declared; binary media
# must be declared in exactly one register; declarations must exist in the
# file list (both directions).
classify_and_check() {
  python3 - "$1" "$2" "$3" <<'PY'
import json
import re
import sys
from pathlib import Path

files = [l.strip() for l in Path(sys.argv[1]).read_text().splitlines() if l.strip()]
manifest = json.loads(Path(sys.argv[2]).read_text())
firstparty = json.loads(Path(sys.argv[3]).read_text())

third = {a["path"] for a in manifest.get("assets", [])}
if not third:
    raise SystemExit("vendored asset gate: manifest has no assets")
first = {}
for a in firstparty.get("assets", []):
    if not a.get("origin", "").strip():
        raise SystemExit(f"vendored asset gate: first-party entry without an origin reason: {a.get('path')}")
    first[a["path"]] = a["origin"]

FONT = re.compile(r"\.(woff2?|ttf|otf|eot)$", re.I)
GEO = re.compile(r"(\.(topojson|geojson)$)|(/geo/.*\.json$)", re.I)
MEDIA = re.compile(r"\.(png|jpe?g|gif|webp|ico|wasm)$", re.I)

errors = []
discovered = set()
for f in files:
    if FONT.search(f) or GEO.search(f):
        discovered.add(f)
        if f not in third:
            errors.append(f"undeclared third-party-class asset (font/geodata): {f}")
    elif MEDIA.search(f):
        discovered.add(f)
        if f not in third and f not in first:
            errors.append(f"undeclared binary asset (declare third-party or first-party with origin): {f}")
        if f in third and f in first:
            errors.append(f"asset declared in BOTH registers: {f}")

fileset = set(files)
for p in sorted(third):
    if p not in fileset:
        errors.append(f"declared third-party asset no longer shipped: {p}")
for p in sorted(first):
    if p not in fileset:
        errors.append(f"declared first-party asset no longer shipped: {p}")

if errors:
    raise SystemExit("vendored asset gate (content-class discovery):\n  " + "\n  ".join(errors))
print(f"vendored asset discovery: {len(discovered)} class-discovered assets all declared "
      f"({len(third)} third-party, {len(first)} first-party)")
PY
}

selftest_classifier() {
  local tmp
  tmp="$(mktemp -d)"
  # (a) planted font OUTSIDE the historically-globbed directories → refuse
  printf '%s\n' \
    "web/src/styles/fonts/inter-latin-wght.woff2" \
    "internal/webui/planted-sneaky-font.woff2" \
    > "$tmp/files"
  if classify_and_check "$tmp/files" "$manifest" "$firstparty" >"$tmp/out" 2>&1; then
    echo "vendored asset gate SELFTEST FAILED: planted outside-glob font was not refused" >&2
    cat "$tmp/out" >&2
    rm -rf "$tmp"
    exit 1
  fi
  grep -q 'planted-sneaky-font.woff2' "$tmp/out" || {
    echo "vendored asset gate SELFTEST FAILED: refusal did not name the planted font" >&2
    cat "$tmp/out" >&2
    rm -rf "$tmp"
    exit 1
  }
  # (b) the real tracked tree must pass
  git ls-files > "$tmp/real-files"
  classify_and_check "$tmp/real-files" "$manifest" "$firstparty" >/dev/null || {
    echo "vendored asset gate SELFTEST FAILED: real tree does not pass discovery" >&2
    rm -rf "$tmp"
    exit 1
  }
  rm -rf "$tmp"
  echo "vendored asset discovery selftest OK (planted outside-glob font refused; real tree passes)"
}

selftest_classifier
if [ "${1:-}" = "SELFTEST" ]; then
  # Classifier planted-shape proven. The generator fail-closed planted
  # manifest (below) needs the Go toolchain and runs in the full gate.
  exit 0
fi

tmpfiles="$(mktemp)"
git ls-files > "$tmpfiles"
classify_and_check "$tmpfiles" "$manifest" "$firstparty"
rm -f "$tmpfiles"

python3 - "$manifest" NOTICE docs/third-party-licenses.md <<'PY'
import json
import sys
from pathlib import Path

manifest_path = Path(sys.argv[1])
notice = Path(sys.argv[2]).read_text()
inventory = Path(sys.argv[3]).read_text()
assets = json.loads(manifest_path.read_text()).get("assets", [])
if not assets:
    raise SystemExit("vendored asset gate: manifest has no assets")

for asset in assets:
    path = asset["path"]
    if notice.count(path) != 1:
        raise SystemExit(
            f"vendored asset gate: {path} appears {notice.count(path)} times in NOTICE; want exactly 1"
        )
    if inventory.count(path) != 1:
        raise SystemExit(
            f"vendored asset gate: {path} appears {inventory.count(path)} times in inventory; want exactly 1"
        )
print(f"vendored asset coverage: {len(assets)} declared assets appear exactly once in both outputs")
PY

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
cp NOTICE "$tmp/NOTICE.before"
cp docs/third-party-licenses.md "$tmp/inventory.before"

python3 - "$manifest" "$tmp/missing-asset.json" <<'PY'
import json
import sys
from pathlib import Path

source = Path(sys.argv[1])
destination = Path(sys.argv[2])
manifest = json.loads(source.read_text())
manifest["assets"][0]["path"] = "web/src/viz/geo/planted-missing-land-110m.json"
destination.write_text(json.dumps(manifest, indent=2) + "\n")
PY

if PROBECTL_VENDORED_ASSET_MANIFEST="$tmp/missing-asset.json" \
  ./scripts/gen_third_party.sh >"$tmp/missing.log" 2>&1; then
  echo "vendored asset gate: generator accepted a declared missing asset" >&2
  exit 1
fi
grep -q 'vendored asset file missing: web/src/viz/geo/planted-missing-land-110m.json' "$tmp/missing.log" || {
  echo "vendored asset gate: planted manifest failed for the wrong reason" >&2
  cat "$tmp/missing.log" >&2
  exit 1
}
cmp -s NOTICE "$tmp/NOTICE.before" || {
  echo "vendored asset gate: failing validation rewrote NOTICE" >&2
  exit 1
}
cmp -s docs/third-party-licenses.md "$tmp/inventory.before" || {
  echo "vendored asset gate: failing validation rewrote the inventory" >&2
  exit 1
}

echo "vendored asset inventory gate: OK (coverage + planted missing-file refusal)"
