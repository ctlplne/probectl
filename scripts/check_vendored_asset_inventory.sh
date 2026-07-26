#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0
#
# SUPPLY-009: prove every explicitly declared shipped data/font asset exists,
# remains byte-identical to its recorded provenance digest, and appears in both
# generated attribution surfaces. A planted missing-file manifest exercises the
# generator's fail-closed path without moving or editing a real runtime asset.
set -euo pipefail

cd "$(dirname "$0")/.."

manifest="third_party/vendored-assets.json"
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

declared_paths = {asset["path"] for asset in assets}
discovered_paths = {
    path.as_posix()
    for pattern in (
        "web/src/viz/geo/*.json",
        "web/src/styles/fonts/*.woff2",
    )
    for path in Path(".").glob(pattern)
    if path.is_file()
}
if declared_paths != discovered_paths:
    missing = sorted(discovered_paths - declared_paths)
    stale = sorted(declared_paths - discovered_paths)
    raise SystemExit(
        "vendored asset gate: manifest/runtime discovery differ; "
        f"undeclared={missing}, no-longer-shipped={stale}"
    )

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
