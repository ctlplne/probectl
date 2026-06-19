#!/usr/bin/env bash
#
# OpenAPI completeness gate (S19, F23 / CLAUDE.md §6, §8): no undocumented routes
# may ship at a GA milestone. This gate:
#   1. validates internal/control/openapi.json is well-formed JSON,
#   2. checks it is an OpenAPI 3.1 document with a non-empty paths object,
#   3. rejects stale sprint-era auth prose in generated API specs,
#   4. runs Go checks that deprecated operations carry lifecycle metadata and
#      that the registered /v1 route table EXACTLY matches the
#      documented /v1 operations (neither undocumented handlers nor documented
#      phantom routes).
set -euo pipefail

cd "$(dirname "$0")/.."

SPEC="internal/control/openapi.json"

echo ">> openapi: validating ${SPEC}"
python3 - "$SPEC" <<'PY'
import json, sys
spec = sys.argv[1]
with open(spec) as f:
    doc = json.load(f)  # raises on malformed JSON
version = str(doc.get("openapi", ""))
if not version.startswith("3.1"):
    sys.exit(f"openapi gate: expected OpenAPI 3.1, got {version!r}")
paths = doc.get("paths") or {}
if not paths:
    sys.exit("openapi gate: no paths documented")
v1 = [p for p in paths if p.startswith("/v1/")]
if not v1:
    sys.exit("openapi gate: no /v1 operations documented")
print(f"   openapi {version}, {len(paths)} paths ({len(v1)} under /v1)")
PY

echo ">> openapi: generated-spec claim drift"
python3 - <<'PY'
from pathlib import Path

banned = ("dev stub", "Dev stub", "S9", "lands in S18", "real identity")
specs = (Path("internal/control/openapi.json"), Path("ee/provider/openapi.json"))
for spec in specs:
    if not spec.exists():
        continue
    body = spec.read_text()
    hits = [phrase for phrase in banned if phrase in body]
    if hits:
        joined = ", ".join(repr(hit) for hit in hits)
        raise SystemExit(f"openapi gate: {spec} contains stale auth wording: {joined}")
print("   generated OpenAPI auth wording is current")
PY

echo ">> openapi: lifecycle + routes <-> spec completeness"
${GO:-go} test -count=1 -run '^(TestDeprecatedOperationsDeclareLifecycle|TestOpenAPIMatchesRoutes)$' ./internal/control/

echo "openapi gate: OK (lifecycle metadata + no undocumented routes)"
