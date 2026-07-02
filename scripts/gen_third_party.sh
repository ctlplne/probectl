#!/usr/bin/env bash
# Regenerate the unified third-party dependency license inventory + NOTICE.
# Dependency-free: Go comes from `go list` plus a cached LICENSE/COPYING scan,
# npm comes from checked-in package-lock license fields, and Python comes from
# checked-in pyproject/uv lock metadata plus a tiny audited hint map where the
# lock format lacks licenses. The detected license is a keyword HEURISTIC; it
# must be verified before any commercial/MSP resale (the code-dependency
# counterpart of docs/opendata-aup.md). Re-run after dependency changes; commit
# both outputs.
set -euo pipefail
cd "$(dirname "$0")/.."
export GOWORK=off

NOTICE_FILE="NOTICE"
INV_FILE="docs/third-party-licenses.md"
mainmod="$(go list -m)"
rows="$(mktemp)"
trap 'rm -f "$rows"' EXIT
: >"$rows"

detect_license() { # detect_license <module-dir>
  local dir="$1" f head
  [ -n "$dir" ] || { echo "UNKNOWN (module dir unavailable)"; return; }
  f="$(ls "$dir"/LICENSE* "$dir"/COPYING* "$dir"/License* 2>/dev/null | head -1 || true)"
  [ -n "$f" ] || { echo "UNKNOWN (no LICENSE file)"; return; }
  head="$(head -40 "$f" 2>/dev/null || true)"
  case "$head" in
    *"Apache License"*"Version 2.0"*) echo "Apache-2.0" ;;
    *"Permission is hereby granted, free of charge"*) echo "MIT" ;;
    *"Mozilla Public License"*"2.0"*) echo "MPL-2.0" ;;
    *"GNU LESSER GENERAL PUBLIC"*) echo "LGPL" ;;
    *"GNU GENERAL PUBLIC"*) echo "GPL" ;;
    *"ISC License"*|*"ISC license"*) echo "ISC" ;;
    *"Redistribution and use in source and binary forms"*) echo "BSD" ;;
    *) echo "see module ($(basename "$f"))" ;;
  esac
}

mods="$(go list -deps -f '{{with .Module}}{{.Path}}|{{.Version}}|{{.Dir}}{{end}}' ./... 2>/dev/null | sort -u)"

n=0
while IFS='|' read -r path ver dir; do
  [ -n "${path:-}" ] || continue
  [ "$path" = "$mainmod" ] && continue
  [ -n "${ver:-}" ] || continue # the main module / a local replace has no version
  lic="$(detect_license "${dir:-}")"
  printf 'go\t%s\t%s\truntime\t%s\tgo list -deps ./...; module cache LICENSE/COPYING scan\n' "$path" "$ver" "$lic" >>"$rows"
  n=$((n + 1))
done <<<"$mods"

python3 - "$rows" "$NOTICE_FILE" "$INV_FILE" "$n" <<'PY'
import json
import re
import sys
import tomllib
from pathlib import Path

rows_path = Path(sys.argv[1])
notice_path = Path(sys.argv[2])
inventory_path = Path(sys.argv[3])
go_count = int(sys.argv[4])

REPO = Path(".")

PYTHON_LICENSE_HINTS = {
    # The uv requirements lock intentionally pins hashes but does not include
    # package metadata. Keep this map tiny and auditable; unknowns stay visible.
    "structlog": "Apache-2.0",
}


def normalize_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def markdown_cell(value: str) -> str:
    return value.replace("|", "\\|")


def package_name_from_lock_key(key: str) -> str | None:
    if "node_modules/" not in key:
        return None
    suffix = key.rsplit("node_modules/", 1)[1]
    parts = suffix.split("/")
    if not parts or not parts[0]:
        return None
    if parts[0].startswith("@"):
        if len(parts) < 2:
            return None
        return f"{parts[0]}/{parts[1]}"
    return parts[0]


def license_from_npm(meta: dict) -> str:
    lic = meta.get("license")
    if isinstance(lic, str) and lic.strip():
        return lic.strip()
    licenses = meta.get("licenses")
    if isinstance(licenses, list):
        values = []
        for item in licenses:
            if isinstance(item, str):
                values.append(item)
            elif isinstance(item, dict) and item.get("type"):
                values.append(str(item["type"]))
        if values:
            return " OR ".join(values)
    return "UNKNOWN (npm lock lacks license field)"


def requirement_name(spec: str) -> str | None:
    match = re.match(r"\s*([A-Za-z0-9_.-]+)", spec)
    if not match:
        return None
    return normalize_name(match.group(1))


def append_npm(rows: list[dict], workspace: str) -> int:
    lock_path = REPO / workspace / "package-lock.json"
    if not lock_path.exists():
        return 0
    data = json.loads(lock_path.read_text())
    count = 0
    for key, meta in data.get("packages", {}).items():
        if not isinstance(meta, dict):
            continue
        name = package_name_from_lock_key(key)
        version = meta.get("version")
        if not name or not version:
            continue
        scope = "dev/build-only" if meta.get("dev") is True else "runtime"
        rows.append(
            {
                "ecosystem": f"npm:{workspace}",
                "name": name,
                "version": str(version),
                "scope": scope,
                "license": license_from_npm(meta),
                "evidence": f"{workspace}/package-lock.json:{key}",
            }
        )
        count += 1
    return count


def append_python(rows: list[dict]) -> int:
    pyproject_path = REPO / "analyzer" / "pyproject.toml"
    lock_path = REPO / "analyzer" / "requirements-dev.lock"
    if not pyproject_path.exists() or not lock_path.exists():
        return 0

    project = tomllib.loads(pyproject_path.read_text())
    runtime_names = {
        name
        for dep in project.get("project", {}).get("dependencies", [])
        if (name := requirement_name(dep))
    }

    count = 0
    for line in lock_path.read_text().splitlines():
        match = re.match(r"^([A-Za-z0-9_.-]+)==([^\\\s]+)", line)
        if not match:
            continue
        raw_name, version = match.groups()
        name = normalize_name(raw_name)
        scope = "runtime" if name in runtime_names else "dev/build-only"
        rows.append(
            {
                "ecosystem": "python:analyzer",
                "name": name,
                "version": version,
                "scope": scope,
                "license": PYTHON_LICENSE_HINTS.get(
                    name, "UNKNOWN (uv lock lacks license metadata)"
                ),
                "evidence": "analyzer/requirements-dev.lock; analyzer/pyproject.toml scope pins",
            }
        )
        count += 1
    return count


def read_go_rows() -> list[dict]:
    rows: list[dict] = []
    for line in rows_path.read_text().splitlines():
        parts = line.split("\t")
        if len(parts) != 6:
            raise SystemExit(f"bad generated row: {line!r}")
        ecosystem, name, version, scope, license_value, evidence = parts
        rows.append(
            {
                "ecosystem": ecosystem,
                "name": name,
                "version": version,
                "scope": scope,
                "license": license_value,
                "evidence": evidence,
            }
        )
    return rows


rows = read_go_rows()
npm_count = append_npm(rows, "web")
npm_count += append_npm(rows, "browser-worker")
python_count = append_python(rows)

deduped = {}
for row in rows:
    key = (
        row["ecosystem"],
        row["name"],
        row["version"],
        row["scope"],
        row["license"],
        row["evidence"],
    )
    deduped[key] = row

scope_rank = {"runtime": 0, "dev/build-only": 1}
rows = sorted(
    deduped.values(),
    key=lambda row: (
        row["ecosystem"],
        scope_rank.get(row["scope"], 9),
        row["name"].lower(),
        row["version"],
    ),
)

notice_lines = [
    "probectl - THIRD-PARTY NOTICES",
    "",
    "probectl is built, tested, packaged, and shipped with the third-party",
    "dependencies listed below, each under its own license. GENERATED by",
    "scripts/gen_third_party.sh from Go, npm, and Python dependency metadata -",
    "do not hand-edit. The per-dependency inventory with detected licenses is",
    "docs/third-party-licenses.md.",
    "",
]
for row in rows:
    notice_lines.append(
        f"- {row['ecosystem']} {row['name']} {row['version']} "
        f"({row['scope']}) - {row['license']}"
    )
notice_lines.append("")
notice_path.write_text("\n".join(notice_lines))

inventory_lines = [
    "# Third-party dependency licenses",
    "",
    "Generated by `scripts/gen_third_party.sh` from:",
    "",
    "- `go list -deps ./...` plus cached Go module `LICENSE`/`COPYING` files;",
    "- `web/package-lock.json` for the browser UI;",
    "- `browser-worker/package-lock.json` for the Playwright worker;",
    "- `analyzer/pyproject.toml` and `analyzer/requirements-dev.lock` for the BGP analyzer.",
    "",
    "The License column is a keyword heuristic over checked-in or cached",
    "dependency metadata. npm license values come from the lockfile. Go values",
    "come from cached license text. Python uv locks do not carry package license",
    "metadata, so only the audited hint map in `scripts/gen_third_party.sh` is",
    "reported as detected and unknowns stay explicit. **Verify before",
    "commercial/MSP resale** (the code-dependency counterpart of the provenance",
    "duty in `docs/opendata-aup.md`).",
    "",
    "| Ecosystem | Package / module | Version | Scope | License (detected) | Evidence |",
    "|---|---|---|---|---|---|",
]
for row in rows:
    inventory_lines.append(
        "| {ecosystem} | `{name}` | {version} | {scope} | {license} | {evidence} |".format(
            ecosystem=markdown_cell(row["ecosystem"]),
            name=markdown_cell(row["name"]),
            version=markdown_cell(row["version"]),
            scope=markdown_cell(row["scope"]),
            license=markdown_cell(row["license"]),
            evidence=markdown_cell(row["evidence"]),
        )
    )
inventory_lines.append("")
inventory_path.write_text("\n".join(inventory_lines))

print(
    "gen_third_party: wrote "
    f"{notice_path} + {inventory_path} "
    f"({go_count} Go modules, {npm_count} npm packages, {python_count} Python packages)."
)
PY
