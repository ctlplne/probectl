#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-probectl-TBD
"""Validate and run the pinned offline stock-client interop manifest."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


REQUIRED_FAMILIES = {
    "otlp_http",
    "prometheus_remote_write",
    "netflow_v5",
    "netflow_v9",
    "ipfix",
    "sflow",
    "snmp",
    "gnmi",
    "bgp_mrt",
}

FORBIDDEN_STOCK_CLIENT = re.compile(r"\b(probectl|adapter|shim|fake)\b", re.IGNORECASE)
FORBIDDEN_REPLAY_TOKEN = re.compile(
    r"(https?://|ssh://|git://|\bcurl\b|\bwget\b|\bnc\b|\bncat\b|\bsocat\b|"
    r"\bdocker\s+(pull|run)\b|\bgo\s+(get|install)\b|\bpip\s+install\b|\bnpm\s+install\b)",
    re.IGNORECASE,
)


def repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def nonempty(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def command_text(argv: list[str]) -> str:
    return " ".join(argv)


def validate_command(row_family: str, command: dict[str, Any], base: Path) -> list[str]:
    errors: list[str] = []
    argv = command.get("argv")
    if not isinstance(argv, list) or not argv or not all(isinstance(v, str) and v for v in argv):
        return [f"{row_family}: replay command must be a non-empty argv array"]
    if FORBIDDEN_REPLAY_TOKEN.search(command_text(argv)):
        errors.append(f"{row_family}: replay command may not fetch or open network clients: {command_text(argv)}")
    if argv[0] in {"curl", "wget", "nc", "ncat", "socat", "ssh", "scp", "git"}:
        errors.append(f"{row_family}: replay command starts with network-capable tool {argv[0]!r}")
    if argv[0] == "docker":
        errors.append(f"{row_family}: replay command uses docker; offline CI must not pull/run mutable images")

    workdir = command.get("workdir", ".")
    if not nonempty(workdir):
        errors.append(f"{row_family}: replay command workdir is empty")
    else:
        wd = (base / workdir).resolve()
        try:
            wd.relative_to(base.resolve())
        except ValueError:
            errors.append(f"{row_family}: replay workdir escapes repo: {workdir}")
        if not wd.exists():
            errors.append(f"{row_family}: replay workdir does not exist: {workdir}")
    return errors


def validate_manifest(manifest: dict[str, Any], base: Path) -> list[str]:
    errors: list[str] = []
    if manifest.get("schema_version") != "probectl.interop.offline.v1":
        errors.append("manifest: schema_version must be probectl.interop.offline.v1")
    policy = manifest.get("network_policy", {})
    if policy.get("default") != "deny" or policy.get("allow_loopback") is not True:
        errors.append("manifest: network_policy must deny by default and allow loopback only")

    rows = manifest.get("families")
    if not isinstance(rows, list) or not rows:
        return errors + ["manifest: families must be a non-empty list"]

    seen: set[str] = set()
    for i, row in enumerate(rows):
        if not isinstance(row, dict):
            errors.append(f"families[{i}]: row must be an object")
            continue
        family = row.get("family")
        if not nonempty(family):
            errors.append(f"families[{i}]: family is required")
            continue
        if family in seen:
            errors.append(f"{family}: duplicate family row")
        seen.add(family)

        fixture = row.get("fixture")
        if not isinstance(fixture, dict):
            errors.append(f"{family}: fixture object is required")
        else:
            for field in ("path", "sha256", "source", "license", "aup"):
                if not nonempty(fixture.get(field)):
                    errors.append(f"{family}: fixture.{field} is required")
            sha = fixture.get("sha256", "")
            if nonempty(sha) and not re.fullmatch(r"[0-9a-f]{64}", sha):
                errors.append(f"{family}: fixture.sha256 must be 64 lowercase hex chars")
            path_value = fixture.get("path")
            if nonempty(path_value):
                fixture_path = (base / path_value).resolve()
                try:
                    fixture_path.relative_to(base.resolve())
                except ValueError:
                    errors.append(f"{family}: fixture path escapes repo: {path_value}")
                if not fixture_path.exists():
                    errors.append(f"{family}: fixture path missing: {path_value}")
                elif nonempty(sha):
                    actual = sha256_file(fixture_path)
                    if actual != sha:
                        errors.append(f"{family}: fixture SHA256 mismatch: got {actual}, want {sha}")

        stock = row.get("stock_client")
        if not isinstance(stock, dict):
            errors.append(f"{family}: stock_client object is required")
        else:
            for field in ("name", "version", "source", "license", "aup"):
                if not nonempty(stock.get(field)):
                    errors.append(f"{family}: stock_client.{field} is required")
            name = stock.get("name", "")
            if nonempty(name) and FORBIDDEN_STOCK_CLIENT.search(name):
                errors.append(f"{family}: stock_client.name must be a real stock client, not {name!r}")

        commands = row.get("replay_commands")
        if not isinstance(commands, list) or not commands:
            errors.append(f"{family}: replay_commands must contain at least one command")
        else:
            for command in commands:
                if not isinstance(command, dict):
                    errors.append(f"{family}: replay command must be an object")
                    continue
                errors.extend(validate_command(family, command, base))

    missing = sorted(REQUIRED_FAMILIES - seen)
    if missing:
        errors.append("manifest: missing required protocol families: " + ", ".join(missing))
    extra = sorted(seen - REQUIRED_FAMILIES)
    if extra:
        errors.append("manifest: unknown protocol families: " + ", ".join(extra))
    return errors


def command_argv(argv: list[str]) -> list[str]:
    if argv[0] == "go":
        return [os.environ.get("GO", "go"), *argv[1:]]
    if argv[0] in {"python", "python3"}:
        return [sys.executable, *argv[1:]]
    return argv


def run_replays(manifest: dict[str, Any], base: Path) -> int:
    env = os.environ.copy()
    env.setdefault("PROBECTL_INTEROP_OFFLINE", "1")
    env.setdefault("NO_PROXY", "localhost,127.0.0.1,::1")
    env.setdefault("no_proxy", env["NO_PROXY"])
    env.setdefault("HTTP_PROXY", "http://127.0.0.1:9")
    env.setdefault("HTTPS_PROXY", "http://127.0.0.1:9")
    env.setdefault("ALL_PROXY", "http://127.0.0.1:9")
    env.setdefault("http_proxy", env["HTTP_PROXY"])
    env.setdefault("https_proxy", env["HTTPS_PROXY"])
    env.setdefault("all_proxy", env["ALL_PROXY"])

    for row in manifest["families"]:
        family = row["family"]
        for command in row["replay_commands"]:
            argv = command_argv(command["argv"])
            workdir = (base / command.get("workdir", ".")).resolve()
            print(f">> interop-offline {family}: {command_text(argv)}", flush=True)
            result = subprocess.run(argv, cwd=workdir, env=env, check=False)
            if result.returncode != 0:
                print(f"interop-offline: {family} replay failed with exit {result.returncode}", file=sys.stderr)
                return result.returncode
    print("interop-offline: OK (manifest valid; all offline stock-client replays passed)")
    return 0


def load_manifest(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise ValueError("manifest root must be an object")
    return data


def valid_selftest_manifest(tmp: Path) -> dict[str, Any]:
    fixture = tmp / "fixture.txt"
    fixture.write_text("offline fixture\n", encoding="utf-8")
    sha = sha256_file(fixture)
    stock = {
        "name": "stock-client",
        "version": "1.0.0",
        "source": "https://example.invalid/source",
        "license": "synthetic",
        "aup": "synthetic",
    }
    row = {
        "family": "",
        "stock_client": stock,
        "fixture": {
            "path": "fixture.txt",
            "sha256": sha,
            "source": "synthetic",
            "license": "synthetic",
            "aup": "synthetic",
        },
        "replay_commands": [{"workdir": ".", "argv": ["go", "test", "./internal/flow", "-run", "^TestNone$", "-count=1"]}],
    }
    return {
        "schema_version": "probectl.interop.offline.v1",
        "network_policy": {"default": "deny", "allow_loopback": True},
        "families": [dict(row, family=fam) for fam in sorted(REQUIRED_FAMILIES)],
    }


def run_selftest() -> int:
    with tempfile.TemporaryDirectory() as d:
        base = Path(d)
        manifest = valid_selftest_manifest(base)
        errors = validate_manifest(manifest, base)
        if errors:
            print("SELFTEST valid manifest failed:", errors, file=sys.stderr)
            return 1

        def expect_fail(label: str, mutate: Any, needle: str) -> bool:
            bad = copy.deepcopy(manifest)
            mutate(bad)
            got = "\n".join(validate_manifest(bad, base))
            if needle not in got:
                print(f"SELFTEST {label} failed: wanted {needle!r} in {got!r}", file=sys.stderr)
                return False
            return True

        checks = [
            expect_fail(
                "missing-sha",
                lambda m: m["families"][0]["fixture"].pop("sha256"),
                "fixture.sha256 is required",
            ),
            expect_fail(
                "missing-source",
                lambda m: m["families"][0]["fixture"].pop("source"),
                "fixture.source is required",
            ),
            expect_fail(
                "wrong-sha",
                lambda m: m["families"][0]["fixture"].update({"sha256": "0" * 64}),
                "fixture SHA256 mismatch",
            ),
            expect_fail(
                "network-command",
                lambda m: m["families"][0].update({"replay_commands": [{"workdir": ".", "argv": ["curl", "https://example.com"]}]}),
                "replay command",
            ),
            expect_fail(
                "probectl-adapter",
                lambda m: m["families"][0]["stock_client"].update({"name": "probectl adapter"}),
                "stock_client.name must be a real stock client",
            ),
            expect_fail(
                "missing-family",
                lambda m: m["families"].pop(),
                "missing required protocol families",
            ),
            expect_fail(
                "missing-replay",
                lambda m: m["families"][0].pop("replay_commands"),
                "replay_commands must contain",
            ),
        ]
        if not all(checks):
            return 1
    print("check_interop_offline.py SELFTEST: OK")
    return 0


def main() -> int:
    if len(sys.argv) == 2 and sys.argv[1] == "SELFTEST":
        return run_selftest()
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", default="test/interop/manifest.json")
    parser.add_argument("--run-replays", action="store_true")
    args = parser.parse_args()

    base = repo_root()
    manifest = load_manifest(base / args.manifest)
    errors = validate_manifest(manifest, base)
    if errors:
        for err in errors:
            print(f"interop-offline: {err}", file=sys.stderr)
        return 1
    if args.run_replays:
        return run_replays(manifest, base)
    print("interop-offline: manifest OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
