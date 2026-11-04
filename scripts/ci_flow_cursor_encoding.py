#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
# Use of this source code is governed by the Business Source License 1.1
# in the LICENSE file at the root of this repository; on its Change Date
# each version converts to the Mozilla Public License 2.0.
"""Require continuation codec success and the exact legacy-redaction control."""
from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path

PACKAGE = "github.com/ctlplne/probectl/internal/store/flowsnapshot"
ROOT = "TestSnapshotCursorEncodingSurvivesMandatoryRedaction"
ROOTS = (ROOT, "TestSnapshotCursorEncodingKeepsLegacyAndRealMACValidation")
MARKER = "opaque continuation changed under mandatory redaction"


def events(output: str) -> list[dict]:
    try:
        result = [json.loads(line) for line in output.splitlines()]
    except (ValueError, TypeError):
        return []
    if not result or any(not isinstance(row, dict) or row.get("Package") != PACKAGE for row in result):
        return []
    return result


def positive(output: str, code: int) -> bool:
    rows = events(output)
    if code or not rows or any(row.get("Action") in {"fail", "skip"} for row in rows):
        return False
    for root in ROOTS:
        for action in ("run", "pass"):
            if sum(row.get("Test") == root and row.get("Action") == action for row in rows) != 1:
                return False
    return sum(not row.get("Test") and row.get("Action") == "pass" for row in rows) == 1


def regression(output: str, code: int) -> bool:
    rows = events(output)
    if not code or not rows or any(row.get("Action") == "skip" for row in rows):
        return False
    for action in ("run", "fail"):
        if sum(row.get("Test") == ROOT and row.get("Action") == action for row in rows) != 1:
            return False
    return (
        not any(row.get("Action") == "pass" for row in rows)
        and sum(not row.get("Test") and row.get("Action") == "fail" for row in rows) == 1
        and any(row.get("Test") == ROOT and MARKER in row.get("Output", "") for row in rows)
    )


def selftest() -> None:
    def row(action: str, name: str = "") -> dict:
        return {"Package": PACKAGE, "Action": action, **({"Test": name} if name else {})}
    good = [row(action, root) for root in ROOTS for action in ("run", "pass")] + [row("pass")]
    def encode(rows: list[dict]) -> str:
        return "\n".join(json.dumps(item) for item in rows)
    assert positive(encode(good), 0)
    for bad in (good[:-1], good + [row("skip", ROOT)], good + [row("pass", ROOT)]):
        assert not positive(encode(bad), 0)
    bad = [row("run", ROOT), {**row("output", ROOT), "Output": MARKER}, row("fail", ROOT), row("fail")]
    assert regression(encode(bad), 1)
    assert not regression(encode(bad), 0)
    assert not regression("compiler failure", 1)
    assert not regression(encode(bad + [row("skip", ROOT)]), 1)
    assert not regression(encode([item for item in bad if item.get("Action") != "output"]), 1)
    print("Cursor proof rejects missing, duplicate, skipped and unrelated failure evidence")


def run(pattern: str, label: str) -> subprocess.CompletedProcess:
    result = subprocess.run(
        ["go", "test", "-json", "-count=1", "-timeout=120s", "-run", pattern, "./internal/store/flowsnapshot"],
        text=True, capture_output=True, timeout=180, check=False,
    )
    evidence = Path("artifacts/flow-cursor-encoding")
    evidence.mkdir(parents=True, exist_ok=True)
    (evidence / (label + ".jsonl")).write_text(result.stdout)
    (evidence / (label + ".stderr.txt")).write_text(result.stderr)
    print(result.stdout, end="")
    print(result.stderr, end="")
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--selftest", action="store_true")
    args = parser.parse_args()
    if args.selftest:
        selftest()
        return
    result = run("^(" + "|".join(ROOTS) + ")$", "positive")
    if not positive(result.stdout, result.returncode):
        raise RuntimeError("required cursor encoding/legacy/MAC proof did not execute and pass")
    source = Path("internal/store/flowsnapshot/cursor_encoding.go")
    original = source.read_text()
    seam = 'return cursorEncodingPrefix + encodeCursorPart(body) + "~" + encodeCursorPart(mac)'
    if original.count(seam) != 1:
        raise RuntimeError("cursor codec control seam missing")
    try:
        source.write_text(original.replace(
            seam,
            'return base64.RawURLEncoding.EncodeToString(body) + "." + base64.RawURLEncoding.EncodeToString(mac)',
        ))
        result = run("^" + ROOT + "$", "legacy-negative-control")
    finally:
        source.write_text(original)
    if not regression(result.stdout, result.returncode):
        raise RuntimeError("legacy encoding did not fail the exact mandatory-redaction assertion")
    print("Cursor codec positive and legacy-encoding negative control passed")


if __name__ == "__main__":
    main()
