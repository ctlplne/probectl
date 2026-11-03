#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
# Use of this source code is governed by the Business Source License 1.1
# in the LICENSE file at the root of this repository; on its Change Date
# each version converts to the Mozilla Public License 2.0.

"""Require the original context-policy reproduction on a clean fixed baseline.

Current isolation tests must pass separately. A build/setup/cleanup failure is
never accepted as the original disclosure. Raw test output stays private.
"""

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

BASE = "4d859f59144ecebe41cf1286cde0a52bc6da6e20"
TEST = "TestFlowTagsRespectCurrentContextPolicy"
PACKAGE = "github.com/ctlplne/probectl/internal/control"
FILE = Path("internal/control/explorer_flow_tag_policy_integration_test.go")
MARKER = "context tag value disclosed after an explicit deny"
ROOT = Path(__file__).resolve().parents[1]


def reproduced(code: int, raw: str) -> bool:
    events = []
    for line in raw.splitlines():
        try:
            value = json.loads(line)
        except ValueError:
            continue
        if isinstance(value, dict):
            events.append(value)
    failed = [
        item.get("Test")
        for item in events
        if item.get("Action") == "fail" and item.get("Test")
    ]
    output = "".join(
        item.get("Output", "")
        for item in events
        if item.get("Test") == TEST and isinstance(item.get("Output", ""), str)
    )
    return (
        code == 1
        and failed == [TEST]
        and MARKER in output
        and "panic:" not in raw
        and "clean policy fixture:" not in raw
        and any(
            item.get("Action") == "run"
            and item.get("Test") == TEST
            and item.get("Package") == PACKAGE
            for item in events
        )
    )


def command(args: list[str], cwd: Path) -> str:
    result = subprocess.run(args, cwd=cwd, capture_output=True, text=True, timeout=120)
    if result.returncode:
        raise RuntimeError("original context regression checkout failed")
    return result.stdout.strip()


def run() -> None:
    if os.environ.get("GITHUB_ACTIONS") != "true":
        raise RuntimeError("original context regression runs only in CI")
    path = Path(tempfile.mkdtemp(prefix="probectl-qa-beta-tag-policy-original-"))
    attached = False
    try:
        command(["git", "fetch", "--no-tags", "--depth=1", "origin", BASE], ROOT)
        command(["git", "worktree", "add", "--detach", str(path), BASE], ROOT)
        attached = True
        if command(["git", "rev-parse", "HEAD"], path) != BASE or command(
            ["git", "status", "--porcelain"], path
        ):
            raise RuntimeError("original context regression baseline was not clean")
        shutil.copyfile(ROOT / FILE, path / FILE)
        with tempfile.TemporaryFile(mode="w+") as log:
            result = subprocess.run(
                [
                    "go",
                    "test",
                    "-json",
                    "-tags=isolation",
                    "-count=1",
                    "-timeout=3m",
                    "-run",
                    "^" + TEST + "$",
                    "./internal/control",
                ],
                cwd=path,
                stdout=log,
                stderr=subprocess.STDOUT,
                timeout=360,
            )
            log.seek(0)
            raw = log.read((4 << 20) + 1)
        if len(raw.encode()) > 4 << 20 or not reproduced(result.returncode, raw):
            raise RuntimeError("original context disclosure did not reproduce exactly")
        print("Original context-policy disclosure reproduced on clean " + BASE)
    finally:
        if attached:
            command(["git", "worktree", "remove", "--force", str(path)], ROOT)
        shutil.rmtree(path, ignore_errors=True)


def selftest() -> None:
    events = [
        {"Action": "run", "Package": PACKAGE, "Test": TEST},
        {"Action": "output", "Test": TEST, "Output": MARKER},
        {"Action": "fail", "Test": TEST},
    ]
    raw = "\n".join(json.dumps(event) for event in events)
    if not reproduced(1, raw):
        raise RuntimeError("original regression classifier lost its expected failure")
    for code, output in [
        (0, raw),
        (2, raw),
        (1, "build failed"),
        (1, raw.replace(MARKER, "setup failed")),
        (1, raw.replace(PACKAGE, "other")),
        (1, raw + "\npanic: planted failure"),
        (1, raw + "\nclean policy fixture: planted failure"),
        (1, raw + '\n{"Action":"fail","Test":"AnotherTest"}'),
    ]:
        if reproduced(code, output):
            raise RuntimeError("original regression accepted an unrelated failure")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--selftest", action="store_true")
    args = parser.parse_args()
    if args.selftest:
        selftest()
    else:
        run()
