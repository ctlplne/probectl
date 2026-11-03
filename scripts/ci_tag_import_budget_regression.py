#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
# Use of this source code is governed by the Business Source License 1.1
# in the LICENSE file at the root of this repository; on its Change Date
# each version converts to the Mozilla Public License 2.0.

"""Require the query-budget HTTP500 reproduction on its original baseline.

Current component regression must pass first. A build/setup/cleanup failure is
never accepted as the original bug. Two exact unused-import cleanups only make
the pinned original compile; they cannot alter query admission or error mapping.
This component proof opens no datastore. Raw test output stays private.
"""

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

BASE = "c41a63d8e0b2b360769d712433d2dfff4e68a250"
TEST = "TestNetBoxImportQueryBudgetUsesRateLimitedDomain"
PACKAGE = "github.com/ctlplne/probectl/internal/control"
FILE = Path("internal/control/tag_import_budget_test.go")
MARKER = "query-budget refusal became HTTP500 instead of429"
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
        and not any(
            marker in raw
            for marker in ("panic:", "build failed", "[setup failed]", "test timed out")
        )
        and "budget fixture:" not in raw
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
        raise RuntimeError("original query-budget regression checkout failed")
    return result.stdout.strip()


def execute(cwd: Path) -> tuple[int, str]:
    with tempfile.TemporaryFile(mode="w+") as log:
        result = subprocess.run(
            [
                "go",
                "test",
                "-json",
                "-tags=integration",
                "-count=1",
                "-timeout=3m",
                "-run",
                "^" + TEST + "$",
                "./internal/control",
            ],
            cwd=cwd,
            env={**os.environ, "GOWORK": "off"},
            stdout=log,
            stderr=subprocess.STDOUT,
            timeout=360,
        )
        log.seek(0)
        raw = log.read((4 << 20) + 1)
    if len(raw.encode()) > 4 << 20:
        raise RuntimeError("query-budget regression output exceeded its bound")
    return result.returncode, raw


def current_passed(code: int, raw: str) -> bool:
    events = []
    for line in raw.splitlines():
        try:
            item = json.loads(line)
        except ValueError:
            continue
        if isinstance(item, dict):
            events.append(item)
    return (
        code == 0
        and any(
            item.get("Action") == "pass"
            and item.get("Test") == TEST
            and item.get("Package") == PACKAGE
            for item in events
        )
        and not any(item.get("Action") in {"fail", "skip"} for item in events)
    )


def repair_baseline_imports(path: Path) -> None:
    """Remove only the two compiler-diagnosed imports, never behavior."""
    for relative, token in [
        ("internal/control/tag_import.go", '\n\t"context"'),
        (
            "internal/control/mcp_tag_netbox.go",
            '\n\t"github.com/ctlplne/probectl/internal/store"',
        ),
    ]:
        source = path / relative
        text = source.read_text()
        if text.count(token) != 1:
            raise RuntimeError("pinned baseline compiler prerequisite changed")
        source.write_text(text.replace(token, "", 1))


def run() -> None:
    if os.environ.get("GITHUB_ACTIONS") != "true":
        raise RuntimeError("original query-budget regression runs only in CI")
    code, raw = execute(ROOT)
    if not current_passed(code, raw):
        raise RuntimeError("current query-budget regression did not pass without skips")
    print("Current query-budget rate-limit regression passed")
    path = Path(tempfile.mkdtemp(prefix="probectl-qa-beta-tag-budget-original-"))
    attached = False
    try:
        command(["git", "fetch", "--no-tags", "--depth=1", "origin", BASE], ROOT)
        command(["git", "worktree", "add", "--detach", str(path), BASE], ROOT)
        attached = True
        if command(["git", "rev-parse", "HEAD"], path) != BASE or command(
            ["git", "status", "--porcelain"], path
        ):
            raise RuntimeError(
                "original query-budget regression baseline was not clean"
            )
        repair_baseline_imports(path)
        shutil.copyfile(ROOT / FILE, path / FILE)
        code, raw = execute(path)
        if not reproduced(code, raw):
            raise RuntimeError(
                "original query-budget HTTP500 did not reproduce exactly"
            )
        print(
            "Original query-budget HTTP500 reproduced on pinned baseline with compiler-only prerequisites "
            + BASE
        )
    finally:
        if attached:
            command(["git", "worktree", "remove", "--force", str(path)], ROOT)
        shutil.rmtree(path, ignore_errors=True)


def selftest() -> None:
    with tempfile.TemporaryDirectory(
        prefix="probectl-qa-beta-budget-imports-selftest-"
    ) as temporary:
        baseline = Path(temporary)
        first = baseline / "internal/control/tag_import.go"
        second = baseline / "internal/control/mcp_tag_netbox.go"
        first.parent.mkdir(parents=True)
        first.write_text(
            'package control\nimport (\n\t"context"\n\t"errors"\n)\n// body retained\n'
        )
        second.write_text(
            'package control\nimport (\n\t"github.com/ctlplne/probectl/internal/store"\n)\n// body retained\n'
        )
        repair_baseline_imports(baseline)
        if (
            first.read_text()
            != 'package control\nimport (\n\t"errors"\n)\n// body retained\n'
            or second.read_text() != "package control\nimport (\n)\n// body retained\n"
        ):
            raise RuntimeError("compiler prerequisite changed baseline behavior")
        try:
            repair_baseline_imports(baseline)
        except RuntimeError:
            pass
        else:
            raise RuntimeError("changed baseline compiler prerequisite was accepted")
    passed = json.dumps({"Action": "pass", "Package": PACKAGE, "Test": TEST})
    if not current_passed(0, passed):
        raise RuntimeError("current regression classifier lost a test pass")
    for code, raw in [
        (1, passed),
        (0, "no tests"),
        (0, passed.replace(TEST, "Other")),
        (0, passed + '\n{"Action":"skip"}'),
        (0, passed + '\n{"Action":"fail"}'),
    ]:
        if current_passed(code, raw):
            raise RuntimeError(
                "current regression accepted absent, skipped or failing proof"
            )
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
        (1, raw + "\nbuild failed"),
        (1, raw + "\n[setup failed]"),
        (1, raw + "\ntest timed out"),
        (1, raw + "\nbudget fixture: planted failure"),
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
