#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
# Use of this source code is governed by the Business Source License 1.1
# in the LICENSE file at the root of this repository; on its Change Date
# each version converts to the Mozilla Public License 2.0.

"""Require one exact assertion on the original query vocabulary, after current pass.

The copied unit regression uses existing APIs. No baseline implementation,
compiler prerequisite, service, dependency or oracle is changed.
"""

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

BASE = "0fd0f52cbb14eaab20f49f17d6c81d3be856be62"
TEST = "TestSubjectTagNamespacesKeepOneDefinitionAndIndependentReadGrants"
PACKAGE = "github.com/ctlplne/probectl/internal/flow"
FILE = Path("internal/flow/query_vocabulary_test.go")
MARKER = "qualified tag field changed definition or subject"
ROOT = Path(__file__).resolve().parents[1]


def classified(code: int, raw: str, original: bool) -> bool:
    events = []
    for line in raw.splitlines():
        try:
            item = json.loads(line)
        except ValueError:
            continue
        if isinstance(item, dict):
            events.append(item)
    target = [
        item
        for item in events
        if item.get("Test") == TEST and item.get("Package") == PACKAGE
    ]
    if not any(item.get("Action") == "run" for item in target):
        return False
    if any(
        word in raw
        for word in ("panic:", "build failed", "[setup failed]", "test timed out")
    ):
        return False
    if any(item.get("Action") == "skip" for item in events):
        return False
    failures = [
        item.get("Test")
        for item in events
        if item.get("Action") == "fail" and item.get("Test")
    ]
    if original:
        return (
            code == 1
            and failures == [TEST]
            and any(item.get("Action") == "fail" for item in target)
            and any(
                item.get("Action") == "fail"
                and item.get("Package") == PACKAGE
                and not item.get("Test")
                for item in events
            )
            and all(
                item.get("Package") == PACKAGE
                for item in events
                if item.get("Action") == "fail"
            )
            and any(MARKER in item.get("Output", "") for item in target)
        )
    return (
        code == 0
        and not any(item.get("Action") == "fail" for item in events)
        and any(item.get("Action") == "pass" for item in target)
        and any(
            item.get("Action") == "pass"
            and item.get("Package") == PACKAGE
            and not item.get("Test")
            for item in events
        )
    )


def execute(cwd: Path) -> tuple[int, str]:
    with tempfile.TemporaryFile(mode="w+") as output:
        result = subprocess.run(
            [
                "go",
                "test",
                "-json",
                "-count=1",
                "-timeout=3m",
                "-run",
                "^" + TEST + "$",
                "./internal/flow",
            ],
            cwd=cwd,
            env={**os.environ, "GOWORK": "off"},
            stdout=output,
            stderr=subprocess.STDOUT,
            timeout=300,
        )
        output.seek(0)
        raw = output.read((4 << 20) + 1)
    if len(raw.encode()) > 4 << 20:
        raise RuntimeError("related tag regression output exceeded its bound")
    return result.returncode, raw


def git(args: list[str], cwd: Path) -> str:
    result = subprocess.run(
        ["git", *args], cwd=cwd, capture_output=True, text=True, timeout=120
    )
    if result.returncode:
        raise RuntimeError("related tag regression checkout or cleanup failed")
    return result.stdout.strip()


def run() -> None:
    if os.environ.get("GITHUB_ACTIONS") != "true":
        raise RuntimeError("original related tag proof runs only in CI")
    code, raw = execute(ROOT)
    if not classified(code, raw, False):
        raise RuntimeError("current related tag regression did not pass without skips")
    print("Current related tag vocabulary and read-grant regression passed")
    path = Path(tempfile.mkdtemp(prefix="probectl-qa-beta-related-tag-original-"))
    attached = False
    try:
        git(["fetch", "--no-tags", "--depth=1", "origin", BASE], ROOT)
        git(["worktree", "add", "--detach", str(path), BASE], ROOT)
        attached = True
        if git(["rev-parse", "HEAD"], path) != BASE or git(
            ["status", "--porcelain"], path
        ):
            raise RuntimeError("related tag original baseline was not clean")
        shutil.copyfile(ROOT / FILE, path / FILE)
        code, raw = execute(path)
        if not classified(code, raw, True):
            raise RuntimeError(
                "original related tag vocabulary assertion did not reproduce"
            )
        print("Original related tag vocabulary assertion reproduced on " + BASE)
    finally:
        if attached:
            git(["worktree", "remove", "--force", str(path)], ROOT)
        shutil.rmtree(path, ignore_errors=True)


def selftest() -> None:
    events = [
        {"Action": "run", "Package": PACKAGE, "Test": TEST},
        {"Action": "output", "Package": PACKAGE, "Test": TEST, "Output": MARKER},
        {"Action": "fail", "Package": PACKAGE, "Test": TEST},
        {"Action": "fail", "Package": PACKAGE},
    ]
    raw = "\n".join(json.dumps(item) for item in events)
    passed = raw.replace('"Action": "fail"', '"Action": "pass"')
    if not classified(1, raw, True) or not classified(0, passed, False):
        raise RuntimeError("related tag classifier refused exact proof")
    for code, changed in [
        (0, raw),
        (2, raw),
        (1, raw.replace(MARKER, "other assertion")),
        (1, raw.replace(TEST, "AnotherTest")),
        (1, raw + "panic:"),
        (1, raw + "build failed"),
        (1, raw + "test timed out"),
        (1, raw + '\n{"Action":"skip"}'),
        (1, raw + '\n{"Action":"fail","Test":"Other"}'),
    ]:
        if classified(code, changed, True):
            raise RuntimeError("related tag classifier accepted invalid original proof")
    for changed in [
        "",
        passed.replace(TEST, "AnotherTest"),
        passed + '\n{"Action":"skip"}',
        passed + '\n{"Action":"fail"}',
        passed.replace('"Action": "run"', '"Action": "output"'),
    ]:
        if classified(0, changed, False):
            raise RuntimeError(
                "related tag classifier accepted absent or failing current proof"
            )
    print("Related tag current/original classifiers passed")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--selftest", action="store_true")
    parser.add_argument("--interfaces", action="store_true")
    args = parser.parse_args()
    if args.interfaces:
        BASE = "9c626335df1bc6f48eb1fb6951a81d0a2fbda198"
        TEST = "TestInterfaceTagVocabularyRequiresOwnedIndexInputs"
        MARKER = "input/output interface tag field is unavailable"

    selftest() if args.selftest else run()
