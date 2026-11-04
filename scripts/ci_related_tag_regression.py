#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
# Use of this source code is governed by the Business Source License 1.1
# in the LICENSE file at the root of this repository; on its Change Date
# each version converts to the Mozilla Public License 2.0.

"""Require one exact original tag assertion after a current pass.

The copied regression uses existing APIs. No baseline implementation,
compiler prerequisite, service, dependency or oracle is changed.
"""

import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

BASE = "0fd0f52cbb14eaab20f49f17d6c81d3be856be62"
TEST = "TestSubjectTagNamespacesKeepOneDefinitionAndIndependentReadGrants"
PACKAGE = "github.com/ctlplne/probectl/internal/flow"
GO_PACKAGE = "./internal/flow"
GO_EXTRA: list[str] = []
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
    if any(
        cue in raw
        for cue in (
            "remove tag Explorer tenants:",
            "tenant fixture cleanup incomplete:",
        )
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
    # Cold compilation has a separate bound. It is never accepted as a test
    # receipt, and the runtime command and timeout below remain unchanged.
    with tempfile.TemporaryDirectory(prefix="probectl-qa-beta-tag-compile-") as build:
        with tempfile.TemporaryFile(mode="w+") as output:
            try:
                compiled = subprocess.run(
                    [
                        "go",
                        "test",
                        *GO_EXTRA,
                        "-c",
                        "-o",
                        str(Path(build) / "proof.test"),
                        GO_PACKAGE,
                    ],
                    cwd=cwd,
                    env={**os.environ, "GOWORK": "off"},
                    stdout=output,
                    stderr=subprocess.STDOUT,
                    timeout=600,
                )
            except subprocess.TimeoutExpired:
                raise RuntimeError(
                    "related tag regression compile phase exceeded 600s"
                ) from None
            if compiled.returncode:
                raise RuntimeError(
                    "related tag regression compile phase failed: exit_code="
                    + str(compiled.returncode)
                )
    print("Related tag regression compile phase passed", flush=True)
    with tempfile.TemporaryFile(mode="w+") as output:
        timed_out = False
        try:
            result = subprocess.run(
                [
                    "go",
                    "test",
                    *GO_EXTRA,
                    "-json",
                    "-count=1",
                    "-timeout=3m",
                    "-run",
                    "^" + TEST + "$",
                    GO_PACKAGE,
                ],
                cwd=cwd,
                env={**os.environ, "GOWORK": "off"},
                stdout=output,
                stderr=subprocess.STDOUT,
                timeout=300,
            )
        except subprocess.TimeoutExpired:
            timed_out = True
        output.seek(0)
        raw = output.read((4 << 20) + 1)
    if len(raw.encode()) > 4 << 20:
        raise RuntimeError("related tag regression output exceeded its bound")
    if timed_out:
        raise RuntimeError(
            "related tag regression runtime phase exceeded 300s: "
            + diagnostic(124, raw)
        )
    return result.returncode, raw


def diagnostic(code: int, raw: str) -> str:
    """Expose only bounded flags, counts and this copied test's line numbers."""
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
    outputs = "\n".join(
        item["Output"] for item in events if isinstance(item.get("Output"), str)
    )
    locations = sorted(
        {
            int(line)
            for line in re.findall(re.escape(FILE.name) + r":([0-9]{1,6}):", outputs)
        }
    )
    store_codes = sorted(
        {int(value) for value in re.findall(r"\(code ([0-9]{1,6})\)", outputs)}
    )
    return json.dumps(
        {
            "exit_code": code,
            "target_run": any(item.get("Action") == "run" for item in target),
            "target_pass": any(item.get("Action") == "pass" for item in target),
            "target_fail": any(item.get("Action") == "fail" for item in target),
            "skip_count": sum(item.get("Action") == "skip" for item in events),
            "package_fail_count": sum(
                item.get("Action") == "fail" and not item.get("Test") for item in events
            ),
            "expected_assertion": any(
                MARKER in item.get("Output", "") for item in target
            ),
            "copied_test_lines": locations[:16],
            "store_codes": store_codes[:16],
            "build_failure": "build failed" in raw or "[setup failed]" in raw,
            "panic": "panic:" in raw,
            "timeout": "test timed out" in raw,
        },
        sort_keys=True,
    )


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
        raise RuntimeError(
            "current related tag regression did not pass without skips: "
            + diagnostic(code, raw)
        )
    print("Current tag regression passed")
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
                + ": "
                + diagnostic(code, raw)
            )
        print("Original tag assertion reproduced on " + BASE)
    finally:
        if attached:
            git(["worktree", "remove", "--force", str(path)], ROOT)
        shutil.rmtree(path, ignore_errors=True)


def selftest() -> None:
    from unittest.mock import patch

    events = [
        {"Action": "run", "Package": PACKAGE, "Test": TEST},
        {"Action": "output", "Package": PACKAGE, "Test": TEST, "Output": MARKER},
        {"Action": "fail", "Package": PACKAGE, "Test": TEST},
        {"Action": "fail", "Package": PACKAGE},
    ]
    raw = "\n".join(json.dumps(item) for item in events)
    passed = raw.replace('"Action": "fail"', '"Action": "pass"')
    private = "postgresql://untrusted-credential/tenant-secret?tag=private-value"
    noisy = (
        raw
        + "\n"
        + json.dumps(
            {
                "Action": "output",
                "Package": PACKAGE,
                "Test": TEST,
                "Output": f"{FILE.name}:73: {private} flow query store status 400 (code 47)",
            }
        )
    )
    summary = diagnostic(1, noisy)
    safe = json.loads(summary)
    if (
        private in summary
        or "credential" in summary
        or "private-value" in summary
        or safe["copied_test_lines"] != [73]
        or safe["store_codes"] != [47]
        or not safe["target_fail"]
    ):
        raise RuntimeError(
            "related tag diagnostic leaked text or lost safe failure evidence"
        )
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
        (1, raw + "tenant fixture cleanup incomplete:"),
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
    # Even a partial passing event stream must fail on either phase timeout,
    # while arbitrary captured output remains private. Never launch Go here.
    for phase in ("compile", "runtime"):
        calls = 0

        def interrupted(
            command: list[str], **kwargs: object
        ) -> subprocess.CompletedProcess:
            nonlocal calls
            calls += 1
            if phase == "compile" or calls == 2:
                kwargs["stdout"].write(passed + "\n" + private)
                raise subprocess.TimeoutExpired(command, kwargs["timeout"])
            return subprocess.CompletedProcess(command, 0)

        with (
            patch("subprocess.run", side_effect=interrupted),
            patch("builtins.print"),
        ):
            try:
                execute(ROOT)
            except RuntimeError as error:
                message = str(error)
                if phase + " phase exceeded" not in message or private in message:
                    raise RuntimeError(
                        "phase timeout lost its safe diagnostic"
                    ) from None
            else:
                raise RuntimeError("phase timeout accepted partial passing evidence")
    print("Related tag current/original classifiers passed")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--selftest", action="store_true")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--interfaces", action="store_true")
    mode.add_argument("--rollup-snapshot", action="store_true")
    mode.add_argument("--tag-actor", action="store_true")
    mode.add_argument("--tag-output", action="store_true")
    mode.add_argument("--canonical-address", action="store_true")
    mode.add_argument("--prefixes", action="store_true")
    args = parser.parse_args()
    if args.interfaces:
        BASE = "9c626335df1bc6f48eb1fb6951a81d0a2fbda198"
        TEST = "TestInterfaceTagVocabularyRequiresOwnedIndexInputs"
        MARKER = "input/output interface tag field is unavailable"
    if args.rollup_snapshot:
        BASE = "9c626335df1bc6f48eb1fb6951a81d0a2fbda198"
        TEST = "TestTagRollupSnapshotUsesActualCompleteInputs"
        PACKAGE = "github.com/ctlplne/probectl/internal/store/flowstore"
        GO_PACKAGE = "./internal/store/flowstore"
        FILE = Path("internal/store/flowstore/tag_rollup_snapshot_test.go")
        MARKER = "complete retained tag rollup was refused by frozen source receipt"

    if args.tag_actor:
        BASE = "9c626335df1bc6f48eb1fb6951a81d0a2fbda198"
        TEST = "TestExplorerTagRuleRetagsHistoryAcrossTenantRESTBoundary"
        PACKAGE = "github.com/ctlplne/probectl/internal/control"
        GO_PACKAGE = "./internal/control"
        GO_EXTRA = ["-tags=integration"]
        FILE = Path("internal/control/explorer_flow_tags_integration_test.go")
        MARKER = "authorized minimum-grant frozen page lost its current policy"
    if args.tag_output:
        BASE = "7d9b3caeb397051b686f4c48e5c0babd4414ecd5"
        TEST = "TestExplorerRelatedTagsUseCurrentOwnedSubjectsAndReadGrants"
        PACKAGE = "github.com/ctlplne/probectl/internal/control"
        GO_PACKAGE = "./internal/control"
        GO_EXTRA = ["-tags=integration"]
        FILE = Path("internal/control/explorer_flow_related_tags_integration_test.go")
        MARKER = "authorized related tag output was rejected by static projection"
    if args.prefixes:
        BASE = "c267edbb37b00c0908d6b6dfab98f2af63f3cffa"
        TEST = "TestPrefixTagVocabularyKeepsIndependentSidesAndOwnedInputs"
        FILE = Path("internal/flow/query_prefix_vocabulary_test.go")
        MARKER = "source/destination prefix field is unavailable"
    if args.canonical_address:
        BASE = "b687019259f8efb824cd71cc5c5fc3568a7c633e"
        TEST = "TestExplorerClickHouseCanonicalAddressesRetainValidIPv6"
        PACKAGE = "github.com/ctlplne/probectl/internal/store/flowstore"
        GO_PACKAGE = "./internal/store/flowstore"
        GO_EXTRA = ["-tags=integration"]
        FILE = Path(
            "internal/store/flowstore/explorer_address_canonical_integration_test.go"
        )
        MARKER = "canonical address query lost valid owned input"
    selftest() if args.selftest else run()
