#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
# Use of this source code is governed by the Business Source License 1.1
# in the LICENSE file at the root of this repository; on its Change Date
# each version converts to the Mozilla Public License 2.0.
"""Require real-PG targetless test isolation and its original refusal control."""

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys

from ci_tag_consumer_proof import classify, report_regression_failed_on_assertion

PACKAGE = "github.com/ctlplne/probectl/internal/store"
ROOT = "TestTargetlessNoopTagContextIsolationKeepsPathAuthorityAbsent"
MARKER = "owned targetless noop context was refused"


def encode(events):
    return "\n".join(json.dumps(value) for value in events)


def selftest() -> None:
    events = [
        {"Package": PACKAGE, "Test": ROOT, "Action": action}
        for action in ("run", "pass")
    ]
    events.append({"Package": PACKAGE, "Action": "pass"})
    assert not classify(encode(events), 0, package=PACKAGE, tests=(ROOT,))
    for bad in (
        events[1:],
        events + events,
        events + [{"Package": PACKAGE, "Test": ROOT, "Action": "skip"}],
    ):
        assert classify(encode(bad), 0, package=PACKAGE, tests=(ROOT,))
    control = [
        {"Package": PACKAGE, "Test": ROOT, "Action": "run"},
        {"Package": PACKAGE, "Test": ROOT + "/success", "Action": "run"},
        {
            "Package": PACKAGE,
            "Test": ROOT + "/success",
            "Action": "output",
            "Output": MARKER,
        },
        {"Package": PACKAGE, "Test": ROOT + "/success", "Action": "fail"},
        {"Package": PACKAGE, "Test": ROOT, "Action": "fail"},
        {"Package": PACKAGE, "Action": "fail"},
    ]
    assert report_regression_failed_on_assertion(
        encode(control), 1, root=ROOT, marker=MARKER, package=PACKAGE
    )
    for bad, code in ((control, 0), (control[1:], 1), (control[:2] + control[3:], 1)):
        assert not report_regression_failed_on_assertion(
            encode(bad), code, root=ROOT, marker=MARKER, package=PACKAGE
        )
    print(
        "Targetless test classifier refuses missing, skipped, duplicate and false assertion evidence"
    )


def run_test(pattern):
    result = subprocess.run(
        [
            "go",
            "test",
            "-race",
            "-tags=integration",
            "-count=1",
            "-timeout=3m",
            "-json",
            "-run",
            pattern,
            "./internal/store",
        ],
        capture_output=True,
        text=True,
        timeout=240,
        check=False,
    )
    sys.stdout.write(result.stdout)
    sys.stderr.write(result.stderr)
    return result


def run() -> None:
    if os.environ.get("PROBECTL_TEST_REQUIRE_SERVICES") != "1":
        raise RuntimeError(
            "targetless test proof requires real services, without skips"
        )
    current = run_test("^" + ROOT + "$")
    failures = classify(
        current.stdout, current.returncode, package=PACKAGE, tests=(ROOT,)
    )
    if failures:
        raise RuntimeError(
            "targetless test isolation root did not execute and pass: " + repr(failures)
        )
    source = Path("internal/store/entityregistry_path.go")
    original = source.read_text()
    seam = 'withoutPath := testType == "noop" && testTarget == ""'
    if original.count(seam) != 1:
        raise RuntimeError("targetless test original-refusal seam unavailable")
    subprocess.run(["git", "diff", "--quiet", "--", str(source)], check=True)
    try:
        source.write_text(original.replace(seam, seam + " && false"))
        broken = run_test("^" + ROOT + "$/^success$")
    finally:
        source.write_text(original)
    if not report_regression_failed_on_assertion(
        broken.stdout, broken.returncode, root=ROOT, marker=MARKER, package=PACKAGE
    ):
        raise RuntimeError(
            "original targetless refusal did not fail its exact positive binding assertion"
        )
    print(
        json.dumps(
            {
                "kind": "real-integration",
                "tests": [ROOT],
                "original_refusal_assertion_control": True,
                "passed": True,
                "scope": "real PostgreSQL store/isolation component; release surface proof remains separate",
            }
        )
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--selftest", action="store_true")
    if parser.parse_args().selftest:
        selftest()
    else:
        run()
