#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
#
# Use of this source code is governed by the Business Source License 1.1
# in the LICENSE file at the root of this repository; on its Change Date
# each version converts to the Mozilla Public License 2.0.

"""Require scoped report-source batch cost proofs and an assertion control."""

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys

from ci_tag_consumer_proof import classify, report_regression_failed_on_assertion

PACKAGE = "github.com/ctlplne/probectl/internal/store/flowstore"
TESTS = (
    "TestExplorerPlanBatchSharesTenantReadAndExecutionEnvelope",
    "TestExplorerPlanBatchRefusesScopeMissingPolicyAndCancellation",
    "TestExplorerPlanBatchTLSChargesEveryResponseAndRejectsMissingReceipts",
    "TestExplorerPlanBatchSummaryAndResponseBounds",
    "TestExplorerClickHouseRealPlanBatchCostAndTenantBoundary",
)
MARKER = "repeated source plan received a fresh read allowance"


def selftest() -> None:
    events = [
        {"Package": PACKAGE, "Test": test, "Action": action}
        for test in TESTS
        for action in ("run", "pass")
    ] + [{"Package": PACKAGE, "Action": "pass"}]

    def encode(values):
        return "\n".join(json.dumps(value) for value in values)

    assert not classify(encode(events), 0, package=PACKAGE, tests=TESTS)
    for bad, code in (
        (events[2:], 0),
        (events + [events[1]], 0),
        (events, 1),
        ([{**e, "Action": "skip"} if i == 1 else e for i, e in enumerate(events)], 0),
    ):
        assert classify(encode(bad), code, package=PACKAGE, tests=TESTS)
    control = [
        {"Package": PACKAGE, "Test": name, "Action": action}
        for name, action in (
            (TESTS[0], "run"),
            (TESTS[0] + "/success", "run"),
            (TESTS[0] + "/success", "fail"),
            (TESTS[0], "fail"),
            ("", "fail"),
        )
    ]
    control.insert(
        2,
        {
            "Package": PACKAGE,
            "Test": TESTS[0] + "/success",
            "Action": "output",
            "Output": MARKER,
        },
    )
    assert report_regression_failed_on_assertion(
        encode(control), 1, root=TESTS[0], marker=MARKER, package=PACKAGE
    )
    for bad, code in ((control, 0), (control[1:], 1), (control[:2] + control[3:], 1)):
        assert not report_regression_failed_on_assertion(
            encode(bad), code, root=TESTS[0], marker=MARKER, package=PACKAGE
        )
    print(
        "Batch source classifier refuses missing, duplicate, skipped and false assertion proof"
    )


def run_tests(pattern: str) -> subprocess.CompletedProcess:
    result = subprocess.run(
        [
            "go",
            "test",
            "-race",
            "-tags=integration",
            "-count=1",
            "-timeout=5m",
            "-json",
            "-run",
            pattern,
            "./internal/store/flowstore",
        ],
        capture_output=True,
        text=True,
        timeout=360,
        check=False,
    )
    sys.stdout.write(result.stdout)
    sys.stderr.write(result.stderr)
    return result


def run() -> None:
    if (
        os.environ.get("GITHUB_ACTIONS") != "true"
        or os.environ.get("PROBECTL_TEST_REQUIRE_SERVICES") != "1"
        or not os.environ.get("PROBECTL_FLOWSTORE_URL")
    ):
        raise RuntimeError(
            "source batch proof requires the existing isolated CI services"
        )
    source = Path("internal/store/flowstore/explorer_memory.go")
    original = source.read_text()
    seam = "\t\tif err := chargeBatchRead(ctx, tenant, 1, int64(entryBytes)); err != nil {\n\t\t\treturn nil, err\n\t\t}"
    if original.count(seam) != 1:
        raise RuntimeError("source batch read-accounting seam unavailable")
    subprocess.run(["git", "diff", "--quiet", "--", str(source)], check=True)
    try:
        source.write_text(
            original.replace(
                seam, "\t\t// Assertion control: omit cumulative batch read accounting."
            )
        )
        result = run_tests("^" + TESTS[0] + "$/^success$")
    finally:
        source.write_text(original)
    if not report_regression_failed_on_assertion(
        result.stdout, result.returncode, root=TESTS[0], marker=MARKER, package=PACKAGE
    ):
        raise RuntimeError(
            "source batch control did not fail its exact cumulative-cost assertion"
        )
    current = run_tests("^(" + "|".join(TESTS) + ")$")
    failures = classify(
        current.stdout, current.returncode, package=PACKAGE, tests=TESTS
    )
    print(
        json.dumps(
            {
                "tests": TESTS,
                "assertion_control": True,
                "passed": not failures,
                "failures": failures,
            }
        )
    )
    if failures:
        raise RuntimeError("mandatory source batch proofs did not all execute and pass")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--selftest", action="store_true")
    if parser.parse_args().selftest:
        selftest()
    else:
        run()
