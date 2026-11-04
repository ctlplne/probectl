#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
# Use of this source code is governed by the Business Source License 1.1
# in the LICENSE file at the root of this repository; on its Change Date
# each version converts to the Mozilla Public License 2.0.
"""Require complete SNMP prefix component proofs and a packet-error control."""

import argparse
import json
from pathlib import Path
import subprocess
import sys

from ci_tag_consumer_proof import classify, report_regression_failed_on_assertion

PACKAGE = "github.com/ctlplne/probectl/internal/device"
TESTS = (
    "TestSNMPInterfacePrefixDecodesExactStandardIndicesAndTruth",
    "TestSNMPInterfacePrefixRejectsMalformedRowsWithoutPartialIdentity",
    "TestSNMPInterfacePrefixSnapshotRetainsCompleteOrderedProtocolData",
    "TestSNMPInterfacePrefixSnapshotRefusesIncompleteOrOverBudgetWalk",
    "TestSNMPInterfacePrefixSnapshotCancellationReturnsNoPartialTable",
    "TestSNMPInterfacePrefixPacketsRequireProtocolCompletion",
    "TestSNMPInterfacePrefixPacketsRejectErrorsAfterPositiveRows",
    "TestSNMPInterfacePrefixPacketsPreserveCancellationAndCallbackRefusal",
    "TestSNMPPrefixOIDFollowsNumericCanonicalOrder",
)
ROOT = "TestSNMPInterfacePrefixPacketsRejectErrorsAfterPositiveRows"
CHILD = "packet-generr"
MARKER = "late protocol failure became successful prefix completion"


def encode(events):
    return "\n".join(json.dumps(event) for event in events)


def selftest() -> None:
    events = [
        {"Package": PACKAGE, "Test": root, "Action": action}
        for root in TESTS
        for action in ("run", "pass")
    ] + [{"Package": PACKAGE, "Action": "pass"}]
    assert not classify(encode(events), 0, package=PACKAGE, tests=TESTS)
    for root in TESTS:
        missing = [event for event in events if event.get("Test") != root]
        assert classify(encode(missing), 0, package=PACKAGE, tests=TESTS)
        for action in ("skip", "fail", "pass"):
            extra = events + [{"Package": PACKAGE, "Test": root, "Action": action}]
            assert classify(encode(extra), 0, package=PACKAGE, tests=TESTS)
    assert classify("", 0, package=PACKAGE, tests=TESTS)
    assert classify(encode(events), 1, package=PACKAGE, tests=TESTS)
    control = [
        {"Package": PACKAGE, "Test": ROOT, "Action": "run"},
        {"Package": PACKAGE, "Test": ROOT + "/" + CHILD, "Action": "run"},
        {
            "Package": PACKAGE,
            "Test": ROOT + "/" + CHILD,
            "Action": "output",
            "Output": MARKER,
        },
        {"Package": PACKAGE, "Test": ROOT + "/" + CHILD, "Action": "fail"},
        {"Package": PACKAGE, "Test": ROOT, "Action": "fail"},
        {"Package": PACKAGE, "Action": "fail"},
    ]

    def exact(values, code):
        return report_regression_failed_on_assertion(
            encode(values), code, root=ROOT, marker=MARKER, package=PACKAGE, child=CHILD
        )

    assert exact(control, 1)
    for bad, code in ((control, 0), (control[1:], 1), (control[:2] + control[3:], 1)):
        assert not exact(bad, code)
    assert not exact([{"Package": PACKAGE, "Action": "build-fail"}], 1)
    print(
        "Prefix proof classifier refuses missing, duplicate, skipped and false assertion proof"
    )


def run_tests(pattern: str) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        [
            "go",
            "test",
            "-race",
            "-count=1",
            "-timeout=3m",
            "-json",
            "-run",
            pattern,
            "./internal/device",
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
    # Positive prerequisites must run before the deliberately broken packet guard.
    current = run_tests("^(" + "|".join(TESTS) + ")$")
    failures = classify(
        current.stdout, current.returncode, package=PACKAGE, tests=TESTS
    )
    if failures:
        raise RuntimeError(
            "mandatory prefix component proofs did not pass: " + repr(failures)
        )
    source = Path("internal/device/snmp_interface_prefix_walk.go")
    original = source.read_text()
    seam = "packet.Error != gosnmp.NoError || "
    if original.count(seam) != 1:
        raise RuntimeError("prefix packet-error assertion seam unavailable")
    subprocess.run(["git", "diff", "--quiet", "--", str(source)], check=True)
    try:
        source.write_text(original.replace(seam, ""))
        broken = run_tests("^" + ROOT + "$/^" + CHILD + "$")
    finally:
        source.write_text(original)
    if not report_regression_failed_on_assertion(
        broken.stdout,
        broken.returncode,
        root=ROOT,
        marker=MARKER,
        package=PACKAGE,
        child=CHILD,
    ):
        raise RuntimeError(
            "omitted packet status did not fail its exact late-error assertion"
        )
    print(
        json.dumps(
            {
                "kind": "simulation",
                "tests": TESTS,
                "packet_error_assertion_control": True,
                "passed": True,
                "scope": "protocol fixtures only; no sender, registry or real router acceptance",
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
