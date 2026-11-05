#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
# Use of this source code is governed by the Business Source License 1.1
# in the LICENSE file at the root of this repository; on its Change Date
# each version converts to the Mozilla Public License 2.0.
"""Require complete static documents and deliberate legacy capacity refusals."""

import argparse
import json
from pathlib import Path
import subprocess

from ci_tag_consumer_proof import classify, report_regression_failed_on_assertion

PACKAGE = "github.com/ctlplne/probectl/internal/control"
ROOT = "TestStaticReportKeepsCompleteValidatedMultilingualDocument"
ROOTS = (
    ROOT,
    "TestStaticSemanticReaderRejoinsPagesWithoutDroppingDocumentText",
    "TestStaticReportProfileCarriesOperatorCapacityAndCallerCancellation",
    "TestDashboardReportRendererStagesOwnedCompleteInlineBodies",
)
PATH = "internal/control/dashboard_report_static.go"
SEAM = "render.Bytes, render.MemoryBytes = limits.Bytes, profile.budget.MemoryBytes/2"
CONTROLS = (
    "render.Bytes, render.MemoryBytes = min(limits.Bytes, 2<<20), profile.budget.MemoryBytes/2",
    "render.Bytes, render.MemoryBytes = limits.Bytes, min(profile.budget.MemoryBytes/2, 128<<20)",
)
MARKER = "static renderer refused complete validated document"


def selftest():
    def encode(rows):
        return "\n".join(json.dumps(row) for row in rows)

    events = [
        {"Package": PACKAGE, "Test": root, "Action": action}
        for root in ROOTS
        for action in ("run", "pass")
    ] + [{"Package": PACKAGE, "Action": "pass"}]
    assert not classify(encode(events), 0, package=PACKAGE, tests=ROOTS)
    for root in ROOTS:
        assert classify(
            encode([row for row in events if row.get("Test") != root]),
            0,
            package=PACKAGE,
            tests=ROOTS,
        )
        assert classify(
            encode(events + [{"Package": PACKAGE, "Test": root, "Action": "skip"}]),
            0,
            package=PACKAGE,
            tests=ROOTS,
        )
    failed = [
        {"Package": PACKAGE, "Test": ROOT, "Action": "run"},
        {"Package": PACKAGE, "Test": ROOT, "Action": "output", "Output": MARKER},
        {"Package": PACKAGE, "Test": ROOT, "Action": "fail"},
        {"Package": PACKAGE, "Action": "fail"},
    ]
    args = dict(root=ROOT, marker=MARKER, package=PACKAGE, child="")
    assert report_regression_failed_on_assertion(encode(failed), 1, **args)
    assert not report_regression_failed_on_assertion("compiler failed", 1, **args)
    assert not report_regression_failed_on_assertion(encode(failed), 0, **args)
    for action in ("skip", "pass"):
        assert not report_regression_failed_on_assertion(
            encode(failed + [{"Package": PACKAGE, "Test": ROOT, "Action": action}]),
            1,
            **args,
        )
    print("Complete static report classifier selftest PASS")


def execute(roots, log):
    result = subprocess.run(
        [
            "go",
            "test",
            "-json",
            "-count=1",
            "-run",
            "^(" + "|".join(roots) + ")$",
            "./internal/control",
        ],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=300,
        check=False,
    )
    log.write_text(result.stdout)
    print(result.stdout, end="")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--selftest", action="store_true")
    args = parser.parse_args()
    if args.selftest:
        selftest()
        return 0
    out = Path("artifacts/static-report-capacity")
    out.mkdir(parents=True, exist_ok=True)
    result = execute(ROOTS, out / "complete.jsonl")
    failed = classify(result.stdout, result.returncode, package=PACKAGE, tests=ROOTS)
    if failed:
        raise RuntimeError("complete static capacity proof failed: " + repr(failed))
    path = Path(PATH)
    original = path.read_bytes()
    if original.decode().count(SEAM) != 2:
        raise RuntimeError("static render capacity seam changed")
    for index, replacement in enumerate(CONTROLS):
        try:
            path.write_text(original.decode().replace(SEAM, replacement))
            result = execute((ROOT,), out / f"legacy-capacity-{index}.jsonl")
            if not report_regression_failed_on_assertion(
                result.stdout,
                result.returncode,
                root=ROOT,
                marker=MARKER,
                package=PACKAGE,
                child="",
            ):
                raise RuntimeError(
                    "legacy static capacity did not fail the intended complete document assertion"
                )
        finally:
            path.write_bytes(original)
    print("Complete static documents and both original capacity refusals PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
