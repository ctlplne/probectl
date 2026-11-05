#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
# Use of this source code is governed by the Business Source License 1.1
# in the LICENSE file at the root of this repository; on its Change Date
# each version converts to the Mozilla Public License 2.0.
"""Require complete selected rows and original quota countercontrols."""

import argparse
import json
from pathlib import Path
import re
import subprocess

from ci_tag_consumer_proof import classify, report_regression_failed_on_assertion

PREFIX = "github.com/ctlplne/probectl/"
UNIT = (
    (
        "internal/flow",
        ("TestSelectedDetailReachUsesRepresentationRatherThanFormerQuota",),
    ),
    (
        "internal/store/flowstore",
        ("TestExplorerCompleteSelectedRowsPastFormerQuotaKeepTenantTotals",),
    ),
    (
        "internal/store/flowsnapshot",
        ("TestSnapshotsCompleteRowsPastFormerQuotaStayPrivateAcrossReplicas",),
    ),
    (
        "internal/control",
        (
            "TestExplorerCLIExpandedPlanAndFiltersOverPairedTLSAPI",
            "TestNativeMCPQueriesAndLibrariesUseAuthenticatedTenantAndOwner",
            "TestFlowQuestionCompositionKeepsBuiltinAndOperatorResources",
            "TestFlowQuestionStatelessProductionBuiltinAndSafeFailures",
        ),
    ),
)
INTEGRATION = (
    (
        "internal/store/flowstore",
        ("TestExplorerClickHouseCompleteRowsPastFormerQuotaKeepTenantTotals",),
    ),
    (
        "internal/store/flowsnapshot",
        ("TestSnapshotsPostgresCompleteRowsPastFormerQuotaAndIdempotentRepair",),
    ),
)
CONTROLS = (
    (
        "internal/flow/query_plan.go",
        r"(?m)^(\s*MaxPlanTableRows\s*=\s*)math[.]MaxInt32$",
        "50000",
        UNIT[0][0],
        UNIT[0][1][0],
        "selected detail reach refused or clamped",
    ),
    (
        "internal/flow/query_plan.go",
        r"(?m)^(\s*MaxPlanChartRows\s*=\s*)math[.]MaxInt32$",
        "350",
        UNIT[0][0],
        UNIT[0][1][0],
        "selected detail reach refused or clamped",
    ),
    (
        "internal/store/flowsnapshot/snapshot.go",
        r"(?m)^(\s*MaxRows\s*=\s*)math[.]MaxInt32$",
        "min(math.MaxInt32, 50000)",
        UNIT[2][0],
        UNIT[2][1][0],
        "complete snapshot still uses former selected row quota",
    ),
)


def selftest() -> None:
    def encode(rows):
        return "\n".join(json.dumps(row) for row in rows)

    for package, roots in UNIT + INTEGRATION:
        name = PREFIX + package
        events = [
            {"Package": name, "Test": root, "Action": action}
            for root in roots
            for action in ("run", "pass")
        ] + [{"Package": name, "Action": "pass"}]
        assert not classify(encode(events), 0, package=name, tests=roots)
        for root in roots:
            assert classify(
                encode([row for row in events if row.get("Test") != root]),
                0,
                package=name,
                tests=roots,
            )
            assert classify(
                encode(events + [{"Package": name, "Test": root, "Action": "skip"}]),
                0,
                package=name,
                tests=roots,
            )
        assert classify("compiler failed", 1, package=name, tests=roots)
    for _, _, _, package, root, marker in CONTROLS:
        name = PREFIX + package
        events = [
            {"Package": name, "Test": root, "Action": "run"},
            {"Package": name, "Test": root, "Action": "output", "Output": marker},
            {"Package": name, "Test": root, "Action": "fail"},
            {"Package": name, "Action": "fail"},
        ]
        options = dict(root=root, marker=marker, package=name, child="")
        assert report_regression_failed_on_assertion(encode(events), 1, **options)
        assert not report_regression_failed_on_assertion(encode(events), 0, **options)
        assert not report_regression_failed_on_assertion(
            "compiler failed", 1, **options
        )
        for action in ("pass", "skip"):
            assert not report_regression_failed_on_assertion(
                encode(events + [{"Package": name, "Test": root, "Action": action}]),
                1,
                **options,
            )
    print("Selected row capacity classifier selftest PASS")


def execute(package, roots, log, integration=False):
    args = ["go", "test", "-json", "-count=1"]
    if integration:
        args += ["-tags", "integration"]
    args += ["-run", "^(" + "|".join(roots) + ")$", "./" + package]
    result = subprocess.run(
        args,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=300,
        check=False,
    )
    log.write_text(result.stdout)
    print(result.stdout, end="")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--selftest", action="store_true")
    parser.add_argument("--integration", action="store_true")
    args = parser.parse_args()
    if args.selftest:
        selftest()
        return 0
    out = Path("artifacts/flow-row-capacity")
    out.mkdir(parents=True, exist_ok=True)
    for index, (package, roots) in enumerate(INTEGRATION if args.integration else UNIT):
        result = execute(
            package,
            roots,
            out / f"{'integration' if args.integration else 'unit'}-{index}.jsonl",
            args.integration,
        )
        failures = classify(
            result.stdout, result.returncode, package=PREFIX + package, tests=roots
        )
        if failures:
            raise RuntimeError("selected row capacity proof failed: " + repr(failures))
    if args.integration:
        print(
            "Complete selected row ClickHouse/Postgres isolation and original database quota control PASS"
        )
        return 0
    for index, (filename, pattern, value, package, root, marker) in enumerate(CONTROLS):
        path = Path(filename)
        original = path.read_bytes()
        changed, count = re.subn(
            pattern, lambda match: match[1] + value, original.decode()
        )
        if count != 1:
            raise RuntimeError("selected row quota control seam changed: " + filename)
        try:
            path.write_text(changed)
            result = execute(package, (root,), out / f"old-quota-{index}.jsonl")
            if not report_regression_failed_on_assertion(
                result.stdout,
                result.returncode,
                root=root,
                marker=marker,
                package=PREFIX + package,
                child="",
            ):
                raise RuntimeError("restored quota did not fail its exact assertion")
        finally:
            path.write_bytes(original)
    print("Complete selected flow rows and all three original quota controls PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
