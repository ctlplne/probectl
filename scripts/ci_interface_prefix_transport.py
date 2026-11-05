#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
# Use of this source code is governed by the Business Source License 1.1
# in the LICENSE file at the root of this repository; on its Change Date
# each version converts to the Mozilla Public License 2.0.
"""Require complete prefix transport, current sender and tenant storage proofs."""

import argparse
import json
from pathlib import Path
import subprocess

from ci_tag_consumer_proof import classify, report_regression_failed_on_assertion

PREFIX = "github.com/ctlplne/probectl/"
UNIT = {
    "internal/entity": (
        "TestSNMPPrefixSnapshotKeepsCompleteOwnedCanonicalRows",
        "TestSNMPPrefixSnapshotRejectsPartialMalformedAndForeignClaims",
        "TestSNMPPrefixSnapshotAdmissionNeverTruncatesToFit",
    ),
    "internal/agent": (
        "TestSNMPPrefixEvidenceWireKeepsCompleteSetAndWholeRequestAdmission",
    ),
    "internal/agenttransport": (
        "TestSNMPPrefixReceiverKeepsPresenceAndRefusesPartialTables",
    ),
    "ee/silo": ("TestEntityRegistryForeignKeysFollowAllSiloCopies",),
}
INTEGRATION = {
    "internal/store": (
        "TestEntityRegistryTenantAndContextIsolation",
        "TestSNMPPrefixStorageKeepsCompleteWirePopulationAndRepairsManagedCopies",
        "TestDashboardReportTenantIsolation",
    ),
    "internal/agenttransport": (
        "TestSNMPPrefixRealMTLSKeepsTenantSenderReplayAndCompleteMetadata",
    ),
    "internal/tenantlife": (
        "TestEntityEvidenceSubjectMetadataExportErasureAndIsolation",
    ),
}
ROOT = UNIT["internal/agent"][0]
MARKER = "combined complete prefix request escaped whole-wire admission"


def selftest():
    def encode(values):
        return "\n".join(json.dumps(row) for row in values)

    for package, roots in list(UNIT.items()) + list(INTEGRATION.items()):
        events = [
            {"Package": PREFIX + package, "Test": root, "Action": action}
            for root in roots
            for action in ("run", "pass")
        ] + [{"Package": PREFIX + package, "Action": "pass"}]
        options = {"package": PREFIX + package, "tests": roots}
        assert not classify(encode(events), 0, **options)
        for root in roots:
            assert classify(
                encode([row for row in events if row.get("Test") != root]), 0, **options
            )
            assert classify(
                encode(
                    events
                    + [{"Package": PREFIX + package, "Test": root, "Action": "skip"}]
                ),
                0,
                **options,
            )
        assert classify("", 0, **options)
        assert classify(encode(events), 1, **options)
    control = [
        {"Package": PREFIX + "internal/agent", "Test": ROOT, "Action": "run"},
        {
            "Package": PREFIX + "internal/agent",
            "Test": ROOT,
            "Action": "output",
            "Output": MARKER,
        },
        {"Package": PREFIX + "internal/agent", "Test": ROOT, "Action": "fail"},
        {"Package": PREFIX + "internal/agent", "Action": "fail"},
    ]
    options = {
        "package": PREFIX + "internal/agent",
        "root": ROOT,
        "marker": MARKER,
        "child": "",
    }
    assert report_regression_failed_on_assertion(encode(control), 1, **options)
    assert not report_regression_failed_on_assertion(encode(control), 0, **options)
    assert not report_regression_failed_on_assertion(
        encode(control[:1] + control[2:]), 1, **options
    )
    assert not report_regression_failed_on_assertion("compiler error", 1, **options)
    print("Prefix transport classifier refuses missing, skipped and unrelated proof")


def execute(package, roots, label, integration=False):
    args = ["go", "test", "-race", "-count=1", "-timeout=5m", "-json"]
    if integration:
        args += ["-tags=integration"]
    result = subprocess.run(
        args + ["-run", "^(" + "|".join(roots) + ")$", "./" + package],
        text=True,
        capture_output=True,
        timeout=360,
        check=False,
    )
    out = Path("artifacts/interface-prefix-transport")
    out.mkdir(parents=True, exist_ok=True)
    (out / (label + ".jsonl")).write_text(result.stdout)
    (out / (label + ".stderr.txt")).write_text(result.stderr)
    print(result.stdout, end="")
    print(result.stderr, end="")
    return result


def main(integration):
    for package, roots in (INTEGRATION if integration else UNIT).items():
        result = execute(
            package, roots, package.replace("/", "_") + "_positive", integration
        )
        failures = classify(
            result.stdout, result.returncode, package=PREFIX + package, tests=roots
        )
        if failures:
            raise RuntimeError(
                f"required prefix transport proof missing/failed: {failures}"
            )
    if not integration:
        source = Path("internal/agent/entity_client.go")
        original = source.read_text()
        seam = "if proto.Size(request) > 1<<20 {"
        assert original.count(seam) == 1
        try:
            source.write_text(
                original.replace(seam, "if false && proto.Size(request) > 1<<20 {")
            )
            result = execute("internal/agent", (ROOT,), "whole_request_guard_omitted")
        finally:
            source.write_text(original)
        if not report_regression_failed_on_assertion(
            result.stdout,
            result.returncode,
            package=PREFIX + "internal/agent",
            root=ROOT,
            marker=MARKER,
            child="",
        ):
            raise RuntimeError(
                "omitted whole-request guard did not fail its exact complete-batch assertion"
            )
    print(
        json.dumps(
            {
                "kind": "real-integration" if integration else "simulation",
                "scope": "mTLS/Postgres with simulated SNMP inputs"
                if integration
                else "typed complete-set/native wire and silo plan",
                "passed": True,
                "real_router_acceptance": "owed",
            }
        )
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--selftest", action="store_true")
    parser.add_argument("--integration", action="store_true")
    args = parser.parse_args()
    if args.selftest:
        selftest()
    else:
        main(args.integration)
