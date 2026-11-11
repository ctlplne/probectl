#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
# Use of this source code is governed by the Business Source License 1.1
# in the LICENSE file at the root of this repository; on its Change Date
# each version converts to the Mozilla Public License 2.0.
"""Require exact retained-evidence portability and erasure on real Postgres."""

import argparse
import json
import os
from pathlib import Path
import subprocess

from ci_report_artifact_storage import execute
from ci_tag_consumer_proof import classify, report_regression_failed_on_assertion

PACKAGE = "github.com/ctlplne/probectl/internal/tenantlife"
ROOT = "TestEntityEvidenceSubjectMetadataExportErasureAndIsolation"
CONTROLS = (
    (
        '"snmp_system_name", "snmp_system_description"',
        '"interface_name", "interface_description"',
        "entity evidence export omitted retained subject metadata",
    ),
    (
        "predicate := subjectTableMatchPredicate(policy)",
        'predicate := subjectTableMatchPredicate(policy)\n\tif policy.agentAddressMembers { return "(($2::text[] IS NULL AND FALSE) OR ($3::text[] IS NULL AND FALSE) OR ($4::text[] IS NULL AND FALSE) OR ($5::inet[] IS NULL AND FALSE))" }',
        "entity evidence erasure retained subject metadata",
    ),
    (
        "subject_address.value = ANY($5::inet[])",
        "EXISTS (SELECT 1 FROM unnest($5::inet[]) weak_subject(value) WHERE host(subject_address.value) LIKE host(weak_subject.value) || '%')",
        "entity evidence export selected unrelated rows",
    ),
)


def selftest():
    events = [
        {"Package": PACKAGE, "Test": ROOT, "Action": action}
        for action in ("run", "pass")
    ] + [{"Package": PACKAGE, "Action": "pass"}]

    def encode(items):
        return "\n".join(json.dumps(item) for item in items)

    assert not classify(encode(events), 0, package=PACKAGE, tests=(ROOT,))
    for bad in (
        events[1:],
        events + events,
        events + [{"Package": PACKAGE, "Test": ROOT, "Action": "skip"}],
    ):
        assert classify(encode(bad), 0, package=PACKAGE, tests=(ROOT,))
    for _, _, marker in CONTROLS:
        failed = [
            {"Package": PACKAGE, "Test": ROOT, "Action": "run"},
            {"Package": PACKAGE, "Test": ROOT, "Action": "output", "Output": marker},
            {"Package": PACKAGE, "Test": ROOT, "Action": "fail"},
            {"Package": PACKAGE, "Action": "fail"},
        ]
        args = dict(root=ROOT, marker=marker, package=PACKAGE, child="")
        assert report_regression_failed_on_assertion(encode(failed), 1, **args)
        for bad, code in (
            (failed, 0),
            (failed[1:], 1),
            (failed[:1] + failed[2:], 1),
            (failed[:-1], 1),
            (failed + failed, 1),
            (failed + [{"Package": PACKAGE, "Test": ROOT, "Action": "skip"}], 1),
        ):
            assert not report_regression_failed_on_assertion(encode(bad), code, **args)
    print(
        "Evidence lifecycle classifier rejects missing/duplicate/skipped tests and false omission controls"
    )


def run():
    if (
        os.environ.get("GITHUB_ACTIONS") != "true"
        or os.environ.get("PROBECTL_TEST_REQUIRE_SERVICES") != "1"
    ):
        raise RuntimeError(
            "retained evidence lifecycle proof requires CI and real Postgres without skips"
        )
    result = execute(PACKAGE, "^" + ROOT + "$")
    if classify(result.stdout, result.returncode, package=PACKAGE, tests=(ROOT,)):
        raise RuntimeError(
            "retained evidence lifecycle baseline did not execute and pass"
        )
    source = Path("internal/tenantlife/subject.go")
    original = source.read_text()
    subprocess.run(["git", "diff", "--quiet", "--", str(source)], check=True)
    for seam, replacement, marker in CONTROLS:
        if original.count(seam) != 1:
            raise RuntimeError(
                "retained evidence lifecycle omission seam is not unique"
            )
        try:
            source.write_text(original.replace(seam, replacement))
            broken = execute(PACKAGE, "^" + ROOT + "$")
        finally:
            source.write_text(original)
        if not report_regression_failed_on_assertion(
            broken.stdout,
            broken.returncode,
            root=ROOT,
            marker=marker,
            package=PACKAGE,
            child="",
        ):
            raise RuntimeError(
                "evidence lifecycle control did not fail its exact assertion: " + marker
            )
    print(
        "Retained evidence metadata portability/erasure/isolation and three original-failure controls passed"
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--selftest", action="store_true")
    args = parser.parse_args()
    selftest() if args.selftest else run()
