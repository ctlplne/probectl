#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
# Use of this source code is governed by the Business Source License 1.1
# in the LICENSE file at the root of this repository; on its Change Date
# each version converts to the Mozilla Public License 2.0.
"""Require real Postgres report storage isolation and old-reader refusal."""

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys

from ci_tag_consumer_proof import classify, report_regression_failed_on_assertion

PACKAGE = "github.com/ctlplne/probectl/internal/store"
ROOT = "TestReportArtifactChunksTenantIsolationAndLegacyRefusal"
MARKER = "legacy reader did not refuse chunk representation"
IO_ROOT = "TestReportArtifactChunksStageCompleteBodiesAndRefuseCorruption"
IO_MARKER = "corrupt report exposed metadata or partial bytes"
SILO_PACKAGE = "github.com/ctlplne/probectl/ee/silo"
SILO_ROOT = "TestReportArtifactChunksSiloCatchUpKeepsLocalParentsAndImmutableBodies"
LIFECYCLE_PACKAGE = "github.com/ctlplne/probectl/internal/tenantlife"
LIFECYCLE_ROOT = "TestSubjectErasureInvalidatesOpaqueReportChunksOnlyInTenant"


def selftest():
    positive = [
        {"Package": PACKAGE, "Test": ROOT, "Action": action}
        for action in ("run", "pass")
    ]
    positive.append({"Package": PACKAGE, "Action": "pass"})

    def encode(events):
        return "\n".join(json.dumps(event) for event in events)

    assert not classify(encode(positive), 0, package=PACKAGE, tests=(ROOT,))
    for bad in (
        positive[1:],
        positive + positive,
        positive + [{"Package": PACKAGE, "Test": ROOT, "Action": "skip"}],
    ):
        assert classify(encode(bad), 0, package=PACKAGE, tests=(ROOT,))
    broken = [
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
        encode(broken), 1, root=ROOT, marker=MARKER, package=PACKAGE
    )
    for bad, code in ((broken, 0), (broken[1:], 1), (broken[:2] + broken[3:], 1)):
        assert not report_regression_failed_on_assertion(
            encode(bad), code, root=ROOT, marker=MARKER, package=PACKAGE
        )
    print(
        "Report storage classifier refuses skips, missing/duplicate roots and false controls"
    )


def execute(package, pattern, *, broken=False):
    env = os.environ.copy()
    env.pop("PROBECTL_QA_REPORT_FORMAT_OMIT", None)
    if broken:
        env["PROBECTL_QA_REPORT_FORMAT_OMIT"] = "1"
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
            package,
        ],
        env=env,
        capture_output=True,
        text=True,
        timeout=360,
        check=False,
    )
    sys.stdout.write(result.stdout)
    sys.stderr.write(result.stderr)
    return result


def run():
    if os.environ.get("PROBECTL_TEST_REQUIRE_SERVICES") != "1":
        raise RuntimeError("report storage proof requires real Postgres without skips")
    for package, root in (
        (PACKAGE, ROOT),
        (PACKAGE, IO_ROOT),
        (SILO_PACKAGE, SILO_ROOT),
        (LIFECYCLE_PACKAGE, LIFECYCLE_ROOT),
    ):
        result = execute(package, "^" + root + "$")
        failed = classify(
            result.stdout, result.returncode, package=package, tests=(root,)
        )
        if failed:
            raise RuntimeError(
                "report storage positive did not execute and pass: " + repr(failed)
            )
    broken = execute(PACKAGE, "^" + ROOT + "$/^success$", broken=True)
    if not report_regression_failed_on_assertion(
        broken.stdout, broken.returncode, root=ROOT, marker=MARKER, package=PACKAGE
    ):
        raise RuntimeError(
            "format-policy omission did not fail the exact legacy-reader assertion"
        )
    source = Path("internal/store/report_artifact_read.go")
    original = source.read_text()
    seam = "receipt.SHA256 != metadata.BodySHA256"
    if original.count(seam) != 1:
        raise RuntimeError("stored report digest comparison seam unavailable")
    subprocess.run(["git", "diff", "--quiet", "--", str(source)], check=True)
    try:
        source.write_text(original.replace(seam, "false && " + seam))
        corrupt = execute(PACKAGE, "^" + IO_ROOT + "$/^digest$")
    finally:
        source.write_text(original)
    if not report_regression_failed_on_assertion(
        corrupt.stdout,
        corrupt.returncode,
        root=IO_ROOT,
        marker=IO_MARKER,
        package=PACKAGE,
        child="digest",
    ):
        raise RuntimeError(
            "digest omission did not fail the exact corruption assertion"
        )
    print(
        json.dumps(
            {
                "kind": "real-integration",
                "tests": [ROOT, IO_ROOT, SILO_ROOT, LIFECYCLE_ROOT],
                "format_policy_omission_control": True,
                "digest_omission_control": True,
                "passed": True,
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
