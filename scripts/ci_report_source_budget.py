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
    "TestExplorerPlanBatchSharedMetadataCannotWidenBudgets",
    "TestExplorerClickHouseRealPlanBatchCostAndTenantBoundary",
)
MARKER = "repeated source plan received a fresh read allowance"
VIEW_PACKAGE = "github.com/ctlplne/probectl/internal/flow"
VIEW_TESTS = (
    "TestQueryViewCurrentAccessIsScopedAndIndependentOfFrozenDefinition",
    "TestQueryViewCurrentAccessRefusesMissingMismatchedAndMalformedScope",
    "TestQueryViewsPostgresRealScopePersistenceAuditAndLifecycle",
)
VIEW_MARKER = "source metadata must remain readable after definition change"
CAPTURE_PACKAGE = "github.com/ctlplne/probectl/internal/control"
CAPTURE_TESTS = (
    "TestReportRealFlowCaptureStagesCurrentOwnedSources",
    "TestReportRealFlowCaptureRetainsCompleteSelectedTable",
    "TestReportRealFlowCaptureDownloadsCompletePDF",
)


def selftest() -> None:
    capture_events = [
        {"Package": CAPTURE_PACKAGE, "Test": test, "Action": action}
        for test in CAPTURE_TESTS
        for action in ("run", "pass")
    ] + [{"Package": CAPTURE_PACKAGE, "Action": "pass"}]
    capture_log = "\n".join(json.dumps(event) for event in capture_events)
    assert not classify(capture_log, 0, package=CAPTURE_PACKAGE, tests=CAPTURE_TESTS)
    for removed in CAPTURE_TESTS:
        partial = "\n".join(
            json.dumps(event)
            for event in capture_events
            if event.get("Test") != removed
        )
        assert classify(partial, 0, package=CAPTURE_PACKAGE, tests=CAPTURE_TESTS)
    for action in ("skip", "fail"):
        bad = (
            capture_log
            + "\n"
            + json.dumps(
                {"Package": CAPTURE_PACKAGE, "Test": CAPTURE_TESTS[0], "Action": action}
            )
        )
        assert classify(bad, 0, package=CAPTURE_PACKAGE, tests=CAPTURE_TESTS)
    assert classify("", 0, package=CAPTURE_PACKAGE, tests=CAPTURE_TESTS)
    assert classify(
        capture_log + "\n" + capture_log,
        0,
        package=CAPTURE_PACKAGE,
        tests=CAPTURE_TESTS,
    )
    view_events = [
        {"Package": VIEW_PACKAGE, "Test": test, "Action": action}
        for test in VIEW_TESTS
        for action in ("run", "pass")
    ] + [{"Package": VIEW_PACKAGE, "Action": "pass"}]
    view_log = "\n".join(json.dumps(event) for event in view_events)
    assert not classify(view_log, 0, package=VIEW_PACKAGE, tests=VIEW_TESTS)
    for removed in VIEW_TESTS:
        partial = "\n".join(
            json.dumps(event) for event in view_events if event.get("Test") != removed
        )
        assert classify(partial, 0, package=VIEW_PACKAGE, tests=VIEW_TESTS)
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
    view_control = []
    for event in control:
        copied = dict(event, Package=VIEW_PACKAGE)
        copied["Test"] = (
            event["Test"]
            .replace(TESTS[0], VIEW_TESTS[-1])
            .replace("/success", "/current_visibility")
        )
        if copied.get("Output") == MARKER:
            copied["Output"] = VIEW_MARKER
        view_control.append(copied)
    assert report_regression_failed_on_assertion(
        encode(view_control),
        1,
        root=VIEW_TESTS[-1],
        marker=VIEW_MARKER,
        package=VIEW_PACKAGE,
        child="current_visibility",
    )
    assert not report_regression_failed_on_assertion(
        encode(view_control),
        0,
        root=VIEW_TESTS[-1],
        marker=VIEW_MARKER,
        package=VIEW_PACKAGE,
        child="current_visibility",
    )
    print(
        "Batch source classifier refuses missing, duplicate, skipped and false assertion proof"
    )


def run_tests(
    pattern: str, go_package: str = "./internal/store/flowstore"
) -> subprocess.CompletedProcess:
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
            go_package,
        ],
        capture_output=True,
        text=True,
        timeout=360,
        check=False,
    )
    sys.stdout.write(result.stdout)
    sys.stderr.write(result.stderr)
    return result


def visibility_proof() -> None:
    source = Path("internal/flow/query_view_access.go")
    original = source.read_text()
    signature = "func (s *PostgresQueryViewStore) GetQueryViewAccess("
    if original.count(signature) != 1:
        raise RuntimeError("current source visibility seam unavailable")
    start = original.index(signature)
    # Replace only the pool-owned getter. Keep the scoped store path available
    # so its one-connection proof compiles and the counterexample still has to
    # reach the original invalid-definition assertion.
    end = original.index("\n// GetQueryViewAccessInScope", start)
    decoded = """func (s *PostgresQueryViewStore) GetQueryViewAccess(ctx context.Context, tenant, owner, id string) (QueryViewAccess, error) {
    if err := queryViewAccessScope(ctx, tenant, owner, id); err != nil { return QueryViewAccess{}, err }
    current, err := s.GetQueryView(ctx, tenant, owner, id)
    if err != nil { return QueryViewAccess{}, err }
    version, err := strconv.ParseInt(current.Version, 10, 64)
    if err != nil { return QueryViewAccess{}, err }
    return validateQueryViewAccess(QueryViewAccess{ID: current.ID, TenantID: current.TenantID, OwnerID: current.OwnerID, Visibility: current.Definition.Visibility, Version: strconv.FormatInt(version, 10)}, tenant, owner)
}
"""
    subprocess.run(["git", "diff", "--quiet", "--", str(source)], check=True)
    try:
        source.write_text(original[:start] + decoded + original[end:])
        before = run_tests(
            "^" + VIEW_TESTS[-1] + "$/^current_visibility$", "./internal/flow"
        )
    finally:
        source.write_text(original)
    if not report_regression_failed_on_assertion(
        before.stdout,
        before.returncode,
        root=VIEW_TESTS[-1],
        marker=VIEW_MARKER,
        package=VIEW_PACKAGE,
        child="current_visibility",
    ):
        raise RuntimeError(
            "current visibility control did not fail its exact frozen-definition assertion"
        )
    current = run_tests("^(" + "|".join(VIEW_TESTS) + ")$", "./internal/flow")
    failures = classify(
        current.stdout, current.returncode, package=VIEW_PACKAGE, tests=VIEW_TESTS
    )
    print(
        json.dumps(
            {
                "tests": VIEW_TESTS,
                "assertion_control": True,
                "passed": not failures,
                "failures": failures,
            }
        )
    )
    if failures:
        raise RuntimeError(
            "mandatory current source visibility proofs did not all execute and pass"
        )


def post_verification_reader_proof() -> None:
    source = Path("internal/control/dashboard_report_download.go")
    original = source.read_text()
    seam = "if err := s.revalidateReportFlowCaptureScope(ctx, sc, actor, capture); err != nil {"
    if original.count(seam) != 1:
        raise RuntimeError("final stored report reader recheck seam unavailable")
    subprocess.run(["git", "diff", "--quiet", "--", str(source)], check=True)
    try:
        source.write_text(original.replace(seam, "if err := error(nil); err != nil {"))
        before = run_tests("^" + CAPTURE_TESTS[0] + "$/^success$", "./internal/control")
    finally:
        source.write_text(original)
    if not report_regression_failed_on_assertion(
        before.stdout,
        before.returncode,
        root=CAPTURE_TESTS[0],
        marker="revoked source reader received a report body after verification",
        package=CAPTURE_PACKAGE,
    ):
        raise RuntimeError(
            "final reader omission did not fail its exact post-verification refusal assertion"
        )
    print(
        json.dumps(
            {
                "test": CAPTURE_TESTS[0],
                "post_verification_reader_omission_control": True,
                "passed": True,
            }
        )
    )


def preauthorization_privacy_proof() -> None:
    source = Path("internal/control/dashboard_report_download.go")
    original = source.read_text()
    seam = "return s.reportArtifactSourceAccessError(actor.TenantID, metadata.ID, err)"
    if original.count(seam) != 1:
        raise RuntimeError("report preauthorization privacy seam unavailable")
    subprocess.run(["git", "diff", "--quiet", "--", str(source)], check=True)
    try:
        source.write_text(
            original.replace(seam, "return reportArtifactReaderError(err)")
        )
        before = run_tests("^" + CAPTURE_TESTS[0] + "$/^success$", "./internal/control")
    finally:
        source.write_text(original)
    if not report_regression_failed_on_assertion(
        before.stdout,
        before.returncode,
        root=CAPTURE_TESTS[0],
        marker="unverifiable report source exposed existence before source authorization",
        package=CAPTURE_PACKAGE,
    ):
        raise RuntimeError(
            "old preauthorization error mapping did not fail its exact privacy assertion"
        )
    print(
        json.dumps(
            {
                "test": CAPTURE_TESTS[0],
                "preauthorization_privacy_omission_control": True,
                "passed": True,
            }
        )
    )


def publication_state_proof() -> None:
    source = Path("internal/control/dashboard_report_generate.go")
    original = source.read_text()
    subprocess.run(["git", "diff", "--quiet", "--", str(source)], check=True)
    cases = (
        ("err := flowsnapshot.MatchSourceGenerationInScope(ctx, sc, capture.SourceGeneration); err != nil",
         "err := flowsnapshot.MatchSourceGenerationInScope(ctx, sc, capture.SourceGeneration); false && err != nil",
         "invalidated source capture published through the public report route"),
        ("if current.Version != input.Version {", "if false && current.Version != input.Version {",
         "changed source version published through the public report route"),
    )
    for seam, replacement, marker in cases:
        if original.count(seam) != 1:
            raise RuntimeError("source publication state seam unavailable")
        try:
            source.write_text(original.replace(seam, replacement))
            result = run_tests("^" + CAPTURE_TESTS[0] + "$/^success$", "./internal/control")
        finally:
            source.write_text(original)
        if not report_regression_failed_on_assertion(
            result.stdout, result.returncode, root=CAPTURE_TESTS[0],
            child="success", marker=marker, package=CAPTURE_PACKAGE,
        ):
            raise RuntimeError("publication omission did not fail exact source state assertion")


def metadata_reader_proof() -> None:
    source = Path("internal/control/dashboard_report_list.go")
    original = source.read_text()
    seam = "accessErr = s.revalidateReportFlowCaptureScope(ctx, sc, actor, capture)"
    if original.count(seam) != 1:
        raise RuntimeError("current report metadata reader seam unavailable")
    subprocess.run(["git", "diff", "--quiet", "--", str(source)], check=True)
    try:
        source.write_text(original.replace(seam, "accessErr = nil\n_ = capture"))
        before = run_tests("^" + CAPTURE_TESTS[0] + "$/^success$", "./internal/control")
    finally:
        source.write_text(original)
    if not report_regression_failed_on_assertion(
        before.stdout,
        before.returncode,
        root=CAPTURE_TESTS[0],
        marker="scoped credential listed private source report metadata",
        package=CAPTURE_PACKAGE,
    ):
        raise RuntimeError(
            "metadata reader omission did not fail its exact current-source refusal assertion"
        )
    print(
        json.dumps(
            {
                "test": CAPTURE_TESTS[0],
                "metadata_reader_omission_control": True,
                "passed": True,
            }
        )
    )


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
    visibility_proof()
    captured = run_tests("^(" + "|".join(CAPTURE_TESTS) + ")$", "./internal/control")
    failures = classify(
        captured.stdout,
        captured.returncode,
        package=CAPTURE_PACKAGE,
        tests=CAPTURE_TESTS,
    )
    print(
        json.dumps(
            {"tests": CAPTURE_TESTS, "passed": not failures, "failures": failures}
        )
    )
    if failures:
        raise RuntimeError(
            "mandatory real source capture/staging proof did not execute and pass"
        )
    post_verification_reader_proof()
    preauthorization_privacy_proof()
    metadata_reader_proof()
    publication_state_proof()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--selftest", action="store_true")
    if parser.parse_args().selftest:
        selftest()
    else:
        run()
