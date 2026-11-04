#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
#
# Use of this source code is governed by the Business Source License 1.1
# in the LICENSE file at the root of this repository; on its Change Date
# each version converts to the Mozilla Public License 2.0.

"""Mandatory alert/native/report component proof on a fresh TLS CI database."""

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from urllib.parse import parse_qs, urlsplit, urlunsplit

PACKAGE = "github.com/ctlplne/probectl/internal/control"
TESTS = (
    "TestAlertTagFiltersRecheckCurrentOwnedUserAndNeverRewriteSeries",
    "TestTagMCPMetadataMutationsUseRealTenantAuthorizationAndAtomicAudit",
    "TestDashboardReportRenderingReleasesTransactionAndRechecksPublication",
    "TestScheduledDashboardReportsRecheckCapturedStateAndPublishOnce",
    "TestCurrentAuthorizationIntersectsCredentialAndCurrentGrants",
    "TestCurrentAuthorizationUsesFreshAttributesAndActualMFA",
    "TestCurrentAuthorizationBackgroundHasNoWriteOrMFAAuthority",
    "TestCurrentAuthorizationSnapshotCannotBorrowAnotherIdentityOrCache",
    "TestCurrentAuthorizationKeepsScopedCredentialAndImmutableSnapshot",
    "TestCurrentUserAuthorityScopeUsesOneConnectionAndForcedTenant",
    "TestReportFlowProjectionPreservesCompleteSections",
    "TestReportFlowProjectionScopesSourcesAndWholeBatchRefusal",
    "TestReportContextCaptureKeepsOnlyAuthorizedOwnedRequirements",
    "TestReportContextCaptureRefusesScopeCostAndCancellationAtomically",
    "TestReportLiveFlowCaptureUsesCurrentOwnedSourcesAndOneBatch",
)
DATABASE = "probectl_qa_beta_tag_consumers"
REPORT_TEST = "TestDashboardReportRenderingReleasesTransactionAndRechecksPublication"
REPORT_ASSERTION = (
    "single-connection report did not publish exact tenant data and audit"
)
SCHEDULE_TEST = "TestScheduledDashboardReportsRecheckCapturedStateAndPublishOnce"
SCHEDULE_ASSERTION = (
    "single-connection scheduled report did not publish and advance atomically"
)
CSV_PACKAGE = "github.com/ctlplne/probectl/internal/reporting"
CSV_TESTS = (
    "TestReportCSVStreamsCompleteLineItemReachAndExactCells",
    "TestReportCSVKeepsWholeUnicodeFormulaAndCRLFCells",
    "TestReportCSVRefusesIncompleteForeignOrMalformedSources",
    "TestReportCSVWholeOperationBudgetsCancellationAndFailure",
    "TestReportCSVLegacyBytesStayStable",
    "TestReportFieldIdentitiesRetainCompleteSchemaAndCapture",
    "TestReportBodyStageCopiesExactBytesAndSealsIntegrity",
    "TestReportBodyStageRefusesPartialOverBudgetAndCanceledOutput",
    "TestReportBodyStageHashFailureNeverReturnsPartialDigest",
    "TestReportBodyStageStreamsCompleteCSV",
    "TestReportBodyStageStreamsCompletePDF",
)
CSV_ASSERTION = "complete table header is missing"
AUTHORITY_TEST = "TestCurrentAuthorizationIntersectsCredentialAndCurrentGrants"
PROJECTION_TEST = "TestReportFlowProjectionPreservesCompleteSections"
PROJECTION_ASSERTION = "complete report matrix cells are missing"
LIVE_SOURCE_TEST = "TestReportLiveFlowCaptureUsesCurrentOwnedSourcesAndOneBatch"
LIVE_SOURCE_ASSERTION = "report comparison bypassed cumulative source read budget"
FROZEN_CONTEXT_ASSERTION = "frozen source ignored a denied captured or current context"
STAGING_TEST = "TestReportBodyStageCopiesExactBytesAndSealsIntegrity"
STAGING_ASSERTION = "staged original bytes or independent SHA256 vector changed"
AUTHORITY_ASSERTION = "current/credential intersection ="


def report_regression_failed_on_assertion(
    output: str,
    returncode: int,
    *,
    root: str = REPORT_TEST,
    marker: str = REPORT_ASSERTION,
    package: str = PACKAGE,
    child: str = "success",
) -> bool:
    """A compiler error, skip, unrelated assertion or passing run is not proof."""
    runs = failures = child_runs = child_failures = package_failures = 0
    assertion = False
    for line in output.splitlines():
        try:
            event = json.loads(line)
        except (ValueError, TypeError):
            return False
        if not isinstance(event, dict) or event.get("Package") != package:
            return False
        action, name = event.get("Action"), event.get("Test", "")
        if action == "skip" or (action == "pass" and not name):
            return False
        if name == root:
            runs += action == "run"
            failures += action == "fail"
            if action == "pass":
                return False
        if name == root + "/" + child:
            child_runs += action == "run"
            child_failures += action == "fail"
            if action == "pass":
                return False
            assertion |= action == "output" and marker in event.get("Output", "")
        if not name:
            package_failures += action == "fail"
    return (
        returncode != 0
        and runs == failures == child_runs == child_failures == package_failures == 1
        and assertion
    )


def report_regression(env: dict[str, str], *, scheduled: bool = False) -> None:
    if scheduled:
        source = Path("internal/control/dashboardreportsupervisor.go")
        root, marker = SCHEDULE_TEST, SCHEDULE_ASSERTION
        line = (
            "\tcontent, mediaType, err := s.render(ctx, item.Schedule.Format, document)"
        )
        held = """\tvar content []byte
\tvar mediaType string
\terr := tenancy.InTenant(ctx, s.pool, func(renderContext context.Context, _ tenancy.Scope) error {
\t\tvar err error
\t\tcontent, mediaType, err = s.render(renderContext, item.Schedule.Format, document)
\t\treturn err
\t})"""
    else:
        source = Path("internal/control/dashboardreporting.go")
        root, marker = REPORT_TEST, REPORT_ASSERTION
        line = "\tcontent, mediaType, err := render(r.Context(), req.Format, doc)"
        held = """\tvar content []byte
\tvar mediaType string
\terr := s.inTenant(r, func(ctx context.Context, _ tenancy.Scope) error {
\t\tvar err error
\t\tcontent, mediaType, err = render(ctx, req.Format, doc)
\t\treturn err
\t})"""
    original = source.read_text()
    if original.count(line) != 1:
        raise RuntimeError("report regression renderer seam is unavailable")
    subprocess.run(["git", "diff", "--quiet", "--", str(source)], check=True)
    # Reintroduce the old held-transaction invariant without modifying any
    # one-connection test, assertion, scope, output or publication check.
    try:
        source.write_text(original.replace(line, held))
        result = subprocess.run(
            [
                "go",
                "test",
                "-race",
                "-tags=integration",
                "-count=1",
                "-timeout=4m",
                "-json",
                "-run",
                "^" + root + "$/^success$",
                "./internal/control",
            ],
            env=env,
            capture_output=True,
            text=True,
            timeout=300,
            check=False,
        )
    finally:
        source.write_text(original)
    sys.stdout.write(result.stdout)
    sys.stderr.write(result.stderr)
    if not report_regression_failed_on_assertion(
        result.stdout, result.returncode, root=root, marker=marker
    ):
        raise RuntimeError(
            "held-transaction report regression did not fail its exact assertion"
        )
    print(
        json.dumps({"report_publication_baseline_assertion_failed": True, "test": root})
    )


def classify(
    output: str,
    returncode: int,
    *,
    package: str = PACKAGE,
    tests: tuple[str, ...] = TESTS,
) -> list[str]:
    failures = []
    runs = dict.fromkeys(tests, 0)
    passes = dict.fromkeys(tests, 0)
    package_passes = 0
    for line in output.splitlines():
        try:
            event = json.loads(line)
        except (ValueError, TypeError):
            failures.append("non-JSON test event")
            continue
        if not isinstance(event, dict):
            failures.append("invalid test event")
            continue
        if event.get("Package") != package:
            failures.append("unexpected test package")
            continue
        action, name = event.get("Action"), event.get("Test")
        if action in ("skip", "fail"):
            failures.append(f"{action}: {name or package}")
        if name in runs and action == "run":
            runs[name] += 1
        if name in passes and action == "pass":
            passes[name] += 1
        if not name and action == "pass":
            package_passes += 1
    for name in tests:
        if runs[name] != 1 or passes[name] != 1:
            failures.append(f"missing or duplicate executed pass: {name}")
    if package_passes != 1:
        failures.append("missing or duplicate package completion")
    if returncode != 0:
        failures.append("test process failed")
    return failures


def report_csv_proof(env: dict[str, str]) -> None:
    source = Path("internal/reporting/csv_tables.go")
    original = source.read_text()
    seam = """\tfor _, table := range d.Tables {
\t\tif err := writeCSVTable(ctx, writer, table, remainingMemory); err != nil {
\t\t\treturn CSVReceipt{}, err
\t\t}
\t}"""
    if original.count(seam) != 1:
        raise RuntimeError("report CSV table regression seam is unavailable")
    subprocess.run(["git", "diff", "--quiet", "--", str(source)], check=True)

    def run(pattern: str) -> subprocess.CompletedProcess[str]:
        result = subprocess.run(
            [
                "go",
                "test",
                "-race",
                "-count=1",
                "-timeout=4m",
                "-json",
                "-run",
                pattern,
                "./internal/reporting",
            ],
            env=env,
            capture_output=True,
            text=True,
            timeout=300,
            check=False,
        )
        sys.stdout.write(result.stdout)
        sys.stderr.write(result.stderr)
        return result

    # Restore the prior renderer's omission of source tables while preserving
    # the complete independent-reader test, types, scope, limits and assertions.
    try:
        source.write_text(
            original.replace(
                seam, "\t// Negative control: source tables are not emitted."
            )
        )
        result = run("^" + CSV_TESTS[0] + "$/^success$")
    finally:
        source.write_text(original)
    if not report_regression_failed_on_assertion(
        result.stdout,
        result.returncode,
        root=CSV_TESTS[0],
        marker=CSV_ASSERTION,
        package=CSV_PACKAGE,
    ):
        raise RuntimeError("omitted-table regression did not fail its exact assertion")
    print(json.dumps({"report_csv_table_baseline_assertion_failed": True}))
    result = run("^(" + "|".join(CSV_TESTS) + ")$")
    failures = classify(
        result.stdout, result.returncode, package=CSV_PACKAGE, tests=CSV_TESTS
    )
    print(
        json.dumps({"tests": CSV_TESTS, "passed": not failures, "failures": failures})
    )
    if failures:
        raise RuntimeError("current complete report CSV proof failed")


def current_authority_regression(env: dict[str, str]) -> None:
    source = Path("internal/control/abac.go")
    original = source.read_text()
    seam = "if loaded, ok := ctx.Value(loadedUserAuthorizationKey{}).(*loadedUserAuthorization); ok {"
    if original.count(seam) != 1:
        raise RuntimeError("current authorization regression seam is unavailable")
    subprocess.run(["git", "diff", "--quiet", "--", str(source)], check=True)
    try:
        # Restore the cached-only decision path while keeping all test inputs,
        # current user loading, credential scopes and assertions unchanged.
        source.write_text(
            original.replace(seam, seam.replace("; ok {", "; false && ok {"))
        )
        result = subprocess.run(
            [
                "go",
                "test",
                "-race",
                "-tags=integration",
                "-count=1",
                "-timeout=4m",
                "-json",
                "-run",
                "^" + AUTHORITY_TEST + "$/^credential_ceiling$",
                "./internal/control",
            ],
            env=env,
            capture_output=True,
            text=True,
            timeout=300,
            check=False,
        )
    finally:
        source.write_text(original)
    sys.stdout.write(result.stdout)
    sys.stderr.write(result.stderr)
    if not report_regression_failed_on_assertion(
        result.stdout,
        result.returncode,
        root=AUTHORITY_TEST,
        marker=AUTHORITY_ASSERTION,
        child="credential_ceiling",
    ):
        raise RuntimeError(
            "cached-only authorization did not fail the exact credential assertion"
        )
    print(json.dumps({"current_authority_baseline_assertion_failed": True}))


def report_projection_regression(env: dict[str, str]) -> None:
    source = Path("internal/control/dashboard_flow_records.go")
    original = source.read_text()
    seam = "\t\tif err := p.matrix(c); err != nil {\n\t\t\treturn err\n\t\t}"
    if original.count(seam) != 1:
        raise RuntimeError("report matrix projection control seam is unavailable")
    subprocess.run(["git", "diff", "--quiet", "--", str(source)], check=True)
    try:
        source.write_text(
            original.replace(
                seam, "\t\t// Omission control: no matrix cells projected."
            )
        )
        result = subprocess.run(
            [
                "go",
                "test",
                "-race",
                "-tags=integration",
                "-count=1",
                "-timeout=4m",
                "-json",
                "-run",
                "^" + PROJECTION_TEST + "$/^success$",
                "./internal/control",
            ],
            env=env,
            capture_output=True,
            text=True,
            timeout=300,
            check=False,
        )
    finally:
        source.write_text(original)
    sys.stdout.write(result.stdout)
    sys.stderr.write(result.stderr)
    if not report_regression_failed_on_assertion(
        result.stdout,
        result.returncode,
        root=PROJECTION_TEST,
        marker=PROJECTION_ASSERTION,
    ):
        raise RuntimeError(
            "report matrix omission did not fail its exact complete-section assertion"
        )
    print(json.dumps({"report_projection_omission_assertion_failed": True}))


def report_live_source_regression(
    env: dict[str, str], *, captured_scope: bool = False
) -> None:
    if captured_scope:
        source = Path("internal/control/dashboard_report_source_access.go")
        original = source.read_text()
        seam = (
            "[]map[string]string{requirement.Resource, entityContextResource(record)}"
        )
        if original.count(seam) != 1:
            raise RuntimeError("captured-context omission seam is unavailable")
        changed = original.replace(
            seam, "[]map[string]string{entityContextResource(record)}"
        )
        marker = FROZEN_CONTEXT_ASSERTION
    else:
        source = Path("internal/store/flowstore/explorer_batch.go")
        original = source.read_text()
        start = original.index("func chargeBatchRead(")
        body = original.index("{", start)
        end = original.index("\n}", body) + 2
        changed = original[:body] + "{\n\treturn nil\n}" + original[end:]
        marker = LIVE_SOURCE_ASSERTION
    subprocess.run(["git", "diff", "--quiet", "--", str(source)], check=True)
    root = LIVE_SOURCE_TEST
    try:
        source.write_text(changed)
        result = subprocess.run(
            [
                "go",
                "test",
                "-race",
                "-tags=integration",
                "-count=1",
                "-timeout=4m",
                "-json",
                "-run",
                "^" + root + "$/^success$",
                "./internal/control",
            ],
            env=env,
            capture_output=True,
            text=True,
            timeout=300,
            check=False,
        )
    finally:
        source.write_text(original)
    sys.stdout.write(result.stdout)
    sys.stderr.write(result.stderr)
    if not report_regression_failed_on_assertion(
        result.stdout,
        result.returncode,
        root=root,
        marker=marker,
    ):
        raise RuntimeError(
            "live source omission did not fail its exact assertion: " + marker
        )
    print(
        json.dumps(
            {
                "report_live_source_omission_assertion_failed": True,
                "captured_scope": captured_scope,
                "assertion": marker,
            }
        )
    )


def report_staging_regression(env: dict[str, str]) -> None:
    source = Path("internal/reporting/body_stage.go")
    original = source.read_text()
    seam = "\t\tcopied := copy(s.chunks[index][inside:], value[offset:])"
    if original.count(seam) != 1:
        raise RuntimeError("report staging ownership omission seam is unavailable")
    subprocess.run(["git", "diff", "--quiet", "--", str(source)], check=True)
    try:
        source.write_text(
            original.replace(
                seam,
                seam
                + "\n\t\tif s.size == 0 && len(value) <= BodyChunkBytes { s.chunks[index] = value }",
            )
        )
        result = subprocess.run(
            [
                "go",
                "test",
                "-race",
                "-count=1",
                "-timeout=4m",
                "-json",
                "-run",
                "^" + STAGING_TEST + "$/^red$",
                "./internal/reporting",
            ],
            env=env,
            capture_output=True,
            text=True,
            timeout=300,
            check=False,
        )
    finally:
        source.write_text(original)
    sys.stdout.write(result.stdout)
    sys.stderr.write(result.stderr)
    if not report_regression_failed_on_assertion(
        result.stdout,
        result.returncode,
        root=STAGING_TEST,
        marker=STAGING_ASSERTION,
        package=CSV_PACKAGE,
        child="red",
    ):
        raise RuntimeError(
            "borrowed staging buffer did not fail its exact integrity assertion"
        )
    print(json.dumps({"report_staging_borrowed_buffer_assertion_failed": True}))


def selftest() -> None:
    def event(action: str, name: str | None = None, package: str = PACKAGE) -> dict:
        item = {"Action": action, "Package": package}
        if name:
            item["Test"] = name
        return item

    def encoded(items: list[dict]) -> str:
        return "\n".join(json.dumps(item) for item in items)

    for tests, package in ((TESTS, PACKAGE), (CSV_TESTS, CSV_PACKAGE)):

        def make_event(
            action: str, name: str | None = None, package: str = package
        ) -> dict:
            return event(action, name, package)

        records = [
            item
            for name in tests
            for item in (make_event("run", name), make_event("pass", name))
        ]
        records.append(make_event("pass"))
        assert not classify(encoded(records), 0, package=package, tests=tests)
        for name in tests:
            assert classify(
                encoded([item for item in records if item.get("Test") != name]),
                0,
                package=package,
                tests=tests,
            )
        for bad in (
            records[:-1],
            records[2:],
            records + [make_event("pass", tests[0])],
            records + [make_event("run", tests[0])],
            records + [make_event("skip", tests[0] + "/source")],
            records + [make_event("fail", tests[1])],
            records + [make_event("fail")],
            [dict(item, Package="foreign/package") for item in records],
        ):
            assert classify(encoded(bad), 0, package=package, tests=tests), (
                "vacuous consumer proof accepted"
            )
        assert classify(encoded(records), 1, package=package, tests=tests)
        assert classify(
            encoded(records) + "\nnot an event", 0, package=package, tests=tests
        )
        assert classify("", 0, package=package, tests=tests)
    for root, marker, package, child in (
        (REPORT_TEST, REPORT_ASSERTION, PACKAGE, "success"),
        (SCHEDULE_TEST, SCHEDULE_ASSERTION, PACKAGE, "success"),
        (CSV_TESTS[0], CSV_ASSERTION, CSV_PACKAGE, "success"),
        (AUTHORITY_TEST, AUTHORITY_ASSERTION, PACKAGE, "credential_ceiling"),
        (PROJECTION_TEST, PROJECTION_ASSERTION, PACKAGE, "success"),
        (LIVE_SOURCE_TEST, LIVE_SOURCE_ASSERTION, PACKAGE, "success"),
        (LIVE_SOURCE_TEST, FROZEN_CONTEXT_ASSERTION, PACKAGE, "success"),
        (STAGING_TEST, STAGING_ASSERTION, CSV_PACKAGE, "red"),
    ):

        def make_event(
            action: str, name: str | None = None, package: str = package
        ) -> dict:
            return event(action, name, package)

        child_name = root + "/" + child
        baseline = [
            make_event("run", root),
            make_event("run", child_name),
            dict(make_event("output", child_name), Output=marker),
            make_event("fail", child_name),
            make_event("fail", root),
            make_event("fail"),
        ]
        assert report_regression_failed_on_assertion(
            encoded(baseline), 1, root=root, marker=marker, package=package, child=child
        )
        assert not report_regression_failed_on_assertion(
            encoded(baseline), 0, root=root, marker=marker, package=package, child=child
        )
        for bad in (
            [],
            baseline[1:],
            baseline[:1] + baseline[2:],
            baseline[:-1],
            baseline + [make_event("pass", root)],
            baseline + [make_event("pass", child_name)],
            baseline + [make_event("skip", child_name)],
            baseline + [make_event("fail", root)],
            [dict(item, Output="unrelated assertion") for item in baseline],
            [dict(item, Package="foreign/package") for item in baseline],
            [make_event("fail")],
        ):
            assert not report_regression_failed_on_assertion(
                encoded(bad), 1, root=root, marker=marker, package=package, child=child
            )
        other = SCHEDULE_TEST if root == REPORT_TEST else REPORT_TEST
        assert not report_regression_failed_on_assertion(
            encoded(baseline),
            1,
            root=other,
            marker=marker,
            package=package,
            child=child,
        )
        assert not report_regression_failed_on_assertion(
            encoded(baseline),
            1,
            root=root,
            marker=marker,
            package=package,
            child="wrong_case",
        )
    print("Tag/report CSV classifier rejects missing/skipped/failed/duplicate proof")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--selftest", action="store_true")
    args = parser.parse_args()
    if args.selftest:
        selftest()
        return 0
    if os.environ.get("GITHUB_ACTIONS") != "true":
        raise RuntimeError("actual consumer runner requires an isolated CI job")
    parsed = urlsplit(os.environ.get("PROBECTL_DATABASE_URL", ""))
    query = parse_qs(parsed.query)
    if (
        parsed.scheme not in ("postgres", "postgresql")
        or query.get("sslmode") != ["verify-full"]
        or not query.get("sslrootcert")
    ):
        raise RuntimeError(
            "consumer proof requires the existing verify-full TLS database"
        )
    dsn = urlunsplit(parsed._replace(path="/" + DATABASE))
    subprocess.run(
        ["docker", "exec", "ci-postgres", "createdb", "-U", "probectl", DATABASE],
        check=True,
        timeout=30,
    )
    try:
        env = dict(
            os.environ, PROBECTL_DATABASE_URL=dsn, PROBECTL_TEST_REQUIRE_SERVICES="1"
        )
        report_csv_proof(env)
        report_staging_regression(env)
        report_projection_regression(env)
        report_live_source_regression(env)
        report_live_source_regression(env, captured_scope=True)
        current_authority_regression(env)
        report_regression(env)
        report_regression(env, scheduled=True)
        result = subprocess.run(
            [
                "go",
                "test",
                "-race",
                "-tags=integration",
                "-count=1",
                "-timeout=8m",
                "-json",
                "-run",
                "^(" + "|".join(TESTS) + ")$",
                "./internal/control",
            ],
            env=env,
            capture_output=True,
            text=True,
            timeout=600,
            check=False,
        )
        sys.stdout.write(result.stdout)
        sys.stderr.write(result.stderr)
        failures = classify(result.stdout, result.returncode)
        print(
            json.dumps({"tests": TESTS, "passed": not failures, "failures": failures})
        )
        return 1 if failures else 0
    finally:
        subprocess.run(
            ["docker", "exec", "ci-postgres", "dropdb", "-U", "probectl", DATABASE],
            check=True,
            timeout=30,
        )


if __name__ == "__main__":
    raise SystemExit(main())
