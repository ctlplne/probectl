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
)
DATABASE = "probectl_qa_beta_tag_consumers"
REPORT_TEST = "TestDashboardReportRenderingReleasesTransactionAndRechecksPublication"
REPORT_ASSERTION = (
    "single-connection report did not publish exact tenant data and audit"
)


def report_regression_failed_on_assertion(output: str, returncode: int) -> bool:
    """A compiler error, skip, unrelated assertion or passing run is not proof."""
    runs = failures = child_runs = child_failures = package_failures = 0
    assertion = False
    for line in output.splitlines():
        try:
            event = json.loads(line)
        except (ValueError, TypeError):
            return False
        if not isinstance(event, dict) or event.get("Package") != PACKAGE:
            return False
        action, name = event.get("Action"), event.get("Test", "")
        if action == "skip" or (action == "pass" and not name):
            return False
        if name == REPORT_TEST:
            runs += action == "run"
            failures += action == "fail"
            if action == "pass":
                return False
        if name == REPORT_TEST + "/success":
            child_runs += action == "run"
            child_failures += action == "fail"
            if action == "pass":
                return False
            assertion |= action == "output" and REPORT_ASSERTION in event.get(
                "Output", ""
            )
        if not name:
            package_failures += action == "fail"
    return (
        returncode != 0
        and runs == failures == child_runs == child_failures == package_failures == 1
        and assertion
    )


def report_regression(env: dict[str, str]) -> None:
    source = Path("internal/control/dashboardreporting.go")
    original = source.read_text()
    line = "\tcontent, mediaType, err := render(r.Context(), req.Format, doc)"
    if original.count(line) != 1:
        raise RuntimeError("report regression renderer seam is unavailable")
    subprocess.run(["git", "diff", "--quiet", "--", str(source)], check=True)
    # Restore exactly the old transaction lifetime, without modifying the
    # one-connection test, assertions, isolation, output or publication checks.
    held = """\tvar content []byte
\tvar mediaType string
\terr := s.inTenant(r, func(ctx context.Context, _ tenancy.Scope) error {
\t\tvar err error
\t\tcontent, mediaType, err = render(ctx, req.Format, doc)
\t\treturn err
\t})"""
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
                "^" + REPORT_TEST + "$/^success$",
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
    if not report_regression_failed_on_assertion(result.stdout, result.returncode):
        raise RuntimeError(
            "held-transaction report regression did not fail its exact assertion"
        )
    print(
        json.dumps(
            {"report_publication_baseline_assertion_failed": True, "test": REPORT_TEST}
        )
    )


def classify(output: str, returncode: int) -> list[str]:
    failures = []
    runs = dict.fromkeys(TESTS, 0)
    passes = dict.fromkeys(TESTS, 0)
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
        if event.get("Package") != PACKAGE:
            failures.append("unexpected test package")
            continue
        action, name = event.get("Action"), event.get("Test")
        if action in ("skip", "fail"):
            failures.append(f"{action}: {name or PACKAGE}")
        if name in runs and action == "run":
            runs[name] += 1
        if name in passes and action == "pass":
            passes[name] += 1
        if not name and action == "pass":
            package_passes += 1
    for name in TESTS:
        if runs[name] != 1 or passes[name] != 1:
            failures.append(f"missing or duplicate executed pass: {name}")
    if package_passes != 1:
        failures.append("missing or duplicate package completion")
    if returncode != 0:
        failures.append("test process failed")
    return failures


def selftest() -> None:
    def event(action: str, name: str | None = None) -> dict:
        item = {"Action": action, "Package": PACKAGE}
        if name:
            item["Test"] = name
        return item

    records = [
        item for name in TESTS for item in (event("run", name), event("pass", name))
    ]
    records.append(event("pass"))

    def encoded(items: list[dict]) -> str:
        return "\n".join(json.dumps(item) for item in items)

    assert not classify(encoded(records), 0)
    for name in TESTS:
        assert classify(
            encoded([item for item in records if item.get("Test") != name]), 0
        )
    for bad in (
        records[:-1],
        records[2:],
        records + [event("pass", TESTS[0])],
        records + [event("run", TESTS[0])],
        records + [event("skip", TESTS[0] + "/source")],
        records + [event("fail", TESTS[1])],
        records + [event("fail")],
        [dict(item, Package="foreign/package") for item in records],
    ):
        assert classify(encoded(bad), 0), "vacuous consumer proof accepted"
    assert classify(encoded(records), 1)
    assert classify(encoded(records) + "\nnot an event", 0)
    assert classify("", 0)
    baseline = [
        event("run", REPORT_TEST),
        event("run", REPORT_TEST + "/success"),
        dict(event("output", REPORT_TEST + "/success"), Output=REPORT_ASSERTION),
        event("fail", REPORT_TEST + "/success"),
        event("fail", REPORT_TEST),
        event("fail"),
    ]
    assert report_regression_failed_on_assertion(encoded(baseline), 1)
    assert not report_regression_failed_on_assertion(encoded(baseline), 0)
    for bad in (
        [],
        baseline[1:],
        baseline[:1] + baseline[2:],
        baseline[:-1],
        baseline + [event("pass", REPORT_TEST)],
        baseline + [event("pass", REPORT_TEST + "/success")],
        baseline + [event("skip", REPORT_TEST + "/success")],
        baseline + [event("fail", REPORT_TEST)],
        [dict(item, Output="unrelated assertion") for item in baseline],
        [dict(item, Package="foreign/package") for item in baseline],
        [event("fail")],
    ):
        assert not report_regression_failed_on_assertion(encoded(bad), 1)
    print("Tag consumer classifier rejects missing/skipped/failed/duplicate proof")


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
        report_regression(env)
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
