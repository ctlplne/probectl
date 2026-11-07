#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
# Use of this source code is governed by the Business Source License 1.1
# in the LICENSE file at the root of this repository; on its Change Date
# each version converts to the Mozilla Public License 2.0.

"""Require complete inbox pages and exact restored-cap failures."""

import argparse
import json
import os
from pathlib import Path
import subprocess

from ci_tag_consumer_proof import classify, report_regression_failed_on_assertion

PACKAGE = "github.com/ctlplne/probectl/internal/control"
ROOT = "TestReportInboxPagesKeepCompleteTenantHistoryAndHiddenSourcesPrivate"
UNIT = (
    "TestReportInboxCursorOnlySelectsCurrentTenantAndOwnerPosition",
    "TestOpenAPICollectionPaginationContract",
)
WEB_NAMES = {
    f"complete report inbox pages stay private: {theme} {tenant}"
    for theme in ("light", "dark")
    for tenant in (
        "00000000-0000-4000-8000-000000000101",
        "00000000-0000-4000-8000-000000000102",
    )
}
WEB_MARKER = "complete inbox page still clipped to four records"


def web_valid(document, code, *, negative=False):
    tests = [
        test
        for suite in document.get("testResults", [])
        for test in suite.get("assertionResults", [])
    ]
    if len(tests) != len(WEB_NAMES) or {t.get("fullName") for t in tests} != WEB_NAMES:
        return False
    if negative:
        return code != 0 and all(
            t.get("status") == "failed"
            and WEB_MARKER in "\n".join(t.get("failureMessages", []))
            for t in tests
        )
    return code == 0 and all(t.get("status") == "passed" for t in tests)


def selftest():
    document = {
        "testResults": [
            {
                "assertionResults": [
                    {"fullName": n, "status": "passed"} for n in WEB_NAMES
                ]
            }
        ]
    }
    assert web_valid(document, 0)
    assert not web_valid(document, 1)
    rows = document["testResults"][0]["assertionResults"]
    for row in rows:
        row.update(status="failed", failureMessages=[WEB_MARKER])
    assert web_valid(document, 1, negative=True)
    assert not web_valid(document, 0, negative=True)
    rows[0]["failureMessages"] = ["unrelated failure"]
    assert not web_valid(document, 1, negative=True)
    rows.pop()
    assert not web_valid(document, 1, negative=True)
    events = [
        {"Package": PACKAGE, "Test": root, "Action": action}
        for root in UNIT + (ROOT,)
        for action in ("run", "pass")
    ] + [{"Package": PACKAGE, "Action": "pass"}]
    encoded = "\n".join(json.dumps(e) for e in events)
    assert not classify(encoded, 0, package=PACKAGE, tests=UNIT + (ROOT,))
    assert classify("compiler error", 1, package=PACKAGE, tests=(ROOT,))
    skipped = (
        encoded
        + "\n"
        + json.dumps({"Package": PACKAGE, "Test": ROOT, "Action": "skip"})
    )
    assert classify(skipped, 0, package=PACKAGE, tests=UNIT + (ROOT,))
    for root in UNIT + (ROOT,):
        missing = "\n".join(json.dumps(e) for e in events if e.get("Test") != root)
        assert classify(missing, 0, package=PACKAGE, tests=UNIT + (ROOT,))
    print("Inbox proof classifiers reject missing, skipped and unrelated failures")


def execute(roots, destination, *, integration=False):
    command = ["go", "test", "-json", "-count=1", "-timeout=5m"]
    if integration:
        command += ["-race", "-tags=integration"]
    command += ["-run", "^(" + "|".join(roots) + ")$", "./internal/control"]
    result = subprocess.run(
        command, capture_output=True, text=True, timeout=360, check=False
    )
    destination.write_text(result.stdout + result.stderr)
    print(result.stdout, end="")
    print(result.stderr, end="")
    return result


def require_go(roots, destination, *, integration=False):
    result = execute(roots, destination, integration=integration)
    failures = classify(result.stdout, result.returncode, package=PACKAGE, tests=roots)
    if failures:
        raise RuntimeError("complete inbox focused proof failed: " + repr(failures))


def prove_web(out):
    def run(name):
        destination = out / name
        result = subprocess.run(
            [
                "npm",
                "exec",
                "--",
                "vitest",
                "run",
                "src/test/report-inbox-pagination.test.tsx",
                "--reporter=json",
                "--outputFile=" + str(destination.resolve()),
            ],
            cwd="web",
            capture_output=True,
            text=True,
            timeout=180,
            check=False,
        )
        print(result.stdout, end="")
        print(result.stderr, end="")
        return json.loads(destination.read_text()), result.returncode

    document, code = run("web-positive.json")
    if not web_valid(document, code):
        raise RuntimeError("complete paired both-theme inbox page proof failed")
    path = Path("web/src/routes/DashboardReportingCard.tsx")
    original = path.read_bytes()
    seam = "artifacts.data?.items.map((item)"
    if original.decode().count(seam) != 1:
        raise RuntimeError("original UI four-record control seam changed")
    try:
        path.write_text(
            original.decode().replace(
                seam, "artifacts.data?.items.slice(0, 4).map((item)"
            )
        )
        document, code = run("web-old-four.json")
    finally:
        path.write_bytes(original)
    if not web_valid(document, code, negative=True):
        raise RuntimeError(
            "old UI quota did not fail the exact complete-page assertion"
        )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--selftest", action="store_true")
    mode.add_argument("--unit", action="store_true")
    mode.add_argument("--integration", action="store_true")
    mode.add_argument("--web", action="store_true")
    args = parser.parse_args()
    if args.selftest:
        selftest()
        return
    os.chdir(Path(__file__).resolve().parents[1])
    out = Path("artifacts/report-inbox")
    out.mkdir(parents=True, exist_ok=True)
    if args.unit:
        require_go(UNIT, out / "cursor-contract.jsonl")
    if args.web:
        prove_web(out)
    if args.integration:
        require_go((ROOT,), out / "complete.jsonl", integration=True)
        path = Path("internal/control/dashboard_report_list.go")
        original = path.read_bytes()
        seam = "\tviews := make([]reportArtifactView, 0)"
        continuation = "nextCursor, err = encodeReportInboxCursor(actor.TenantID, dashboardActorID(r), lastVisible)"
        controls = (
            (
                seam,
                "\tlimit = min(limit, 200)\n" + seam,
                "inbox page retains former200record quota",
            ),
            (
                continuation,
                'nextCursor, err = "", nil\n_ = lastVisible',
                "default inbox page is not a complete physical batch",
            ),
        )
        for index, (old, replacement, marker) in enumerate(controls):
            if original.decode().count(old) != 1:
                raise RuntimeError("inbox restored-restriction seam changed")
            try:
                path.write_text(original.decode().replace(old, replacement))
                result = execute(
                    (ROOT,), out / f"old-restriction-{index}.jsonl", integration=True
                )
            finally:
                path.write_bytes(original)
            if not report_regression_failed_on_assertion(
                result.stdout,
                result.returncode,
                root=ROOT,
                marker=marker,
                package=PACKAGE,
                child="",
            ):
                raise RuntimeError(
                    "old inbox restriction did not fail its exact reach assertion"
                )
    print("Complete inbox focused proof and selected controls PASS")


if __name__ == "__main__":
    main()
