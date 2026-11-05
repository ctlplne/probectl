#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
#
# Use of this source code is governed by the Business Source License 1.1
# in the LICENSE file at the root of this repository; on its Change Date
# each version converts to the Mozilla Public License 2.0.

"""Require complete lookup admission and original restriction countercontrols."""

import argparse
import json
from pathlib import Path
import subprocess

from ci_tag_consumer_proof import classify, report_regression_failed_on_assertion

PACKAGE = "github.com/ctlplne/probectl/internal/cmdb"
TESTS = (
    "TestNetBoxCompleteLookupPagesKeepAllMatchesAndTenantBinding",
    "TestNetBoxCompleteLookupProfilesAreCumulativeAndRaiseable",
    "TestNetBoxInvalidAndCancelledLookupProfilesDoNotFetch",
    "TestResolverEveryProviderCacheRequiresTenantScope",
    "TestServiceNowCompletePhysicalPagesKeepAllAuthorizedCIs",
    "TestServiceNowLookupAdmissionIsCumulativeAcrossPhysicalPages",
    "TestServiceNowCompleteLookupProfilesAreRaiseableAndCancelBeforeIO",
    "TestServiceNowLinkMetadataPreservesFixedRequestAuthority",
)
API_PACKAGE = "github.com/ctlplne/probectl/internal/control"
API_TESTS = (
    "TestCMDBAPIEqualOwnedKeysKeepIndependentTenantCaches",
    "TestCMDBBuilderAppliesCompleteLookupCapacityProfiles",
    "TestCMDBAdmissionRefusalAPIIsExplicitAndDoesNotEchoSourceData",
)
CONTROLS = (
    (
        "internal/cmdb/servicenow.go",
        "\t\t\treturn out, nil\n",
        "\t\t\tif len(out) > 10 { return out[:10], nil }\n\t\t\treturn out, nil\n",
        TESTS[4],
        "complete ServiceNow physical-page scan omitted authorized CIs",
    ),
    (
        "internal/cmdb/servicenow.go",
        "\t\ttotal = count\n",
        "\t\ttotal = count\n\t\tif len(page) == 0 { return out, nil }\n",
        TESTS[4],
        "complete ServiceNow physical-page scan omitted authorized CIs",
    ),
    (
        "internal/cmdb/cmdb.go",
        '\tcacheKey := tenant.String() + "\\x00" + key\n',
        "\tcacheKey := key\n",
        TESTS[3],
        "generic cache reused another tenant's CI",
    ),
    (
        "internal/cmdb/netbox_pages.go",
        "\t\ttotal = *page.Count\n",
        "\t\ttotal = *page.Count\n\t\tif total > 10 { return ErrTenantBinding }\n",
        TESTS[0],
        "complete plural lookup above ten refused",
    ),
    (
        "internal/cmdb/lookup_budget.go",
        "\tlimit := min(work.response, work.memory/64)\n",
        "\tlimit := min(work.response, work.memory/64)\n\tlimit = min(limit, 4<<20)\n",
        TESTS[1],
        "larger complete source response profile refused",
    ),
    (
        "internal/cmdb/lookup_budget.go",
        "\t\treturn ctx, func() {}, nil\n",
        "\t\texisting.response = policy.ResponseBytes\n\t\treturn ctx, func() {}, nil\n",
        TESTS[1],
        "cumulative admission returned partial matches",
    ),
)


def selftest() -> None:
    events = [
        {"Package": PACKAGE, "Test": test, "Action": action}
        for test in TESTS
        for action in ("run", "pass")
    ] + [{"Package": PACKAGE, "Action": "pass"}]

    def encode(rows):
        return "\n".join(json.dumps(row) for row in rows)

    assert not classify(encode(events), 0, package=PACKAGE, tests=TESTS)
    for test in TESTS:
        assert classify(
            encode([event for event in events if event.get("Test") != test]),
            0,
            package=PACKAGE,
            tests=TESTS,
        )
    assert classify("", 0, package=PACKAGE, tests=TESTS)
    api_events = [
        {"Package": API_PACKAGE, "Test": test, "Action": action}
        for test in API_TESTS
        for action in ("run", "pass")
    ] + [{"Package": API_PACKAGE, "Action": "pass"}]
    assert not classify(encode(api_events), 0, package=API_PACKAGE, tests=API_TESTS)
    for test in API_TESTS:
        assert classify(
            encode([event for event in api_events if event.get("Test") != test]),
            0,
            package=API_PACKAGE,
            tests=API_TESTS,
        )
    for _, _, _, root, marker in CONTROLS:
        fail = [
            {"Package": PACKAGE, "Test": root, "Action": "run"},
            {"Package": PACKAGE, "Test": root, "Action": "output", "Output": marker},
            {"Package": PACKAGE, "Test": root, "Action": "fail"},
            {"Package": PACKAGE, "Action": "fail"},
        ]
        args = dict(root=root, marker=marker, package=PACKAGE, child="")
        assert report_regression_failed_on_assertion(encode(fail), 1, **args)
        for action in ("skip", "pass"):
            assert not report_regression_failed_on_assertion(
                encode(fail + [{"Package": PACKAGE, "Test": root, "Action": action}]),
                1,
                **args,
            )
        assert not report_regression_failed_on_assertion("compiler failed", 1, **args)
        assert not report_regression_failed_on_assertion(encode(fail), 0, **args)
        fail[1]["Output"] = "unrelated assertion"
        assert not report_regression_failed_on_assertion(encode(fail), 1, **args)
    print("CMDB complete capacity classifier selftest PASS")


def run(
    tests: tuple[str, ...], log: Path, package: str = "./internal/cmdb"
) -> subprocess.CompletedProcess:
    result = subprocess.run(
        [
            "go",
            "test",
            "-json",
            "-count=1",
            "-run",
            "^(" + "|".join(tests) + ")$",
            package,
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=180,
        check=False,
    )
    log.write_text(result.stdout)
    print(result.stdout, end="")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--selftest", action="store_true")
    args = parser.parse_args()
    if args.selftest:
        selftest()
        return 0
    out = Path("artifacts/cmdb-capacity")
    out.mkdir(parents=True, exist_ok=True)
    baseline = run(TESTS, out / "complete.jsonl")
    failures = classify(
        baseline.stdout, baseline.returncode, package=PACKAGE, tests=TESTS
    )
    if failures:
        print("complete lookup baseline failed:", failures)
        return 1
    api = run(API_TESTS, out / "api.jsonl", "./internal/control")
    failures = classify(
        api.stdout, api.returncode, package=API_PACKAGE, tests=API_TESTS
    )
    if failures:
        print("CMDB API capacity and isolation proof failed:", failures)
        return 1
    for index, (filename, old, new, root, marker) in enumerate(CONTROLS):
        path = Path(filename)
        original = path.read_bytes()
        source = original.decode()
        if source.count(old) != 1:
            raise RuntimeError("capacity control seam changed: " + filename)
        try:
            path.write_text(source.replace(old, new))
            result = run((root,), out / f"old-restriction-{index}.jsonl")
            if not report_regression_failed_on_assertion(
                result.stdout,
                result.returncode,
                root=root,
                marker=marker,
                package=PACKAGE,
                child="",
            ):
                raise RuntimeError(
                    "restored restriction did not fail its exact assertion"
                )
        finally:
            path.write_bytes(original)
    print("Complete CMDB capacity and all six original restriction controls PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
