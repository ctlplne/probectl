#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
# Use of this source code is governed by the Business Source License 1.1
# in the LICENSE file at the root of this repository; on its Change Date
# each version converts to the Mozilla Public License 2.0.
"""Require complete interface-role component proofs and exact omission controls."""

import argparse
import json
from pathlib import Path
import subprocess
import sys

from ci_tag_consumer_proof import classify, report_regression_failed_on_assertion

PACKAGE = "github.com/ctlplne/probectl/internal/device"
TESTS = (
    "TestSNMPInterfacePrefixDecodesExactStandardIndicesAndTruth",
    "TestSNMPInterfacePrefixRejectsMalformedRowsWithoutPartialIdentity",
    "TestSNMPInterfacePrefixSnapshotRetainsCompleteOrderedProtocolData",
    "TestSNMPInterfacePrefixSnapshotRefusesIncompleteOrOverBudgetWalk",
    "TestSNMPInterfacePrefixSnapshotCancellationReturnsNoPartialTable",
    "TestSNMPInterfacePrefixPacketsRequireProtocolCompletion",
    "TestSNMPInterfacePrefixPacketsRejectErrorsAfterPositiveRows",
    "TestSNMPInterfacePrefixPacketsPreserveCancellationAndCallbackRefusal",
    "TestSNMPPrefixOIDFollowsNumericCanonicalOrder",
)
ROOT = "TestSNMPInterfacePrefixPacketsRejectErrorsAfterPositiveRows"
CHILD = "packet-generr"
MARKER = "late protocol failure became successful prefix completion"
ROLE_PACKAGE = "github.com/ctlplne/probectl/internal/control"
ROLE_TESTS = (
    "TestInterfaceRoleClassificationKeepsOwnedEvidenceAndOverrides",
    "TestInterfaceRoleClassifierRefusesForeignMalformedAndOverBudgetFacts",
    "TestInterfaceRoleClassifierKeepsCompleteStableProvenanceAndCancellation",
)
ROLE_ROOT = ROLE_TESTS[2]
ROLE_MARKER = "role provenance omitted matching current evidence"
ASSOCIATION_TESTS = (
    "TestInterfaceRolePeerAssociationUsesOwnedRouterAndCompletePrefixes",
    "TestInterfaceRolePeerAssociationRefusesForeignAndMalformedSnapshots",
    "TestInterfaceRolePeerAssociationKeepsAmbiguousAndUnavailableEvidenceUnresolved",
    "TestInterfaceRolePeerAssociationPreservesProvenanceBudgetsAndCancellation",
)
ASSOCIATION_ROOT = ASSOCIATION_TESTS[3]
ASSOCIATION_MARKER = "peer association provenance omitted current prefix"


def encode(events):
    return "\n".join(json.dumps(event) for event in events)


def selftest_suite(package, tests, root, child, marker) -> None:
    events = [
        {"Package": package, "Test": root, "Action": action}
        for root in tests
        for action in ("run", "pass")
    ] + [{"Package": package, "Action": "pass"}]
    assert not classify(encode(events), 0, package=package, tests=tests)
    for name in tests:
        missing = [event for event in events if event.get("Test") != name]
        assert classify(encode(missing), 0, package=package, tests=tests)
        for action in ("skip", "fail", "pass"):
            extra = events + [{"Package": package, "Test": name, "Action": action}]
            assert classify(encode(extra), 0, package=package, tests=tests)
    assert classify("", 0, package=package, tests=tests)
    assert classify(encode(events), 1, package=package, tests=tests)
    control = [
        {"Package": package, "Test": root, "Action": "run"},
        {"Package": package, "Test": root + "/" + child, "Action": "run"},
        {
            "Package": package,
            "Test": root + "/" + child,
            "Action": "output",
            "Output": marker,
        },
        {"Package": package, "Test": root + "/" + child, "Action": "fail"},
        {"Package": package, "Test": root, "Action": "fail"},
        {"Package": package, "Action": "fail"},
    ]

    def exact(values, code):
        return report_regression_failed_on_assertion(
            encode(values), code, root=root, marker=marker, package=package, child=child
        )

    assert exact(control, 1)
    for bad, code in ((control, 0), (control[1:], 1), (control[:2] + control[3:], 1)):
        assert not exact(bad, code)
    assert not exact([{"Package": package, "Action": "build-fail"}], 1)
    print(
        package
        + ": proof classifier refuses missing, duplicate, skipped and false assertion proof"
    )


def selftest() -> None:
    selftest_suite(PACKAGE, TESTS, ROOT, CHILD, MARKER)
    selftest_suite(
        ROLE_PACKAGE,
        ASSOCIATION_TESTS,
        ASSOCIATION_ROOT,
        "success",
        ASSOCIATION_MARKER,
    )
    selftest_suite(ROLE_PACKAGE, ROLE_TESTS, ROLE_ROOT, "success", ROLE_MARKER)


def run_tests(
    pattern: str, package: str, *, integration: bool
) -> subprocess.CompletedProcess[str]:
    command = ["go", "test", "-race", "-count=1", "-timeout=3m", "-json"]
    if integration:
        command.append("-tags=integration")
    result = subprocess.run(
        command + ["-run", pattern, package],
        capture_output=True,
        text=True,
        timeout=240,
        check=False,
    )
    sys.stdout.write(result.stdout)
    sys.stderr.write(result.stderr)
    return result


def run(*, classifier: bool = False, associations: bool = False) -> None:
    if associations:
        package, tests, root, child, marker = (
            ROLE_PACKAGE,
            ASSOCIATION_TESTS,
            ASSOCIATION_ROOT,
            "success",
            ASSOCIATION_MARKER,
        )
        source = Path("internal/control/interface_role_associations.go")
        seam = "provenance := []string{snapshot.SourceID, binding.SourceID}"
        replacement = "provenance := []string{binding.SourceID}"
        control_name = "prefix_association_provenance"
    elif classifier:
        package, tests, root, child, marker = (
            ROLE_PACKAGE,
            ROLE_TESTS,
            ROLE_ROOT,
            "success",
            ROLE_MARKER,
        )
        source = Path("internal/control/interface_roles.go")
        seam = (
            "add(declaration.Role, facts.SourceID, peer.SourceID, declaration.SourceID)"
        )
        replacement = "add(declaration.Role, peer.SourceID, declaration.SourceID)"
        control_name = "interface_source_provenance"
    else:
        package, tests, root, child, marker = PACKAGE, TESTS, ROOT, CHILD, MARKER
        source = Path("internal/device/snmp_interface_prefix_walk.go")
        seam, replacement = "packet.Error != gosnmp.NoError || ", ""
        control_name = "packet_error"
    # Positive prerequisites must run before the deliberately broken guard.
    current = run_tests(
        "^(" + "|".join(tests) + ")$", package, integration=classifier or associations
    )
    failures = classify(
        current.stdout, current.returncode, package=package, tests=tests
    )
    if failures:
        raise RuntimeError(
            "mandatory interface-role component proofs did not pass: " + repr(failures)
        )
    original = source.read_text()
    if original.count(seam) != 1:
        raise RuntimeError("interface-role assertion seam unavailable")
    subprocess.run(["git", "diff", "--quiet", "--", str(source)], check=True)
    try:
        source.write_text(original.replace(seam, replacement))
        broken = run_tests(
            "^" + root + "$/^" + child + "$",
            package,
            integration=classifier or associations,
        )
    finally:
        source.write_text(original)
    if not report_regression_failed_on_assertion(
        broken.stdout,
        broken.returncode,
        root=root,
        marker=marker,
        package=package,
        child=child,
    ):
        raise RuntimeError(
            "omitted " + control_name + " did not fail its exact assertion"
        )
    print(
        json.dumps(
            {
                "kind": "simulation",
                "tests": tests,
                "assertion_control": control_name,
                "passed": True,
                "scope": "component fixtures only; no sender, registry or real router acceptance",
            }
        )
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--selftest", action="store_true")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--classifier", action="store_true")
    mode.add_argument("--associations", action="store_true")
    args = parser.parse_args()
    if args.selftest:
        selftest()
    else:
        run(classifier=args.classifier, associations=args.associations)
