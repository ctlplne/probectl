#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
# Use of this source code is governed by the Business Source License 1.1
# in the LICENSE file at the root of this repository; on its Change Date
# each version converts to the Mozilla Public License 2.0.
"""Require complete metadata above former quotas and exact old-quota controls."""

import argparse
import json
import os
from pathlib import Path
import subprocess

from ci_report_artifact_storage import execute
from ci_tag_consumer_proof import classify, report_regression_failed_on_assertion

STORE = "github.com/ctlplne/probectl/internal/store"
STORE_ROOT = "TestTagCardinalityUsesCompleteResourceAdmissionAndTenantIsolation"
PURE = "github.com/ctlplne/probectl/internal/tags"
PURE_ROOT = "TestSnapshotRetainsMetadataAboveFormerCountCeilings"
PUBLIC = "github.com/ctlplne/probectl/internal/control"
PUBLIC_ROOT = "TestTagCapacityPublicVocabularyKeepsEveryOwnedDefinition"
REQUIRED = (
    (
        "github.com/ctlplne/probectl/internal/alert",
        "TestTagFilterAcceptsCompleteBindingsAboveFormerVocabularyCount",
        ("TestTagFilterAcceptsCompleteBindingsAboveFormerVocabularyCount",),
    ),
    (PURE, PURE_ROOT, (PURE_ROOT, PURE_ROOT + "/assignments", PURE_ROOT + "/rules")),
    (STORE, STORE_ROOT, (STORE_ROOT,)),
    (PUBLIC, PUBLIC_ROOT, (PUBLIC_ROOT,)),
)
QUOTAS = (
    (
        "internal/store/tag_definitions.go",
        "func (TagDefinitions) Create(",
        "tenant_tag_definitions",
        64,
        "definition",
    ),
    (
        "internal/store/tag_rules.go",
        "func lockTagRuleRevision(",
        "tenant_tag_rules",
        25000,
        "rule",
    ),
    (
        "internal/store/tag_assignments.go",
        "func lockTagAssignmentRevision(",
        "tenant_tag_assignments",
        25000,
        "assignment",
    ),
)


def selftest():
    def encode(events):
        return "\n".join(json.dumps(event) for event in events)

    for package, _, roots in REQUIRED:
        events = [
            {"Package": package, "Test": root, "Action": action}
            for root in roots
            for action in ("run", "pass")
        ] + [{"Package": package, "Action": "pass"}]
        assert not classify(encode(events), 0, package=package, tests=roots)
        for root in roots:
            missing = [e for e in events if e.get("Test") != root]
            assert classify(encode(missing), 0, package=package, tests=roots)
            assert classify(
                encode(events + [{"Package": package, "Test": root, "Action": "skip"}]),
                0,
                package=package,
                tests=roots,
            )
        assert classify(encode(events + events), 0, package=package, tests=roots)
    for *_, kind in QUOTAS:
        marker = "above-former " + kind + " write refused"
        failed = [
            {"Package": STORE, "Test": STORE_ROOT, "Action": "run"},
            {
                "Package": STORE,
                "Test": STORE_ROOT,
                "Action": "output",
                "Output": marker,
            },
            {"Package": STORE, "Test": STORE_ROOT, "Action": "fail"},
            {"Package": STORE, "Action": "fail"},
        ]
        args = dict(root=STORE_ROOT, marker=marker, package=STORE, child="")
        assert report_regression_failed_on_assertion(encode(failed), 1, **args)
        for bad, code in (
            (failed, 0),
            (failed[1:], 1),
            (failed[:1] + failed[2:], 1),
            (failed[:-1], 1),
            (failed + failed, 1),
        ):
            assert not report_regression_failed_on_assertion(encode(bad), code, **args)
    print(
        "Tag capacity classifier requires every root/child and exact original-quota failures"
    )


def run():
    if (
        os.environ.get("GITHUB_ACTIONS") != "true"
        or os.environ.get("PROBECTL_TEST_REQUIRE_SERVICES") != "1"
    ):
        raise RuntimeError(
            "tag capacity proof requires CI and real Postgres without skips"
        )
    for package, root, required in REQUIRED:
        result = execute(package, "^" + root + "$")
        if classify(result.stdout, result.returncode, package=package, tests=required):
            raise RuntimeError("complete tag capacity baseline did not pass: " + root)
    for filename, function, table, maximum, kind in QUOTAS:
        source = Path(filename)
        original = source.read_text()
        start = original.index(function)
        end = original.index("\nfunc ", start + len(function))
        body = original[start:end]
        if kind == "definition":
            seam = "\tid, err := crypto.UUIDv4()"
        else:
            seam = "\treturn nil\n}"
        if body.count(seam) != 1:
            raise RuntimeError("old tag quota control seam is not unique")
        refusal = (
            "tags.Definition{}, tags.ErrInvalid"
            if kind == "definition"
            else "tags.ErrInvalid"
        )
        query_error = "tags.Definition{}, err" if kind == "definition" else "err"
        quota = (
            "\tvar count int\n\tif err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM "
            + table
            + " WHERE tenant_id=$1`, tenantID).Scan(&count); err != nil { return "
            + query_error
            + " }\n\tif count >= "
            + str(maximum)
            + " { return "
            + refusal
            + " }\n"
        )
        subprocess.run(["git", "diff", "--quiet", "--", filename], check=True)
        try:
            source.write_text(
                original[:start] + body.replace(seam, quota + seam) + original[end:]
            )
            broken = execute(STORE, "^" + STORE_ROOT + "$")
        finally:
            source.write_text(original)
        marker = "above-former " + kind + " write refused"
        if not report_regression_failed_on_assertion(
            broken.stdout,
            broken.returncode,
            root=STORE_ROOT,
            marker=marker,
            package=STORE,
            child="",
        ):
            raise RuntimeError(
                "old count quota did not reproduce the exact failure: " + kind
            )
    print(
        "Complete larger metadata, public vocabulary, paired isolation/resource refusal and three old-quota controls passed"
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--selftest", action="store_true")
    args = parser.parse_args()
    selftest() if args.selftest else run()
