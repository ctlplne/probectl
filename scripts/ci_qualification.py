#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
# Use of this source code is governed by the Business Source License 1.1
# in the LICENSE file at the root of this repository; on its Change Date
# each version converts to the Mozilla Public License 2.0.
"""Bind the existing full CI workflow to its exact checked-out main SHA."""

import argparse
import datetime
import json
import os
from pathlib import Path
import re
import subprocess
import unittest


def qualification(event, ref, head, requested, checkout):
    """A manual full run must name the exact main SHA selected by GitHub."""
    if not re.fullmatch(r"[0-9a-f]{40}", head) or checkout != head:
        raise ValueError("CI checkout must equal its exact GitHub event SHA")
    if event == "workflow_dispatch":
        if ref != "refs/heads/main" or requested != head:
            raise ValueError("full qualification requires the exact dispatched main SHA")
        mode = "full"
    elif event == "push" and ref == "refs/heads/main":
        if requested:
            raise ValueError("development push cannot carry a manual qualification pin")
        mode = "development"
    elif event == "pull_request" and ref.startswith("refs/pull/"):
        if requested:
            raise ValueError("pull request cannot carry a manual qualification pin")
        mode = "pull-request"
    else:
        raise ValueError("unsupported CI event/ref; qualification is not established")
    return {"schema_version": 1, "mode": mode, "sha": head, "event": event, "ref": ref}


class QualificationTests(unittest.TestCase):
    def test_full_run_keeps_exact_main_and_source_identity(self):
        head = "a" * 40
        proof = qualification("workflow_dispatch", "refs/heads/main", head, head, head)
        self.assertEqual(proof["mode"], "full")
        self.assertEqual(proof["sha"], head)

    def test_rejects_wrong_branch_pin_checkout_and_untrusted_event(self):
        head = "a" * 40
        for event, ref, pin, checkout in [
            ("workflow_dispatch", "refs/heads/other", head, head),
            ("workflow_dispatch", "refs/heads/main", "b" * 40, head),
            ("workflow_dispatch", "refs/heads/main", "", head),
            ("workflow_dispatch", "refs/heads/main", head, "b" * 40),
            ("pull_request_target", "refs/heads/main", head, head),
            ("push", "refs/tags/v0.6.6", "", head),
            ("push", "refs/heads/main", head, head),
            ("pull_request", "refs/pull/1/merge", head, head),
        ]:
            with self.subTest(event=event, ref=ref, pin=pin, checkout=checkout):
                with self.assertRaises(ValueError):
                    qualification(event, ref, head, pin, checkout)

    def test_development_and_pull_request_do_not_masquerade_as_qualification(self):
        head = "a" * 40
        self.assertEqual(qualification("push", "refs/heads/main", head, "", head)["mode"], "development")
        self.assertEqual(qualification("pull_request", "refs/pull/1/merge", head, "", head)["mode"], "pull-request")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--selftest", action="store_true")
    parser.add_argument("--output", type=Path, default=Path("artifacts/ci-qualification/run.json"))
    args = parser.parse_args()
    if args.selftest:
        result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(QualificationTests))
        return 0 if result.wasSuccessful() else 1
    checkout = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    proof = qualification(os.environ.get("GITHUB_EVENT_NAME", ""), os.environ.get("GITHUB_REF", ""), os.environ.get("GITHUB_SHA", ""), os.environ.get("QUALIFICATION_SHA", ""), checkout)
    proof.update({"repository": os.environ["GITHUB_REPOSITORY"], "run_id": int(os.environ["GITHUB_RUN_ID"]), "run_attempt": int(os.environ["GITHUB_RUN_ATTEMPT"]), "validated_at": datetime.datetime.now(datetime.timezone.utc).isoformat()})
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(proof, indent=2) + "\n")
    print(json.dumps(proof))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
