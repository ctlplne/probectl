#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
# Use of this source code is governed by the Business Source License 1.1
# in the LICENSE file at the root of this repository; on its Change Date
# each version converts to the Mozilla Public License 2.0.
"""Coalesce only older ordinary main CI; never cancel a qualification or scanner."""

import argparse
from copy import deepcopy
import datetime
import json
import os
from pathlib import Path
import re
import subprocess
import time
import unittest


CI_PATH = ".github/workflows/ci.yml"
ACTIVE = {"queued", "in_progress", "waiting", "pending", "requested"}


def ordinary(run, repository, workflow_id):
    """A rerun is protected even when GitHub retains its original push event."""
    return (
        run.get("event") == "push"
        and run.get("path") == CI_PATH
        and run.get("workflow_id") == workflow_id
        and run.get("head_branch") == "main"
        and run.get("repository", {}).get("full_name") == repository
        and run.get("head_repository", {}).get("full_name") == repository
        and run.get("run_attempt") == 1
        and isinstance(run.get("id"), int)
        and run["id"] > 0
        and isinstance(run.get("run_number"), int)
        and bool(re.fullmatch(r"[0-9a-f]{40}", run.get("head_sha", "")))
    )


def candidate(run, anchor, repository, workflow_id, protected):
    return (
        ordinary(run, repository, workflow_id)
        and run.get("status") in ACTIVE
        and run["id"] != anchor["id"]
        and run["run_number"] < anchor["run_number"]
        and run["head_sha"] != anchor["head_sha"]
        and run["head_sha"] not in protected
    )


class GitHub:
    def __init__(self, repository):
        if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
            raise ValueError("invalid repository")
        self.root = "repos/" + repository

    def api(self, path, method="GET"):
        # No shell, arbitrary endpoint, delete, force-cancel, or token output.
        if not path.startswith(self.root + "/") or method not in {"GET", "POST"}:
            raise ValueError("unsupported API operation")
        if method == "POST" and not re.fullmatch(re.escape(self.root) + r"/actions/runs/[1-9][0-9]*/cancel", path):
            raise ValueError("only normal run cancellation is authorized")
        result = subprocess.run(["gh", "api", "--method", method, path], text=True, capture_output=True, check=False)
        if result.returncode:
            # gh stderr can contain headers/context. Retain no credential data.
            raise RuntimeError("GitHub metadata/cancel request failed; stop without widening authority")
        return json.loads(result.stdout) if result.stdout.strip() else {}

    def pages(self, path, key):
        separator = "&" if "?" in path else "?"
        page = 1
        while True:
            value = self.api(path + separator + f"per_page=100&page={page}")
            rows = value[key]
            yield from rows
            if len(rows) < 100:
                return
            page += 1

    def run(self, run_id):
        return self.api(self.root + f"/actions/runs/{run_id}")

    def active(self, workflow_id):
        runs = {}
        for status in sorted(ACTIVE):
            for run in self.pages(self.root + f"/actions/workflows/{workflow_id}/runs?status={status}", "workflow_runs"):
                runs[run["id"]] = run
        return list(runs.values())

    def ancestor(self, older, newer):
        value = self.api(self.root + f"/compare/{older}...{newer}")
        return value.get("status") == "ahead" and value.get("base_commit", {}).get("sha") == older and value.get("merge_base_commit", {}).get("sha") == older

    def evidence(self, run_id):
        # Cancellation leaves GitHub's existing logs/artifacts in place. Record
        # their identities and job conclusions before requesting cancellation.
        return {
            "jobs": list(self.pages(self.root + f"/actions/runs/{run_id}/jobs?filter=latest", "jobs")),
            "artifacts": list(self.pages(self.root + f"/actions/runs/{run_id}/artifacts", "artifacts")),
        }


def coalesce(api, repository, source_id, receipt, save):
    workflow = api.api(api.root + "/actions/workflows/ci.yml")
    workflow_id = workflow["id"]
    if workflow.get("path") != CI_PATH or workflow.get("state") != "active":
        raise ValueError("ordinary CI workflow identity is not established")
    anchor = api.run(source_id)
    if not ordinary(anchor, repository, workflow_id):
        raise ValueError("source must be a first-attempt ordinary main CI run")
    # Several queued start notifications can arrive after a newer source has
    # already superseded this run. That is an expected no-op, not a controller
    # failure, and must never grant this stale source cancellation authority.
    if anchor.get("conclusion") == "cancelled":
        receipt["status"] = "unchanged: source already canceled"
        save()
        return
    # Require the existing qualification/pin/permission checks before replacing
    # older work. This does not add an acceptance gate or wait for the full run.
    jobs = api.evidence(source_id)["jobs"]
    pins = [job for job in jobs if job.get("name") == "action-pins"]
    if len(pins) != 1 or pins[0].get("conclusion") != "success":
        receipt["status"] = "unchanged: source validation not yet successful"
        save()
        return
    receipt["source"] = {key: anchor[key] for key in ("id", "head_sha", "html_url", "run_attempt")}
    for run in api.active(workflow_id):
        protected = {row["head_sha"] for row in api.active(workflow_id) if not ordinary(row, repository, workflow_id)}
        if not candidate(run, anchor, repository, workflow_id, protected):
            continue
        if not api.ancestor(run["head_sha"], anchor["head_sha"]):
            continue
        evidence = api.evidence(run["id"])
        fresh = api.run(run["id"])
        if not candidate(fresh, anchor, repository, workflow_id, protected) or fresh["head_sha"] != run["head_sha"]:
            continue
        entry = {"run": fresh, "before_cancel": evidence, "status": "cancel requested; incomplete checks remain owed"}
        receipt["cancelled_development"].append(entry)
        save()  # Persist receipt before mutation; never delete logs or artifacts.
        try:
            api.api(api.root + f"/actions/runs/{fresh['id']}/cancel", method="POST")
        except RuntimeError:
            after = api.run(fresh["id"])
            if after.get("status") != "completed":
                raise
            entry["status"] = "run completed during normal cancellation request; inspect actual conclusion"
        entry["after_request"] = api.run(fresh["id"])
        save()
    receipt["status"] = "finished; cancellation is not qualification"
    save()


class CoalescingTests(unittest.TestCase):
    def setUp(self):
        self.repo = "example/product"
        self.old = {"id": 10, "run_number": 10, "workflow_id": 5, "event": "push", "path": CI_PATH, "head_branch": "main", "repository": {"full_name": self.repo}, "head_repository": {"full_name": self.repo}, "run_attempt": 1, "head_sha": "a" * 40, "status": "in_progress", "html_url": "https://example.invalid/10"}
        self.anchor = dict(self.old, id=20, run_number=20, head_sha="b" * 40)

    def test_never_selects_protected_foreign_newer_or_terminal_runs(self):
        self.assertTrue(candidate(self.old, self.anchor, self.repo, 5, set()))
        mutations = [{"event": event} for event in ("workflow_dispatch", "schedule", "release", "pull_request", "workflow_run")]
        mutations += [{"path": ".github/workflows/" + name} for name in ("codeql.yml", "security-scan.yml", "release.yml")]
        mutations += [{"head_branch": "v0.6.6"}, {"run_attempt": 2}, {"workflow_id": 6}, {"run_number": 21}, {"head_sha": self.anchor["head_sha"]}, {"head_sha": "invalid"}, {"status": "completed"}, {"repository": {"full_name": "foreign/product"}}, {"head_repository": {"full_name": "foreign/product"}}]
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                self.assertFalse(candidate(dict(self.old, **mutation), self.anchor, self.repo, 5, set()))
        self.assertFalse(candidate(self.old, self.anchor, self.repo, 5, {self.old["head_sha"]}))

    def test_cancellation_requires_ancestry_current_attempt_and_preserved_receipt(self):
        test = self

        class Fake:
            root = "repos/" + test.repo
            allow_ancestry = True
            changed_attempt = False
            validated = True

            def __init__(self):
                self.posts = []
                self.saved = []

            def api(self, path, method="GET"):
                if method == "POST":
                    test.assertTrue(self.saved[-1]["cancelled_development"][0]["before_cancel"]["jobs"])
                    self.posts.append(path)
                    return {}
                return {"id": 5, "path": CI_PATH, "state": "active"}

            def run(self, run_id):
                return test.anchor if run_id == 20 else dict(test.old, run_attempt=2 if self.changed_attempt else 1)

            def active(self, unused):
                return [test.old, test.anchor, dict(test.old, id=30, event="workflow_dispatch", head_sha="c" * 40)]

            def ancestor(self, older, newer):
                test.assertEqual((older, newer), (test.old["head_sha"], test.anchor["head_sha"]))
                return self.allow_ancestry

            def evidence(self, unused):
                return {"jobs": [{"name": "action-pins", "conclusion": "success" if self.validated else "failure"}], "artifacts": [{"id": 17}]}

        for validated, ancestry, changed, expected in [(True, True, False, 1), (False, True, False, 0), (True, False, False, 0), (True, True, True, 0)]:
            api = Fake()
            api.validated, api.allow_ancestry, api.changed_attempt = validated, ancestry, changed
            receipt = {"cancelled_development": []}
            coalesce(api, self.repo, 20, receipt, lambda: api.saved.append(deepcopy(receipt)))
            self.assertEqual(len(api.posts), expected)

    def test_canceled_source_is_a_noop_before_reading_or_changing_other_runs(self):
        test = self

        class Superseded:
            root = "repos/" + test.repo

            def api(self, path, method="GET"):
                test.assertEqual(method, "GET")
                test.assertEqual(path, self.root + "/actions/workflows/ci.yml")
                return {"id": 5, "path": CI_PATH, "state": "active"}

            def run(self, run_id):
                test.assertEqual(run_id, 20)
                return dict(test.anchor, status="completed", conclusion="cancelled")

        receipt = {"cancelled_development": []}
        saved = []
        coalesce(Superseded(), self.repo, 20, receipt, lambda: saved.append(deepcopy(receipt)))
        self.assertEqual(receipt["cancelled_development"], [])
        self.assertEqual(saved, [{"cancelled_development": [], "status": "unchanged: source already canceled"}])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--selftest", action="store_true")
    parser.add_argument("--output", type=Path, default=Path("artifacts/ci-development/receipt.json"))
    args = parser.parse_args()
    if args.selftest:
        result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(CoalescingTests))
        return 0 if result.wasSuccessful() else 1
    event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
    if os.environ["GITHUB_EVENT_NAME"] != "workflow_run" or event.get("action") != "in_progress":
        raise ValueError("only source CI start notifications are supported")
    source_id = int(os.environ["SOURCE_RUN_ID"])
    if source_id <= 0 or event.get("workflow_run", {}).get("id") != source_id:
        raise ValueError("invalid source run")
    repository = os.environ["GITHUB_REPOSITORY"]
    receipt = {"schema_version": 1, "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(), "repository": repository, "cancelled_development": []}
    args.output.parent.mkdir(parents=True, exist_ok=True)

    def save():
        args.output.write_text(json.dumps(receipt, indent=2) + "\n")

    save()
    api = GitHub(repository)
    deadline = time.monotonic() + 15 * 60
    while True:
        jobs = api.evidence(source_id)["jobs"]
        pins = [job for job in jobs if job.get("name") == "action-pins"]
        if any(job.get("status") == "completed" for job in pins) or time.monotonic() >= deadline:
            break
        time.sleep(20)
    coalesce(api, repository, source_id, receipt, save)
    print(receipt["status"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
