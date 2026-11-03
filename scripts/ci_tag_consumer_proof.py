#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
#
# Use of this source code is governed by the Business Source License 1.1
# in the LICENSE file at the root of this repository; on its Change Date
# each version converts to the Mozilla Public License 2.0.

"""Mandatory paired alert/native component proof on a fresh TLS CI database."""

import argparse
import json
import os
import subprocess
import sys
from urllib.parse import parse_qs, urlsplit, urlunsplit

PACKAGE = "github.com/ctlplne/probectl/internal/control"
TESTS = (
    "TestAlertTagFiltersRecheckCurrentOwnedUserAndNeverRewriteSeries",
    "TestTagMCPMetadataMutationsUseRealTenantAuthorizationAndAtomicAudit",
)
DATABASE = "probectl_qa_beta_tag_consumers"


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
