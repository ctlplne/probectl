#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
#
# Use of this source code is governed by the Business Source License 1.1
# in the LICENSE file at the root of this repository; on its Change Date
# each version converts to the Mozilla Public License 2.0.

"""Observe complete renderer/stager/verifier RSS in isolated Linux CI workers."""

import argparse
import json
import os
from pathlib import Path
import platform
import re
import resource
import subprocess
import sys
import time

CASES = {
    "csv": ("TestReportBodyStageStreamsCompleteCSV", 500_000),
    "pdf": ("TestReportBodyStageStreamsCompletePDF", 4_000),
}
MAX_BYTES = 256 << 20
MAX_ALLOCATION = MAX_BYTES + (MAX_BYTES // (64 << 10)) * 64 + (256 << 10)


def classify(kind: str, output: str, returncode: int) -> dict[str, int]:
    root, expected = CASES[kind]
    lines = output.splitlines()
    if (
        returncode != 0
        or lines.count("=== RUN   " + root) != 1
        or sum(line.startswith("--- PASS: " + root + " (") for line in lines) != 1
        or lines.count("PASS") != 1
        or "--- FAIL:" in output
        or "--- SKIP:" in output
    ):
        raise RuntimeError(
            "memory observation did not execute its complete output root"
        )
    metrics = re.findall(
        rf"\b{kind.upper()} staging: logical_rows=(\d+) bytes=(\d+) charged_allocation=(\d+)\b",
        output,
    )
    if len(metrics) != 1:
        raise RuntimeError("memory observation lost exact complete output metrics")
    rows, size, allocation = map(int, metrics[0])
    if (
        rows != expected
        or not (2 << 20) < size <= MAX_BYTES
        or not size <= allocation <= MAX_ALLOCATION
    ):
        raise RuntimeError("memory observation received incomplete or unbounded output")
    return {
        "logical_rows": rows,
        "bytes": size,
        "charged_staging_allocation": allocation,
    }


def selftest() -> None:
    for kind, (root, rows) in CASES.items():
        output = f"=== RUN   {root}\n{kind.upper()} staging: logical_rows={rows} bytes=26000000 charged_allocation=27000000 complete\n--- PASS: {root} (1.00s)\nPASS\n"
        classify(kind, output, 0)
        for bad, code in (
            (output, 1),
            (output.replace("=== RUN   " + root, ""), 0),
            (output + output, 0),
            (output.replace("--- PASS:", "--- SKIP:"), 0),
            (output.replace(f"logical_rows={rows}", "logical_rows=1"), 0),
            (output.replace("bytes=26000000", "bytes=2000"), 0),
            (
                output.replace(
                    "charged_allocation=27000000", "charged_allocation=999999999"
                ),
                0,
            ),
        ):
            try:
                classify(kind, bad, code)
            except RuntimeError:
                pass
            else:
                raise RuntimeError(
                    "memory classifier accepted vacuous or incomplete proof"
                )
    print(
        "Body memory classifier refuses missing/skipped/duplicate/failed/incomplete output"
    )


def measure(kind: str, binary: Path, output: Path, sha: str) -> None:
    # This fresh worker has not compiled or spawned anything. Its only child
    # is the exact test binary; Linux ru_maxrss therefore excludes the compiler.
    if resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss != 0:
        raise RuntimeError("memory worker is not fresh")
    root, _ = CASES[kind]
    started = time.monotonic()
    result = subprocess.run(
        [
            str(binary),
            "-test.v=true",
            "-test.count=1",
            "-test.timeout=3m",
            "-test.run=^" + root + "$",
        ],
        text=True,
        capture_output=True,
        check=False,
        timeout=200,
    )
    usage = resource.getrusage(resource.RUSAGE_CHILDREN)
    (output / (kind + ".log")).write_text(result.stdout + result.stderr)
    metrics = classify(kind, result.stdout, result.returncode)
    if usage.ru_maxrss <= 0:
        raise RuntimeError("kernel returned no child peak memory observation")
    receipt = {
        "sha": sha,
        "format": kind,
        "test": root,
        "compiler_excluded": True,
        "race_instrumented": False,
        "peak_rss_kib": usage.ru_maxrss,
        "elapsed_seconds_observation": time.monotonic() - started,
        "platform": platform.system(),
        "architecture": platform.machine(),
        "scope": "Whole renderer/stager/test-verifier process, including fonts/runtime/independent verification; not source-only or production-only RSS",
        **metrics,
    }
    (output / (kind + ".json")).write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps(receipt))


def run(output: Path) -> None:
    output.mkdir(parents=True, exist_ok=True)
    for name in ("csv.json", "pdf.json", "receipt.json"):
        (output / name).unlink(missing_ok=True)
    sha = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    if not re.fullmatch(r"[0-9a-f]{40}", sha):
        raise RuntimeError("checked source identity is unavailable")
    subprocess.run(["git", "diff", "--quiet", "--", "internal/reporting"], check=True)
    binary = (output / "reporting.test").resolve()
    try:
        subprocess.run(
            ["go", "test", "-c", "-o", str(binary), "./internal/reporting"],
            check=True,
            timeout=300,
        )
        for kind in CASES:
            subprocess.run(
                [
                    sys.executable,
                    str(Path(__file__).resolve()),
                    "--measure",
                    kind,
                    "--binary",
                    str(binary),
                    "--sha",
                    sha,
                    "--output",
                    str(output.resolve()),
                ],
                check=True,
                timeout=240,
            )
        receipts = [
            json.loads((output / (kind + ".json")).read_text()) for kind in CASES
        ]
        if any(
            r["sha"] != sha or r["format"] != kind
            for kind, r in zip(CASES, receipts, strict=True)
        ):
            raise RuntimeError("memory receipts disagree with the checked source")
        (output / "receipt.json").write_text(
            json.dumps({"sha": sha, "measurements": receipts}, indent=2) + "\n"
        )
    finally:
        binary.unlink(missing_ok=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--selftest", action="store_true")
    parser.add_argument("--measure", choices=CASES)
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--sha")
    parser.add_argument("--output", type=Path, default=Path("dist/report-body-memory"))
    args = parser.parse_args()
    if args.selftest:
        selftest()
        return
    if os.environ.get("GITHUB_ACTIONS") != "true" or sys.platform != "linux":
        raise RuntimeError("actual body memory observations require isolated Linux CI")
    if args.measure:
        if args.binary is None or not re.fullmatch(r"[0-9a-f]{40}", args.sha or ""):
            raise RuntimeError("memory worker requires its exact compiled source")
        measure(args.measure, args.binary, args.output, args.sha)
    else:
        run(args.output)


if __name__ == "__main__":
    main()
