#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
# Use of this source code is governed by the Business Source License 1.1
# in the LICENSE file at the root of this repository; on its Change Date
# each version converts to the Mozilla Public License 2.0.
"""Require the same-router FRR/SNMP/captured-IPFIX role proof; no skipped root."""

from pathlib import Path
import subprocess

from ci_tag_consumer_proof import classify

ROOT = "TestInterfaceRoleFRRSameRouterKeepsThreeRolesFlowAndOverride"
PACKAGE = "github.com/ctlplne/probectl/internal/bgp"


def main():
    out = Path("artifacts/interface-role-router")
    out.mkdir(parents=True, exist_ok=True)
    result = subprocess.run(
        ["go", "test", "-race", "-json", "-count=1", "-tags=integration",
         "-timeout=15m", "-run", "^" + ROOT + "$", "./internal/bgp"],
        text=True, capture_output=True, timeout=960, check=False,
    )
    (out / "router.jsonl").write_text(result.stdout)
    (out / "router.stderr.txt").write_text(result.stderr)
    print(result.stdout, end="")
    print(result.stderr, end="")
    errors = classify(result.stdout, result.returncode, package=PACKAGE, tests=(ROOT,))
    if errors:
        raise RuntimeError("required real-router role proof missing/failed: " + str(errors))


if __name__ == "__main__":
    main()
