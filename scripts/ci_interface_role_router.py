#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
# Use of this source code is governed by the Business Source License 1.1
# in the LICENSE file at the root of this repository; on its Change Date
# each version converts to the Mozilla Public License 2.0.
"""Require the same-router FRR/SNMP/captured-IPFIX role proof; no skipped root."""

from pathlib import Path
import json
import subprocess

from ci_tag_consumer_proof import classify, report_regression_failed_on_assertion
from ci_interface_prefix_transport import overlay_source_path

ROOT = "TestInterfaceRoleFRRSameRouterKeepsThreeRolesFlowAndOverride"
PACKAGE = "github.com/ctlplne/probectl/internal/bgp"
SURFACES = tuple(ROOT + "/" + theme + "/" + tenant + "/" + surface
                 for theme in ("light", "dark")
                 for tenant in ("primary", "paired")
                 for surface in ("admin", "flow"))
PATH_HEALTH = (
    ROOT + "/routed-path-health",
    *(ROOT + "/routed-path-health/" + tenant for tenant in ("primary", "paired")),
    *(ROOT + "/routed-path-health/" + tenant + "/" + theme
      for tenant in ("primary", "paired") for theme in ("light", "dark")),
    *(ROOT + "/routed-path-health/" + tenant + "/stdio/" + wire
      for tenant in ("primary", "paired") for wire in ("2026-07-28", "2025-11-25")),
)


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
    errors = classify(result.stdout, result.returncode, package=PACKAGE, tests=(ROOT, *SURFACES, *PATH_HEALTH, *(ROOT + "/stdio/" + wire for wire in ("2026-07-28", "2025-11-25"))))
    if errors:
        raise RuntimeError("required real-router role proof missing/failed: " + str(errors))
    # One focused real child models an unexecuted/missing browser report. The
    # full positive above independently requires all eight served surfaces.
    source = Path("internal/testsupport/render.go").resolve()
    original = source.read_text()
    seam = "res := renderOnce(t, spec)"
    assert original.count(seam) == 1
    mutant = overlay_source_path(out, "missing-accessibility.go")
    mutant.write_text(original.replace(seam, seam + "\nif spec.Accessibility { res.Accessibility = nil }"))
    overlay = out / "missing-accessibility.json"
    overlay.write_text(json.dumps({"Replace": {str(source): str(mutant.resolve())}}))
    child = "light/primary/admin"
    control = subprocess.run(
        ["go", "test", "-race", "-json", "-count=1", "-tags=integration",
         "-timeout=15m", "-overlay", str(overlay.resolve()),
         "-run", "^" + ROOT + "$/^light$/^primary$/^admin$", "./internal/bgp"],
        text=True, capture_output=True, timeout=960, check=False,
    )
    (out / "missing-accessibility.jsonl").write_text(control.stdout)
    (out / "missing-accessibility.stderr.txt").write_text(control.stderr)
    print(control.stdout, end="")
    print(control.stderr, end="")
    if not report_regression_failed_on_assertion(
        control.stdout, control.returncode, package=PACKAGE, root=ROOT,
        child=child, marker="served accessibility proof was missing or unexecuted",
    ):
        raise RuntimeError("missing served accessibility report did not fail its exact assertion")



if __name__ == "__main__":
    main()
