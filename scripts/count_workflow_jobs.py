#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-probectl-TBD
"""Count top-level GitHub Actions jobs from checked-in workflow YAML.

This intentionally avoids PyYAML so the docs gate works in a bare Python
environment. The workflow files use the ordinary GitHub Actions shape:

jobs:
  job-id:
    ...

Only those direct children of `jobs:` are counted.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path


JOB_ID = re.compile(r"^  ([A-Za-z0-9_-]+):\s*(?:#.*)?$")


def workflow_jobs(path: Path) -> list[str]:
    jobs: list[str] = []
    in_jobs = False
    for line in path.read_text().splitlines():
        if re.match(r"^jobs:\s*(?:#.*)?$", line):
            in_jobs = True
            continue
        if not in_jobs:
            continue
        if line and not line.startswith(" ") and not line.startswith("#"):
            break
        m = JOB_ID.match(line)
        if m:
            jobs.append(m.group(1))
    return jobs


def workflow_paths(root: Path) -> list[Path]:
    workflows = root / ".github" / "workflows"
    return sorted([*workflows.glob("*.yml"), *workflows.glob("*.yaml")])


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--total", action="store_true", help="print only the total count")
    parser.add_argument("--json", action="store_true", help="print machine-readable counts")
    args = parser.parse_args()

    counts = {str(path.relative_to(args.root)): workflow_jobs(path) for path in workflow_paths(args.root)}
    total = sum(len(jobs) for jobs in counts.values())
    if args.total:
        print(total)
    elif args.json:
        print(json.dumps({"total": total, "workflows": counts}, indent=2))
    else:
        for path, jobs in counts.items():
            print(f"{path}: {len(jobs)}")
        print(f"total: {total}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
