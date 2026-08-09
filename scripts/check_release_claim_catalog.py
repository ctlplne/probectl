#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""Validate complete, uniquely owned release/backlog claim coverage."""

from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
CATALOG = ROOT / "docs" / "claims" / "release-catalog.json"
REGISTER = ROOT / "docs" / "claims" / "register.json"


def fail(message: str) -> None:
    raise SystemExit(f"release-claim-catalog: {message}")


def main() -> None:
    catalog = json.loads(CATALOG.read_text(encoding="utf-8"))
    register = json.loads(REGISTER.read_text(encoding="utf-8"))
    rows = catalog.get("claims")
    if not isinstance(rows, list):
        fail("claims must be an array")

    ids: list[str] = []
    for row in rows:
        if not isinstance(row, dict):
            fail("every row must be an object")
        claim = row.get("id")
        owner = row.get("owner")
        kind = row.get("kind")
        if not isinstance(claim, str) or not claim:
            fail("every row needs a non-empty id")
        if not isinstance(owner, str) or not owner:
            fail(f"{claim} has no owner")
        if not isinstance(kind, str) or not kind:
            fail(f"{claim} has no kind")
        ids.append(claim)
    if len(ids) != len(set(ids)):
        fail("duplicate ids")

    required = {
        *(f"F{i}" for i in range(1, 58)),
        *(f"N{i}" for i in range(1, 14)),
        *(f"BL-{i:03d}" for i in range(1, 49)),
        *(row["id"] for row in register["claims"]),
    }
    missing = sorted(required - set(ids))
    extra = sorted(set(ids) - required)
    if missing or extra:
        fail(f"coverage drift; missing={missing}, extra={extra}")

    print(
        "release-claim-catalog: OK "
        f"({len(rows)} claims; F1-F57, N1-N13, BL-001-BL-048, governed register)"
    )


if __name__ == "__main__":
    main()
