#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""Seal, verify, and query exact-source probectl evidence receipts."""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


SCHEMA = "probectl.evidence-receipt/v1"
SHA_RE = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
RESULTS = {"pass", "fail", "error"}


class ReceiptError(ValueError):
    """A receipt is incomplete, contradictory, stale, or altered."""


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def git(repo: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", "-C", str(repo), *args],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if proc.returncode:
        raise ReceiptError(f"git {' '.join(args)} failed: {proc.stderr.strip()}")
    return proc.stdout.strip()


def source_state(repo: Path) -> dict[str, Any]:
    sha = git(repo, "rev-parse", "HEAD")
    if not SHA_RE.fullmatch(sha):
        raise ReceiptError(f"unexpected git SHA: {sha!r}")
    dirty_paths = [
        line
        for line in git(
            repo, "status", "--porcelain=v1", "--untracked-files=all"
        ).splitlines()
        if line
    ]
    return {
        "git_sha": sha,
        "tree_sha": git(repo, "rev-parse", "HEAD^{tree}"),
        "branch": git(repo, "rev-parse", "--abbrev-ref", "HEAD"),
        "dirty": bool(dirty_paths),
        "dirty_path_count": len(dirty_paths),
    }


def require_string(value: dict[str, Any], key: str) -> str:
    item = value.get(key)
    if not isinstance(item, str) or not item.strip():
        raise ReceiptError(f"{key} must be a non-empty string")
    return item


def validate_draft(draft: dict[str, Any]) -> None:
    for key in ("receipt_id", "profile", "started_at", "completed_at", "result"):
        require_string(draft, key)
    if draft["result"] not in RESULTS:
        raise ReceiptError(f"result must be one of {sorted(RESULTS)}")
    claims = draft.get("claims")
    if (
        not isinstance(claims, list)
        or not claims
        or any(not isinstance(item, str) or not item for item in claims)
    ):
        raise ReceiptError("claims must be a non-empty string array")
    if len(claims) != len(set(claims)):
        raise ReceiptError("claims must not contain duplicates")
    for key in ("thresholds", "dependencies"):
        if not isinstance(draft.get(key), dict) or not draft[key]:
            raise ReceiptError(f"{key} must be a non-empty object")


def artifact_rows(paths: list[Path], output: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    names: set[str] = set()
    for path in paths:
        resolved = path.resolve()
        if not resolved.is_file():
            raise ReceiptError(f"artifact is missing or not a file: {path}")
        name = resolved.name
        if name in names:
            raise ReceiptError(f"duplicate artifact basename: {name}")
        names.add(name)
        if resolved.parent != output.resolve().parent:
            raise ReceiptError(
                f"artifact must be beside the receipt for offline verification: {resolved}"
            )
        rows.append(
            {
                "path": name,
                "bytes": resolved.stat().st_size,
                "sha256": sha256_file(resolved),
            }
        )
    if not rows:
        raise ReceiptError("at least one artifact is required")
    return sorted(rows, key=lambda row: row["path"])


def seal(
    draft_path: Path,
    artifact_paths: list[Path],
    output: Path,
    repo: Path,
    record_dirty: bool,
) -> dict[str, Any]:
    if output.exists():
        raise ReceiptError(f"refusing to overwrite immutable receipt: {output}")
    draft = json.loads(draft_path.read_text(encoding="utf-8"))
    if not isinstance(draft, dict):
        raise ReceiptError("draft must be a JSON object")
    validate_draft(draft)
    source = source_state(repo)
    if source["dirty"] and not record_dirty:
        raise ReceiptError(
            "source checkout is dirty; use --record-dirty for a non-promotable diagnostic receipt"
        )
    envelope = {
        "schema": SCHEMA,
        "receipt_id": draft["receipt_id"],
        "claims": sorted(draft["claims"]),
        "source": source,
        "run": {
            "profile": draft["profile"],
            "started_at": draft["started_at"],
            "completed_at": draft["completed_at"],
            "result": draft["result"],
        },
        "environment": draft.get(
            "environment",
            {"host": platform.platform(), "python": platform.python_version()},
        ),
        "dependencies": draft["dependencies"],
        "thresholds": draft["thresholds"],
        "artifacts": artifact_rows(artifact_paths, output),
        "notes": draft.get("notes", []),
    }
    envelope["integrity"] = {
        "algorithm": "sha256",
        "canonical_payload_sha256": hashlib.sha256(
            canonical_bytes(envelope)
        ).hexdigest(),
    }
    output.write_text(
        json.dumps(envelope, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return envelope


def validate_envelope(
    receipt: dict[str, Any], path: Path, verify_artifacts: bool = True
) -> None:
    if receipt.get("schema") != SCHEMA:
        raise ReceiptError(f"{path}: unsupported schema {receipt.get('schema')!r}")
    require_string(receipt, "receipt_id")
    claims = receipt.get("claims")
    if not isinstance(claims, list) or not claims or len(claims) != len(set(claims)):
        raise ReceiptError(f"{path}: claims are missing or duplicated")
    source = receipt.get("source")
    if not isinstance(source, dict) or not SHA_RE.fullmatch(
        str(source.get("git_sha", ""))
    ):
        raise ReceiptError(f"{path}: source.git_sha is invalid")
    if not isinstance(source.get("dirty"), bool):
        raise ReceiptError(f"{path}: source.dirty must be explicit")
    run = receipt.get("run")
    if not isinstance(run, dict) or run.get("result") not in RESULTS:
        raise ReceiptError(f"{path}: run result is invalid")
    for key in ("profile", "started_at", "completed_at"):
        require_string(run, key)
    for key in ("dependencies", "thresholds"):
        if not isinstance(receipt.get(key), dict) or not receipt[key]:
            raise ReceiptError(f"{path}: {key} must be a non-empty object")
    integrity = receipt.get("integrity")
    if not isinstance(integrity, dict) or integrity.get("algorithm") != "sha256":
        raise ReceiptError(f"{path}: integrity metadata is invalid")
    without_integrity = dict(receipt)
    without_integrity.pop("integrity", None)
    actual = hashlib.sha256(canonical_bytes(without_integrity)).hexdigest()
    if integrity.get("canonical_payload_sha256") != actual:
        raise ReceiptError(f"{path}: canonical payload hash mismatch")
    artifacts = receipt.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        raise ReceiptError(f"{path}: artifacts are missing")
    if verify_artifacts:
        for row in artifacts:
            artifact = path.parent / str(row.get("path", ""))
            if not artifact.is_file():
                raise ReceiptError(f"{path}: artifact missing: {artifact.name}")
            if artifact.stat().st_size != row.get("bytes") or sha256_file(
                artifact
            ) != row.get("sha256"):
                raise ReceiptError(f"{path}: artifact changed: {artifact.name}")


def load_and_validate(path: Path, verify_artifacts: bool = True) -> dict[str, Any]:
    try:
        receipt = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ReceiptError(f"cannot read {path}: {exc}") from exc
    if not isinstance(receipt, dict):
        raise ReceiptError(f"{path}: receipt must be a JSON object")
    validate_envelope(receipt, path, verify_artifacts)
    return receipt


def strict_status(receipt: dict[str, Any], repo: Path) -> str:
    source = source_state(repo)
    if receipt["run"]["result"] != "pass":
        return "FAILED"
    if receipt["source"]["dirty"]:
        return "NON_PROMOTABLE_DIRTY"
    if source["dirty"]:
        return "CURRENT_CHECKOUT_DIRTY"
    if receipt["source"]["git_sha"] != source["git_sha"]:
        return "STALE_SHA"
    return "VERIFIED_LIVE_CURRENT_HEAD"


def query_claim(root: Path, claim: str, repo: Path) -> list[dict[str, str]]:
    found: list[dict[str, str]] = []
    for path in sorted(root.rglob("*.json")):
        try:
            receipt = load_and_validate(path)
        except ReceiptError:
            continue
        if claim in receipt["claims"]:
            found.append(
                {
                    "receipt_id": receipt["receipt_id"],
                    "path": str(path),
                    "git_sha": receipt["source"]["git_sha"],
                    "status": strict_status(receipt, repo),
                }
            )
    return found


def catalog_claims(path: Path | None) -> dict[str, dict[str, str]]:
    if path is None:
        return {}
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ReceiptError(f"cannot read claim catalog {path}: {exc}") from exc
    rows = value.get("claims") if isinstance(value, dict) else value
    if not isinstance(rows, list):
        raise ReceiptError(
            "claim catalog must be an array or an object with a claims array"
        )
    claims: dict[str, dict[str, str]] = {}
    for row in rows:
        claim = row.get("id") if isinstance(row, dict) else row
        if not isinstance(claim, str) or not claim.strip():
            raise ReceiptError(
                "every claim catalog row must be a string or an object with an id"
            )
        if claim in claims:
            raise ReceiptError(f"claim catalog contains duplicate id: {claim}")
        metadata: dict[str, str] = {}
        if isinstance(row, dict):
            for key in ("kind", "owner", "title"):
                value = row.get(key)
                if value is not None:
                    if not isinstance(value, str) or not value.strip():
                        raise ReceiptError(
                            f"claim catalog {claim} has invalid {key} metadata"
                        )
                    metadata[key] = value
        claims[claim] = metadata
    return claims


def aggregate_claim_status(
    claim: str, receipts: list[tuple[Path, dict[str, Any]]], repo: Path
) -> str:
    if not receipts:
        return "UNVERIFIED"
    checkout = source_state(repo)
    current_clean = [
        receipt
        for _, receipt in receipts
        if receipt["source"]["git_sha"] == checkout["git_sha"]
        and not receipt["source"]["dirty"]
    ]
    current_results = {receipt["run"]["result"] for receipt in current_clean}
    if len(current_results) > 1:
        raise ReceiptError(
            f"claim {claim} has contradictory clean current-SHA results: "
            f"{sorted(current_results)}"
        )
    statuses = {strict_status(receipt, repo) for _, receipt in receipts}
    for status in (
        "VERIFIED_LIVE_CURRENT_HEAD",
        "CURRENT_CHECKOUT_DIRTY",
        "NON_PROMOTABLE_DIRTY",
        "FAILED",
        "STALE_SHA",
    ):
        if status in statuses:
            return status
    raise ReceiptError(f"claim {claim} has no resolvable strict status")


def build_claim_index(root: Path, catalog: Path | None, repo: Path) -> dict[str, Any]:
    by_claim: dict[str, list[tuple[Path, dict[str, Any]]]] = {}
    catalog_rows = catalog_claims(catalog)
    claim_ids = set(catalog_rows)
    for path in sorted(root.rglob("*.json")):
        try:
            receipt = load_and_validate(path)
        except ReceiptError:
            continue
        for claim in receipt["claims"]:
            claim_ids.add(claim)
            by_claim.setdefault(claim, []).append((path, receipt))
    rows: list[dict[str, Any]] = []
    for claim in sorted(claim_ids):
        receipts = by_claim.get(claim, [])
        evidence = [
            {
                "receipt_id": receipt["receipt_id"],
                "path": str(path),
                "git_sha": receipt["source"]["git_sha"],
                "status": strict_status(receipt, repo),
            }
            for path, receipt in receipts
        ]
        row = {
            "claim": claim,
            "status": aggregate_claim_status(claim, receipts, repo),
            "evidence": evidence,
        }
        row.update(catalog_rows.get(claim, {}))
        rows.append(row)
    return {
        "schema": "probectl.claim-status-index/v1",
        "source": source_state(repo),
        "claims": rows,
    }


def selftest() -> None:
    with tempfile.TemporaryDirectory(prefix="probectl-receipt-") as temp:
        root = Path(temp)
        repo = root / "repo"
        bundle = root / "bundle"
        repo.mkdir()
        bundle.mkdir()
        git(repo, "init", "-q")
        git(repo, "config", "user.email", "receipt@example.invalid")
        git(repo, "config", "user.name", "Receipt Selftest")
        (repo / "source.txt").write_text("source\n", encoding="utf-8")
        git(repo, "add", "source.txt")
        git(repo, "commit", "-qm", "selftest source")
        artifact = bundle / "gate.log"
        artifact.write_text("PASS\n", encoding="utf-8")
        draft = bundle / "draft.json"
        draft.write_text(
            json.dumps(
                {
                    "receipt_id": "selftest",
                    "claims": ["F1", "N1"],
                    "profile": "selftest",
                    "started_at": "2026-08-09T00:00:00Z",
                    "completed_at": "2026-08-09T00:00:01Z",
                    "result": "pass",
                    "dependencies": {"fixture": "1"},
                    "thresholds": {"failures": 0},
                }
            ),
            encoding="utf-8",
        )
        output = bundle / "receipt.json"
        sealed = seal(draft, [artifact], output, repo, record_dirty=False)
        validate_envelope(sealed, output)
        if strict_status(sealed, repo) != "VERIFIED_LIVE_CURRENT_HEAD":
            raise ReceiptError("selftest current-SHA receipt was not promoted")
        found = query_claim(bundle, "F1", repo)
        if len(found) != 1 or found[0]["status"] != "VERIFIED_LIVE_CURRENT_HEAD":
            raise ReceiptError(
                "selftest claim query did not return the current receipt"
            )
        catalog = bundle / "catalog.json"
        catalog.write_text(
            json.dumps(
                {
                    "claims": [
                        {"id": "F1", "kind": "capability", "owner": "agent"},
                        {"id": "F2", "kind": "capability", "owner": "release"},
                    ]
                }
            ),
            encoding="utf-8",
        )
        index = build_claim_index(bundle, catalog, repo)
        statuses = {row["claim"]: row["status"] for row in index["claims"]}
        if statuses != {
            "F1": "VERIFIED_LIVE_CURRENT_HEAD",
            "F2": "UNVERIFIED",
            "N1": "VERIFIED_LIVE_CURRENT_HEAD",
        }:
            raise ReceiptError(f"selftest claim index statuses are wrong: {statuses}")
        f1 = next(row for row in index["claims"] if row["claim"] == "F1")
        if f1.get("kind") != "capability" or f1.get("owner") != "agent":
            raise ReceiptError("selftest claim catalog metadata was not preserved")
        failed_draft = bundle / "failed-draft.json"
        failed_value = json.loads(draft.read_text(encoding="utf-8"))
        failed_value["receipt_id"] = "selftest-failed"
        failed_value["result"] = "fail"
        failed_draft.write_text(json.dumps(failed_value), encoding="utf-8")
        seal(failed_draft, [artifact], bundle / "failed-receipt.json", repo, False)
        try:
            build_claim_index(bundle, catalog, repo)
        except ReceiptError as exc:
            if "contradictory" not in str(exc):
                raise
        else:
            raise ReceiptError(
                "selftest contradictory current-SHA receipts were accepted"
            )

        (bundle / "failed-receipt.json").unlink()
        (repo / "source.txt").write_text("dirty\n", encoding="utf-8")
        if strict_status(sealed, repo) != "CURRENT_CHECKOUT_DIRTY":
            raise ReceiptError("selftest dirty checkout was not demoted")
        try:
            seal(draft, [artifact], bundle / "dirty.json", repo, record_dirty=False)
        except ReceiptError:
            pass
        else:
            raise ReceiptError("selftest dirty checkout was sealed as promotable")
        git(repo, "add", "source.txt")
        git(repo, "commit", "-qm", "advance selftest source")
        if strict_status(sealed, repo) != "STALE_SHA":
            raise ReceiptError("selftest changed HEAD did not demote the receipt")
        artifact.write_text("TAMPERED\n", encoding="utf-8")
        try:
            load_and_validate(output)
        except ReceiptError:
            pass
        else:
            raise ReceiptError("selftest altered artifact was accepted")
    print("evidence-receipt selftest: OK")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    seal_parser = sub.add_parser("seal")
    seal_parser.add_argument("--draft", type=Path, required=True)
    seal_parser.add_argument("--artifact", type=Path, action="append", required=True)
    seal_parser.add_argument("--output", type=Path, required=True)
    seal_parser.add_argument("--repo", type=Path, default=Path("."))
    seal_parser.add_argument("--record-dirty", action="store_true")
    verify_parser = sub.add_parser("verify")
    verify_parser.add_argument("receipt", type=Path)
    verify_parser.add_argument("--repo", type=Path, default=Path("."))
    verify_parser.add_argument("--require-current", action="store_true")
    query_parser = sub.add_parser("query")
    query_parser.add_argument("--root", type=Path, required=True)
    query_parser.add_argument("--claim", required=True)
    query_parser.add_argument("--repo", type=Path, default=Path("."))
    index_parser = sub.add_parser("index")
    index_parser.add_argument("--root", type=Path, required=True)
    index_parser.add_argument("--catalog", type=Path)
    index_parser.add_argument("--output", type=Path)
    index_parser.add_argument("--repo", type=Path, default=Path("."))
    sub.add_parser("selftest")
    args = parser.parse_args()

    try:
        if args.command == "seal":
            receipt = seal(
                args.draft, args.artifact, args.output, args.repo, args.record_dirty
            )
            print(
                json.dumps(
                    {"path": str(args.output), "receipt_id": receipt["receipt_id"]},
                    sort_keys=True,
                )
            )
        elif args.command == "verify":
            receipt = load_and_validate(args.receipt)
            status = strict_status(receipt, args.repo)
            if args.require_current and status != "VERIFIED_LIVE_CURRENT_HEAD":
                raise ReceiptError(f"receipt is not current strict proof: {status}")
            print(
                json.dumps(
                    {"receipt_id": receipt["receipt_id"], "status": status},
                    sort_keys=True,
                )
            )
        elif args.command == "query":
            print(
                json.dumps(
                    query_claim(args.root, args.claim, args.repo),
                    indent=2,
                    sort_keys=True,
                )
            )
        elif args.command == "index":
            rendered = (
                json.dumps(
                    build_claim_index(args.root, args.catalog, args.repo),
                    indent=2,
                    sort_keys=True,
                )
                + "\n"
            )
            if args.output:
                args.output.write_text(rendered, encoding="utf-8")
            else:
                print(rendered, end="")
        else:
            selftest()
    except (OSError, ReceiptError, json.JSONDecodeError) as exc:
        print(f"evidence-receipt: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
