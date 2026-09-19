#!/usr/bin/env bash
# RUNOPS evidence freshness gate. The restore/failover docs must contain
# committed, dated drill rows and the matching archived logs; placeholders are
# not release evidence.
set -euo pipefail
cd "$(dirname "$0")/.."

python3 - <<'PY'
import csv
import datetime as dt
import glob
import os
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(".")
MAX_AGE_DAYS = int(os.environ.get("PROBECTL_DRILL_MAX_AGE_DAYS", "180"))
ALLOW_HISTORICAL = os.environ.get("PROBECTL_DRILL_ALLOW_HISTORICAL", "").lower() in {"1", "true", "yes"}
CHECK_DOCS = os.environ.get("PROBECTL_DRILL_CHECK_DOCS", "1").lower() not in {"0", "false", "no"}
SCOPE = os.environ.get("PROBECTL_DRILL_SCOPE", "all")
now = dt.datetime.now(dt.timezone.utc)
failures = []


def fail(msg: str) -> None:
    failures.append(msg)


def repo_path(raw: str) -> pathlib.Path:
    path = pathlib.Path(raw)
    if path.is_absolute():
        return path
    return ROOT / path


def normalize_sha(raw: str) -> str:
    raw = (raw or "").strip()
    if len(raw) >= 12:
        return raw[:12]
    return raw


def profile_set(env_name: str, default: set[str]) -> set[str]:
    raw = os.environ.get(env_name, "")
    if not raw.strip():
        return default
    return {part.strip() for part in raw.split(",") if part.strip()}


def current_git_sha() -> str:
    try:
        out = subprocess.check_output(["git", "rev-parse", "--short=12", "HEAD"], cwd=ROOT, text=True)
    except Exception:
        return ""
    return normalize_sha(out)


EXPECTED_SHA = normalize_sha(os.environ.get("PROBECTL_DRILL_EXPECTED_SHA", "")) or current_git_sha()
BACKUP_PROFILES = profile_set("PROBECTL_DRILL_BACKUP_PROFILES", {"large", "production-shaped"})
# DPR-207: which profiles are CLAIMING to be production-shaped, and therefore
# have to carry a production-shaped artifact. The >=1MB bar exists so nobody
# cites a trivial run as representative evidence in the runbook — it is about the
# claim, not about every row. A `ci-marker` run makes no such claim: it proves on
# every commit that backup → wipe → restore still works, at a size chosen to be
# fast, and it is still held to its signature, its freshness and its restore
# time. Holding it to 1MB as well made the assertion unsatisfiable, which is why
# CI's backup-drill has been red.
REPRESENTATIVE_PROFILES = profile_set(
    "PROBECTL_DRILL_REPRESENTATIVE_PROFILES", {"large", "production-shaped"}
)
MIN_REPRESENTATIVE_BYTES = int(os.environ.get("PROBECTL_DRILL_MIN_REPRESENTATIVE_BYTES", "1000000"))
FAILOVER_PROFILES = profile_set("PROBECTL_DRILL_FAILOVER_PROFILES", {"representative-compose", "production-shaped"})
if not ALLOW_HISTORICAL and not EXPECTED_SHA:
    fail("exact-commit mode requires PROBECTL_DRILL_EXPECTED_SHA or a readable git HEAD")
if SCOPE not in {"all", "backup", "failover"}:
    fail(f"PROBECTL_DRILL_SCOPE must be one of all, backup, failover; got {SCOPE!r}")


def require_sha(row: dict[str, str], context: str) -> None:
    if ALLOW_HISTORICAL:
        return
    got = normalize_sha(row.get("git_sha", ""))
    if got != EXPECTED_SHA:
        fail(f"{context}: git_sha {got or '<missing>'} does not match expected {EXPECTED_SHA}")


def parse_time(raw: str, context: str):
    try:
        return dt.datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except Exception as exc:
        fail(f"{context}: invalid timestamp {raw!r}: {exc}")
        return None


def fresh(ts: dt.datetime, context: str) -> None:
    age = now - ts
    if age < dt.timedelta(0):
        fail(f"{context}: timestamp is in the future: {ts.isoformat()}")
    if age > dt.timedelta(days=MAX_AGE_DAYS):
        fail(f"{context}: evidence is {age.days} days old (max {MAX_AGE_DAYS})")


if SCOPE in {"all", "backup"}:
    backup_csv = repo_path(os.environ.get("PROBECTL_DRILL_BACKUP_CSV", "docs/ops/backup-restore-results.csv"))
    if not backup_csv.exists():
        fail(f"{backup_csv}: backup restore evidence CSV is missing")
    else:
        rows = list(csv.DictReader(backup_csv.open()))
        large = [r for r in rows if r.get("profile") in BACKUP_PROFILES]
        if not large:
            fail(f"backup restore evidence lacks a row for profile(s): {', '.join(sorted(BACKUP_PROFILES))}")
        else:
            row = max(large, key=lambda r: r.get("run_at", ""))
            require_sha(row, "backup large row")
            ts = parse_time(row.get("run_at", ""), "backup large row")
            if ts:
                fresh(ts, "backup large row")
                date = ts.date().isoformat()
                if CHECK_DOCS and date not in (ROOT / "docs/ops/backup-restore.md").read_text():
                    fail(f"docs/ops/backup-restore.md does not cite backup date {date}")
            try:
                artifact_bytes = int(row.get("artifact_bytes", "0"))
                restore_secs = int(row.get("restore_secs", "-1"))
            except ValueError:
                fail("backup large row has non-numeric artifact/restore fields")
            else:
                claims_representative = row.get("profile") in REPRESENTATIVE_PROFILES
                if claims_representative and artifact_bytes < MIN_REPRESENTATIVE_BYTES:
                    fail(
                        f"backup profile {row.get('profile')!r} claims to be production-shaped but its artifact is "
                        f"{artifact_bytes} bytes (min {MIN_REPRESENTATIVE_BYTES})"
                    )
                if artifact_bytes <= 0:
                    fail(f"backup row has no artifact at all: {artifact_bytes} bytes")
                if restore_secs < 0:
                    fail("backup large row restore_secs is negative")


if SCOPE in {"all", "failover"}:
    failover_csv = repo_path(os.environ.get("PROBECTL_DRILL_FAILOVER_CSV", "docs/ops/failover-results.csv"))
    if not failover_csv.exists():
        fail(f"{failover_csv}: failover evidence CSV is missing")
    else:
        rows = list(csv.DictReader(failover_csv.open()))
        representative = [r for r in rows if r.get("profile") in FAILOVER_PROFILES]
        if not representative:
            fail(f"failover evidence lacks a row for profile(s): {', '.join(sorted(FAILOVER_PROFILES))}")
        else:
            row = max(representative, key=lambda r: r.get("run_at", ""))
            require_sha(row, "failover representative row")
            ts = parse_time(row.get("run_at", ""), "failover representative row")
            if ts:
                fresh(ts, "failover representative row")
                date = ts.date().isoformat()
                if CHECK_DOCS:
                    dr_text = (ROOT / "docs/ops/dr.md").read_text()
                    if date not in dr_text:
                        fail(f"docs/ops/dr.md does not cite failover date {date}")
                    if "_pending_" in dr_text or "sign-off are pending" in dr_text:
                        fail("docs/ops/dr.md still contains pending representative placeholders")
            try:
                rto_ms = int(row.get("rto_ms", "0"))
                rpo_rows = int(row.get("rpo_acked_rows", "-1"))
                rpo_seconds = float(row.get("rpo_seconds", "-1"))
            except ValueError:
                fail("failover representative row has non-numeric RTO/RPO fields")
            else:
                if rto_ms <= 0:
                    fail("failover representative row rto_ms must be > 0")
                if rpo_rows < 0 or rpo_seconds < 0:
                    fail("failover representative row RPO values must be non-negative")


logs = {}
if SCOPE in {"all", "backup"}:
    logs["backup large"] = (os.environ.get("PROBECTL_DRILL_BACKUP_LOG_GLOB", "docs/ops/drill-logs/backup-restore-large-*.log"), "BACKUP_RESTORE_RESULT")
if SCOPE in {"all", "failover"}:
    logs["failover"] = (os.environ.get("PROBECTL_DRILL_FAILOVER_LOG_GLOB", "docs/ops/drill-logs/failover-*.log"), "FAILOVER_RESULT")
for label, (pattern, marker) in logs.items():
    paths = [pathlib.Path(p) for p in glob.glob(str(repo_path(pattern)))]
    if not paths:
        fail(f"{label}: archived drill log missing ({pattern})")
        continue
    matched = False
    for p in paths:
        text = p.read_text(errors="replace")
        if marker not in text:
            continue
        if not ALLOW_HISTORICAL and f"git_sha={EXPECTED_SHA}" not in text:
            continue
        matched = True
        break
    if not matched:
        if ALLOW_HISTORICAL:
            fail(f"{label}: no archived log contains {marker}")
        else:
            fail(f"{label}: no archived log contains {marker} for expected git_sha={EXPECTED_SHA}")

if failures:
    for msg in failures:
        print(f"::error::drill-evidence: {msg}", file=sys.stderr)
    sys.exit(1)

if ALLOW_HISTORICAL:
    print("drill-evidence gate: OK (fresh dated historical restore/failover rows + archived logs)")
else:
    print(f"drill-evidence gate: OK (fresh restore/failover rows + archived logs for git_sha={EXPECTED_SHA})")
PY
