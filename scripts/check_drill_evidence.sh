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
import pathlib
import sys

ROOT = pathlib.Path(".")
MAX_AGE_DAYS = int(__import__("os").environ.get("PROBECTL_DRILL_MAX_AGE_DAYS", "180"))
now = dt.datetime.now(dt.timezone.utc)
failures = []


def fail(msg: str) -> None:
    failures.append(msg)


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


backup_csv = ROOT / "docs/ops/backup-restore-results.csv"
if not backup_csv.exists():
    fail("docs/ops/backup-restore-results.csv is missing")
else:
    rows = list(csv.DictReader(backup_csv.open()))
    large = [r for r in rows if r.get("profile") in {"large", "production-shaped"}]
    if not large:
        fail("backup restore evidence lacks a large/production-shaped row")
    else:
        row = max(large, key=lambda r: r.get("run_at", ""))
        ts = parse_time(row.get("run_at", ""), "backup large row")
        if ts:
            fresh(ts, "backup large row")
            date = ts.date().isoformat()
            if date not in (ROOT / "docs/ops/backup-restore.md").read_text():
                fail(f"docs/ops/backup-restore.md does not cite backup date {date}")
        try:
            artifact_bytes = int(row.get("artifact_bytes", "0"))
            restore_secs = int(row.get("restore_secs", "-1"))
        except ValueError:
            fail("backup large row has non-numeric artifact/restore fields")
        else:
            if artifact_bytes < 1_000_000:
                fail(f"backup large artifact too small for representative row: {artifact_bytes}")
            if restore_secs < 0:
                fail("backup large row restore_secs is negative")


failover_csv = ROOT / "docs/ops/failover-results.csv"
if not failover_csv.exists():
    fail("docs/ops/failover-results.csv is missing")
else:
    rows = list(csv.DictReader(failover_csv.open()))
    representative = [r for r in rows if r.get("profile") in {"representative-compose", "production-shaped"}]
    if not representative:
        fail("failover evidence lacks a representative-compose/production-shaped row")
    else:
        row = max(representative, key=lambda r: r.get("run_at", ""))
        ts = parse_time(row.get("run_at", ""), "failover representative row")
        if ts:
            fresh(ts, "failover representative row")
            date = ts.date().isoformat()
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


logs = {
    "backup large": ("docs/ops/drill-logs/backup-restore-large-*.log", "BACKUP_RESTORE_RESULT"),
    "failover": ("docs/ops/drill-logs/failover-*.log", "FAILOVER_RESULT"),
}
for label, (pattern, marker) in logs.items():
    paths = [pathlib.Path(p) for p in glob.glob(str(ROOT / pattern))]
    if not paths:
        fail(f"{label}: archived drill log missing ({pattern})")
        continue
    if not any(marker in p.read_text(errors="replace") for p in paths):
        fail(f"{label}: no archived log contains {marker}")

if failures:
    for msg in failures:
        print(f"::error::drill-evidence: {msg}", file=sys.stderr)
    sys.exit(1)

print("drill-evidence gate: OK (fresh dated restore/failover rows + archived logs)")
PY
