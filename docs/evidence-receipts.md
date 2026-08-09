# Exact-source evidence receipts

`scripts/evidence_receipt.py` gives every release proof one portable JSON
envelope. The envelope binds a run to its Git commit, clean/dirty state,
profile, dependency versions, timestamps, thresholds, claims, and artifact
SHA-256 values. It refuses to overwrite an existing receipt.

This separates two ideas that are easy to confuse:

- a test can pass on some machine at some time;
- a buyer-facing claim is current only when the receipt passes integrity checks,
  records a clean checkout, and names the current Git commit.

A dirty run can be retained with `--record-dirty`, but it is always reported as
`NON_PROMOTABLE_DIRTY`. Moving HEAD or changing the checkout automatically
demotes an otherwise valid receipt to `STALE_SHA` or
`CURRENT_CHECKOUT_DIRTY`.

## Draft and seal

Place the draft and every evidence artifact in the same bundle directory:

```json
{
  "receipt_id": "e2e-20260809",
  "claims": ["BL-001", "F50"],
  "profile": "real-store-e2e",
  "started_at": "2026-08-09T12:00:00Z",
  "completed_at": "2026-08-09T12:08:00Z",
  "result": "pass",
  "dependencies": {
    "postgres": "16",
    "kafka": "3.9.0"
  },
  "thresholds": {
    "cross_tenant_records": 0,
    "correlated_incidents": 1
  }
}
```

```sh
python3 scripts/evidence_receipt.py seal \
  --draft receipts/e2e/draft.json \
  --artifact receipts/e2e/e2e.log \
  --artifact receipts/e2e/environment.json \
  --output receipts/e2e/receipt.json
```

The receipt is self-contained except for its named artifacts, which must sit
beside it. This keeps offline verification deterministic and prevents an
absolute developer path from masquerading as portable evidence.

## Verify and query

```sh
python3 scripts/evidence_receipt.py verify \
  --require-current receipts/e2e/receipt.json

python3 scripts/evidence_receipt.py query \
  --root receipts \
  --claim F50

python3 scripts/evidence_receipt.py index \
  --root receipts \
  --catalog docs/claims/release-catalog.json \
  --output receipts/claim-status-index.json
```

`verify --require-current` fails for altered artifacts, altered envelope data,
a dirty checkout, a dirty recorded run, a failed run, or a different HEAD.
`query` returns every valid envelope that names the requested backlog, feature,
need, or claim ID and computes its strict status against the current checkout.
`index` assigns exactly one strict aggregate status to every catalog claim,
including `UNVERIFIED` when no receipt exists, preserves its unique owner/kind,
and includes all evidence pointers. The release catalog covers F1–F57,
N1–N13, BL-001–BL-048, and every repository-governed claim. It fails if clean
receipts at the current SHA disagree about pass, fail, or error, so
contradictory release evidence cannot be silently ranked.

Run `make evidence-receipt-gate release-claim-gate` for the planted
positive/negative self-test and complete-catalog check.
