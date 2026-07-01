# Audit log — a tamper-evident record of who did what

## What it is

The audit log is probectl's permanent, ordered record of every action that changes
configuration or touches data: who did it, to what, from where, and when. Think of it
as the building's CCTV plus a signed visitor book — not to slow anyone down, but so
that afterwards you can prove exactly what happened and be confident no one quietly
edited the tape.

A term you'll see: **WORM** (write-once, read-many) — storage that accepts a record
once and then physically refuses to let anyone overwrite or delete it before its
retention period is up.

## Why it exists

When something goes wrong — a misconfiguration, a suspicious access, an auditor's
question a year later — "what actually changed, and who changed it?" must have a
trustworthy answer. A log you can edit answers nothing, because the first thing a
careless or malicious actor does is fix the log. Regulated teams also have to *prove*
to a third party that the record is complete and unaltered. The audit log exists to
make that proof cheap and routine.

## How it works

The model: every meaningful action writes one entry, entries are chained so any later
edit is detectable, and sensitive actions are kept in their own stream.

1. **Capture.** Each config change and data-access action emits a structured entry —
   actor, action, target, tenant, a free-form `data` map, a sequence number, and
   a hash chain (with a `created_at` timestamp) — there is no dedicated `result`
   field.
2. **Make it tamper-evident.** Entries are hash-chained: each record commits to the one
   before it, so removing or altering any entry breaks the chain and is detectable. On
   supported backends the chain is written to WORM storage so it physically cannot be
   rewritten.
3. **Separate the sensitive streams.** Operator/provider actions and any audited
   "break-glass" emergency access go to a **separate** audit stream from ordinary
   tenant activity, so privileged actions are reviewable on their own and never blend
   into the noise.
4. **Scope it to the tenant.** Like everything in probectl, an audit query returns only
   the calling tenant's entries — you can never read another tenant's history.

What probectl guarantees you:

- **The record is complete and ordered.** Actions are recorded as they happen; you
  review history, you don't reconstruct it.
- **Tampering is detectable (and, on WORM, prevented).** A changed or missing entry
  breaks the verifiable chain.
- **It's exportable, not a silo.** Entries stream to your SIEM for long-term search and
  correlation — probectl is the source of truth, not a replacement for your security
  tooling.

## Use it

Read the audit trail for a tenant (results are already tenant-scoped); page with a
sequence cursor:

```sh
curl --cacert ./ca.crt -H "Authorization: Bearer $TOKEN" \
  "https://probectl.example.com/v1/audit?limit=100"
```

The in-product route is `/audit`: it pages by sequence cursor, filters by actor,
action, and target, verifies the tenant hash chain, and downloads the filtered
JSON page. The CLI equivalents are `probectl audit list` (page through entries)
and `probectl audit verify` (check the hash chain).

Expected result — entries oldest-first (ascending by sequence), wrapped with a
`next` cursor:

```json
{"items":[{"created_at":"2026-06-22T14:03:11Z","actor":"alice@example.com","action":"config.update","target":"alert.rule/api-latency","data":{},"seq":42,"hash":"…"}],"next":43}
```

If the integrity check ever fails, the verifier reports the first broken link rather
than silently continuing — that's the signal to investigate.

## Pitfalls & limits

- **It records, it does not prevent.** The audit log proves what happened; stopping a
  bad action is the job of access control (see [scim-abac.md](scim-abac.md)), not the log.
- **Retention is a setting with consequences.** WORM retention can't be shortened after
  the fact — that's the point — so size it deliberately (see [data-retention.md](data-retention.md)).
- **It is not your SIEM.** For long-term search, alerting, and cross-system correlation,
  export to your SIEM ([siem.md](siem.md)); the in-product view is for recent,
  tenant-scoped review.

## Reference

- Entry categories: configuration changes, data-access actions, auth events; a separate
  stream for provider/operator and break-glass actions.
- Properties: append-only, hash-chained (tamper-evident), optional WORM backing,
  tenant-scoped reads.
- Export: streamed to your SIEM ([siem.md](siem.md)); retention configured per
  [data-retention.md](data-retention.md).

## See also

[SIEM integration](siem.md) · [SCIM / ABAC](scim-abac.md) ·
[Advanced governance](governance.md) · [glossary](glossary.md) (SIEM, tenant)

**Covers:** F23
