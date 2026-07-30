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

### Encrypted incident-response attribution

Provider break-glass evidence deliberately keeps the signed WORM copy
minimized: operator identity, tenant, grant, consent, outcome, and reason are
still stripped from that ordinary immutable projection. The real break-glass
transaction now also writes one append-only encrypted IR sidecar record. That
record is local-only, envelope-sealed under the operator's own per-tenant public
wrapping key, hash-chained, and signed. Seal or sidecar failure rolls the
break-glass mutation and provider audit event back together.

This is a deliberate accountability-versus-minimization choice inside the
sovereign boundary: privileged identity is private by encryption rather than
private by amnesia. The steady-state runtime has only a public wrapping key and
cannot unseal the record; ordinary audit reads cannot reveal it. No vendor,
third party, other tenant, network service, or phone-home path holds or resolves
the key. The keyring is operator-owned local storage, so sealing remains
deterministic in an air gap. When an investigation is authorized, the operator
mounts an owner-only directory containing envelope-encrypted private-key
artifacts and supplies its distinct local unlock KEK through the
`internal/crypto` key-provider seam. Plaintext private keys are never stored by
probectl. For each bounded open, the temporary PEM buffer is zeroized and the
parsed key capability is immediately discarded afterward; Go cannot guarantee
in-place erasure of every parsed big-integer heap copy.

Ordinary full-tenant and subject lifecycle exports cannot read, unseal, or
export this sidecar. They carry one fixed, non-disclosing policy note and omit
the sidecar table entirely; only the audited investigator path below can reveal
attribution.

Investigation-only separation of duty is enforced at
`POST /v1/audit/ir/{event_ref}/reveal`: authenticated tenant scope first,
mandatory MFA, the dedicated `ir.investigate` permission, and tenant ABAC.
Migration 0081 registers that permission but deliberately grants it to no
admin/editor/viewer role. It seeds the exact `ir-investigator` SCIM group for
existing tenants and auto-grants only `ir.investigate` when that exact group is
created for a later tenant. The tenant's IdP/SCIM administrator adds the
investigator members; no hand-written SQL is required.
Missing and other-tenant references have the same response. Every authorization
check runs before any unseal or permanent IR receipt. Admitted attempts are
rate-bounded; reveal intent, failed open, and successful open receipts commit to
the separate provider/break-glass stream. The successful receipt commits before
decrypted bytes are returned, and responses are marked `Cache-Control:
no-store`.

Migration 0079 is the append-time inner envelope; migration 0080 completes its
retention-surviving WORM binding. After each signed WORM segment is durably
read back and verified with the WORM key, probectl outer-seals each protected
stage with AAD containing the tenant, provider sequence, and hash of those exact
segment bytes. The global companion omits the tenant identifier; it carries
only the event sequence, randomized envelope material, and signed opaque
commitments, so it does not restore the tenant linkage stripped from WORM. A
separately signed companion manifest and continuous coverage head are then
verified before retention may use the lower of the WORM and IR watermarks.
Missing stages, companions, coverage rows, signatures, or chain links fail
closed; the runtime never fabricates historical proof. The encrypted stage and
companion are not pruned with the plaintext provider rows, so an authorized
investigation can still reconstruct attribution after a legitimate prune.

Migration 0082 adds the separate, signed IR key-destruction ledger used by
verifiable tenant deletion. Before deleting any tenant store, the lifecycle
engine verifies the complete sidecar chain and WORM coverage, inventories every
historical tenant IR key artifact, and atomically records a provider intent plus
signed plan. That plan immediately freezes new sidecar writes and reveals. Only
after every ordinary store succeeds does the explicitly mounted destruction
capability remove the exact tenant public key and encrypted private artifacts,
verify their absence, and atomically append the completion event and signed
tombstone. Failure is separately audited with a bounded class; another tenant's
key and ledger remain usable. The encrypted sidecar and WORM proof survive as
unreadable accountability evidence, and a restored key file is still rejected
by the tombstone.

Local overwrite and unlink are best-effort filesystem hygiene, not a claim that
flash media, snapshots, external escrow, or operator backups were physically
zeroized. The operator must destroy those copies or the corresponding external
KMS handle under its own policy. The product's signed tombstone prevents a
restored local artifact from reactivating attribution through probectl.

Rejected agent and collector enrollment attempts use the fixed
`security.enrollment_rejected` action. If a tenant was resolved from an
authenticated caller, consumed tenant-bound token, or deployment-verified
certificate, the event goes to that tenant's chain. Otherwise it goes to the
deployment/provider chain; probectl never guesses a tenant from an unverified
token, CSR, certificate, or proof. The event contains only the bounded
`failure_class`, `surface`, and `outcome: denied` fields. Aggregate, label-free
`probectl_enrollment_failures_<class>_total` counters expose the same fixed
classes at `/metrics`; neither surface records credential material or tenant
identifiers as metric labels.

## Use it

Read the audit trail for a tenant (results are already tenant-scoped); page with a
sequence cursor:

```sh
curl --cacert ./ca.crt -H "Authorization: Bearer $TOKEN" \
  "https://probectl.example.com/v1/audit?limit=100"
```

The in-product route is `/audit`: it pages by sequence cursor, filters by actor,
action, and target, verifies the tenant hash chain, and downloads the filtered
JSON page. For exact `test.create`, `test.update`, `test.delete`, and
`incident.resolve` actions, the Target cell also offers a same-app **Open**
pivot. The original immutable target stays visible. Tests open the exact
Targets inventory state; resolved incidents open the existing incident room.
The destination performs its ordinary tenant and RBAC checks, and a deleted
object produces that route's honest unavailable state.

The allowlist is deliberately exact. Unknown actions, lookalike names, erased
subjects, journal/share record IDs, authentication/security targets, and
provider-stream targets remain inert text. The audit page does not prefetch the
object, infer a route from arbitrary strings, or turn a link into authority to
read or change anything.

The CLI equivalents are `probectl audit list` (page through the same canonical
`action` and `target` evidence), `probectl audit verify` (check the hash chain),
and the separation-of-duty reveal path:

```sh
printf '%s\n' 'investigate privileged abuse case IR-42' |
  probectl --tenant "$TENANT_ID" audit reveal "$EVENT_REF" \
    --session-cookie-file /operator/private/probectl-session.cookie
```

Reveal requires an MFA-bearing OIDC session; ordinary bearer/API tokens cannot
claim MFA and are rejected. Store the `probectl_session` cookie value in the
mode-`0600` file (or set `PROBECTL_SESSION_COOKIE_FILE` to its path). The CLI
uses the cookie instead of any configured bearer token.

For a non-interactive investigation, pass
`--reason-file /operator/private/case-reason.txt`; the CLI accepts only a real,
mode-`0600` file. The reason is never accepted as a command-line
value, so it does not appear in process arguments. A terminal never needs
UI-specific links to preserve evidence parity.

Provision the encrypted investigation artifact locally, without calling the
control plane or any network service:

```sh
probectl audit seal-private-key "$TENANT_ID" \
  --private-key-file /operator/escrow/tenant-ir-private.pem \
  --unlock-key-file /operator/escrow/ir-artifact-kek.b64 \
  --unlock-key-id operator-ir-unlock-v1 \
  --output-dir /operator/ir/private
```

Both input files must be real mode-`0600` files and the output directory must
be absolute and owner-only. The command refuses to overwrite a version, writes
only the envelope-encrypted
`<tenant>.<sha256-of-key-id>.pem.enc` artifact, and prints its non-secret path
and key ID. Keep old versions after rotation.

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
- **Retention is a setting with consequences.** The `single` profile defaults
  to keep-forever; `multi-tenant` and `regulated` default to a finite `8760h`
  deployment maximum and fail closed without WORM/SIEM export-watermark
  configuration. A tenant's `audit_retention_days` may tighten that maximum;
  `NULL` inherits it, and a finite override still works when a single
  deployment keeps provider rows forever. The hourly pruner removes only old
  rows already covered by durable WORM/SIEM watermarks. Provider/break-glass
  rows always use the deployment window; tenant prune receipts record the
  tenant's actual effective window. A small, non-prunable
  per-stream metadata row preserves the highest-ever sequence/hash and the
  last-pruned sequence/hash, so even a full local prune cannot reset the chain
  behind an export cursor. Prefix deletion, prune-anchor advance, and the
  append-only prune receipt commit in one database transaction. The verifier
  starts at that declared retention anchor but still rejects gaps, altered
  hashes, or a missing retained tail; SIEM/WORM exporters likewise fail loudly
  if their cursor is behind the prune anchor or above the durable head.
  `/readyz.audit_retention` and the `probectl_audit_retention_*` metrics show
  whether raw in-DB rows are actually aging out. WORM retention can't be
  shortened after the fact, so size it deliberately (see
  [data-retention.md](data-retention.md)).
- **Upgrade recovery for a prefix pruned before migration 0075.** A retained
  suffix carries its predecessor hash, so 0075 reconstructs partial-prune
  anchors exactly. If an older binary already removed an entire tenant suffix,
  the surviving SIEM cursor makes the loss detectable and new appends fail
  closed until that anchor is restored. The provider stream has no local
  database cursor—the cursor and hash live in signed WORM objects—so a
  pre-0075 *full* provider prune cannot be reconstructed by SQL alone. When
  WORM is configured, startup verifies the complete signed WORM chain before
  admitting provider writes. If SQL is completely empty, it restores the
  terminal WORM sequence/hash as the prune anchor and atomically appends an
  `audit.retention_anchor_recovered` receipt; retained SQL disagreement,
  tampering, or a WORM rewind fails startup without changing SQL. Without the
  original configured WORM evidence, restore the audit tables from backup or
  restore `provider_audit_stream_head` under the audited maintenance procedure.
  The mutating `envelope-rewrap` command runs the same admission gate before it
  changes ciphertext, so a one-shot CLI cannot bypass recovery. Never fabricate
  genesis or rewind the WORM cursor.
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
- Local GA gate receipt: [`dataroom-receipts-20260715`](../dataroom-receipts-20260715/README.md)
  identifies its exact verified source commit and records
  machine-readable gate results, coverage, real-store isolation/integration,
  recovery transcripts, vulnerability reports, image identity, and SBOM. It
  deliberately excludes reference-hardware scale/overhead, representative
  multi-region DR, and counsel-owned commercial legal work.

## See also

[SIEM integration](siem.md) · [SCIM / ABAC](scim-abac.md) ·
[Advanced governance](governance.md) · [glossary](glossary.md) (SIEM, tenant)

**Covers:** F23
