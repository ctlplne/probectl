# Incident evidence package

`probectl-evidence/v1` is the immutable carrier handoff contract. ELI5: a live
share is a library card that can expire; an evidence package is a sealed copy of
the book. Expiring or revoking the card does not rewrite a copy that was already
exported.

## Observed impact comparison (preview)

The incident room's **Traffic and customer impact** card, `POST
/v1/incidents/{id}/impact`, `probectl incident impact <id> --body '<JSON>'`,
and native MCP `incident_impact` compare an explicit half-open window with
the same-duration window seven days earlier. Request example:

```json
{"from":"2026-11-12T10:00:00Z","to":"2026-11-12T10:15:00Z","customer_tag_key":"customer"}
```

The service reads every persisted canonical incident member and signal citation.
Current exporter ownership and attested interface bindings select measurement
points; original capture receipts and continuous current ownership authorize
their observations. Shared router/interface selections count an observation
once. Separate exporters remain separate measurement points. Counters use exact
decimal strings, including sampling-adjusted values larger than 64 bits.

Selecting a customer-tag key adds cited closest-prefix membership. Source and
destination matches for the same customer count the observation once. Empty or
ambiguous closer prefixes block broader annotations. Customer pages retain the
complete returned population. Missing original coverage and an empty baseline
stay explicitly unavailable. A weekly change describes observed traffic rather
than causally assigning every missing byte to an incident.

Requires a current tenant user and `incident.read`, `flow.read`, `entities.read`,
`metrics.read`, `events.read`, plus `tags.read` for customer classification,
including current context and credential restrictions. It requires no AI query
grant. The existing flow cost policy and tenant fairness admit the complete
operation; a refused operation returns no truncated prefix.

The card can download a signed package with the selected impact comparison.
The existing export endpoint accepts an optional `impact` selection object:

```json
{"impact":{"from":"2026-11-12T10:00:00.123456789Z","to":"2026-11-12T10:15:00.123456789Z","customer_tag_key":"customer"}}
```

```sh
probectl incident export <incident-id> --body-file selections.json --out incident-evidence.json
```

The server recomputes the comparison under current reader, source and original
capture authority. It includes one complete content-addressed impact attachment;
clients cannot supply counters or claim a reusable source grant. Timestamp text
retains nanoseconds. Export keeps its existing `ai.query` requirement because it
also gathers cited RCA; the deterministic comparison above needs no AI grant.
Current report memory/output configuration admits complete signed output, and
refuses the whole export if resources are insufficient. Increase the configured
allowance for the intended complete workload rather than truncating it.

This extension remains preview. Test/SLO customer membership, original
real-flow/week-baseline proof and complete served/native/accessibility
qualification remain pending. Signing preserves observations and their declared
coverage; it does not turn a weekly difference into a causal loss estimate.

## Signed package contents

`POST /v1/incidents/{id}/exports`, the incident-room download button, and
`probectl incident export <id>` all return the same bytes:

- one canonical JSON manifest;
- one content-addressed JSON attachment for every retained, redacted incident
  signal;
- an optional complete impact attachment when selections are supplied;
- a detached Ed25519 signature over the exact manifest bytes;
- the public key and its SHA-256 fingerprint.

Every factual statement names at least one `evidence:sha256:...` record. Every
record names a `sha256:...` attachment. Verification therefore follows a closed
chain: statement → record → attachment digest → signed manifest. A conclusion
is `inference` only when the RCA was grounded; otherwise it is literally
`unknown`. `unknown`, `stale`, `unsupported`, `inferred`, and `observed` are
separate states and must never be rendered as synonyms.

Every record also carries mandatory provenance:

| Field | Meaning |
|---|---|
| `source` | collector/feed that made the observation |
| `vantage_id`, `vantage_owner` | where it ran and who controls it |
| `trust_tier` | authentication/integrity posture |
| `independence` | whether it is an independent observation |
| `captured_at`, `freshness` | time and freshness label |
| `clock_quality` | declared clock quality; `unknown` stays explicit |
| `sample_cadence_seconds` | expected interval when known |
| `missing_intervals` | known gaps; an empty list does not overclaim source health |

The manifest contains a one-way tenant-scope digest, never the raw tenant ID.
The API still reads through the tenant-scoped transaction/RLS boundary before
packaging; a foreign incident ID and a missing ID have the same 404 response.

## Offline verification

```sh
probectl incident export <incident-id> --out incident-evidence.json
probectl incident verify incident-evidence.json
```

The first command proves only that the package is internally consistent with
the key embedded in it — it does **not** prove who signed it, because a package
re-signed with any other key is just as internally consistent. So that command
reports `INTEGRITY-ONLY` and exits non-zero (3): never treat its output as a
verified package. Authenticity requires one extra human step — compare the
reported signer fingerprint with a fingerprint published by the probectl
operator through a separate trusted channel, then pin it:

```sh
probectl incident verify incident-evidence.json \
  --trusted-key-fingerprint 'sha256:<operator-published-fingerprint>'
```

Only this pinned command prints `VERIFIED` and exits 0; a package whose signer
does not match the pin is rejected. This is the same distinction as checking
that an envelope seal is intact versus checking whose seal it is. Verification
is local cryptographic math; it makes no network request.

## Key operations

- Single-replica Compose uses
  `PROBECTL_EVIDENCE_SIGNING_KEY_FILE` on the persistent control volume and
  generates the key once at mode 0600.
- HA deployments inject one shared `PROBECTL_EVIDENCE_SIGNING_KEY` from an
  operator-owned Kubernetes Secret/KMS bridge. Never use pod-local key files in
  HA: two replicas would otherwise claim two signer identities.
- Back up the private key with the envelope/WORM keys. Publish only the public
  fingerprint. Rotation changes the fingerprint; retain old public keys or
  fingerprints for historical package verification.
- A missing or invalid configured key disables export with a loud 503/startup
  error. Existing packages remain offline-verifiable.

## Golden intermittent-ISP contract

The automated acceptance fixture uses three customer-owned independent
vantages, a five-second declared cadence, a 90-second before/during/after
window, and clock quality of at most two seconds of NTP skew. It asserts exactly
one incident, preserves one contrary/unknown intermediate-ICMP record, rejects
cross-tenant access, and verifies the exported package offline. Intermediate
router silence or response is not reported as terminal loss unless end-to-end
evidence supports that claim.
