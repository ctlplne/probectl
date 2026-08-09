# Incident evidence package

`probectl-evidence/v1` is the immutable carrier handoff contract. ELI5: a live
share is a library card that can expire; an evidence package is a sealed copy of
the book. Expiring or revoking the card does not rewrite a copy that was already
exported.

## What is signed

`POST /v1/incidents/{id}/exports`, the incident-room download button, and
`probectl incident export <id>` all return the same bytes:

- one canonical JSON manifest;
- one content-addressed JSON attachment for every retained, redacted incident
  signal;
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

The first verification proves that the package has not changed. Authenticity
requires one extra human step: compare the reported signer fingerprint with a
fingerprint published by the probectl operator through a separate trusted
channel, then pin it:

```sh
probectl incident verify incident-evidence.json \
  --trusted-key-fingerprint 'sha256:<operator-published-fingerprint>'
```

This is the same distinction as checking that an envelope seal is intact versus
also checking whose seal it is. Verification is local cryptographic math; it
makes no network request.

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
