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

Select **Include original configured-test outcomes**, or add `"include_tests":
true` to the same JSON selection, to include the explicitly anchored tests on
the affected entities. This additionally requires current `test.read` for the
owning contexts and each exact test. Both windows retain every original
observation's evidence UUID and digest. A test definition without observations
does not establish an outcome. Complete ICMP batches report exact transmitted,
received and lost packet counts; incomplete local IO and canceled executions
remain unknown. Non-ICMP failures describe the application test's outcome and
do not establish packet loss or an upstream cause. An empty weekly baseline
stays unavailable. Observation pages preserve the complete returned population,
which is also present in the complete source citations and signed attachment.
When SLO definitions are available, the same selection cites the original failed
test inputs matching their current executable selectors. HTTP userinfo masking,
socket ports, DNS names and browser script start URLs follow the producing
canary's result identity. OpenSLO names stay names, including non-UUID names.
Objective ratios and definition digests are preserved in native and signed
outputs. These selected-window failures do not establish a rolling error-budget
violation. Missing SLO engines or definitions are explicit. With a customer-tag
selection, original test failures and complete measured echo loss also join
their current effective test tags, including the existing manual/inherited
precedence. Matching failed SLO inputs name the same tagged customers. Test,
tag-definition and original evidence IDs accompany these entries; the tag
revision and current disclosure are rechecked before publication. A test-only
customer retains unavailable traffic counters. Flow/test overlap contributes
one customer entry per routing context and value without changing flow totals.

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
Operator-owned annotation and incident text also masks literal tenant identifiers,
including when optional IP or PII masking is disabled. Canonical citation IDs and
exact decimal counters retain their types and values.
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

### Fault-domain verdict preview

`POST /v1/incidents/{id}/verdict` evaluates an explicit half-open `from`/`to`
window. The same read is available as `getIncidentVerdict` in the generated
clients, `probectl incident verdict <id> --body-file <file|->`, the native
`incident_verdict` tool, and **Fault domain** in the incident room. It requires
current `incident.read`, `entities.read`, `metrics.read`, `events.read` and
`test.read`; the native tool also uses the existing tenant egress consent and
redaction controls. It does not require an AI query or remote model.

This preview reads original interface-state and primary HTTPS observations.
A directly implicated, currently owned backbone interface must have original
administrative-up and operational-down evidence. A role label alone supplies
no failure measurement. Remote-service corroboration requires overlapping
executions by different authorized agents against the same HTTPS origin, with
verified TLS and original server-error responses. A timeout, missing response,
posture-only TLS handshake or cross-origin redirect supplies no such proof.

Every response retains all four hypotheses, their supporting and contradicting
original citations, missing coverage and the selected window. Carrier and
wider-internet source evidence are not connected in this preview. Thin,
contradictory or unresolved incident coverage returns `unknown`. The label
`remote_service` describes observed service failure; it does not identify a
SaaS provider or attribute its internal root cause. Confidence is an evidence
category (`insufficient`, `corroborated`, `direct`), not a probability.

The response's `valid_until`, when present, bounds its current source authority.
Re-evaluate after that deadline or after changing tenant/access context. Queries
use the deployment's finite query memory/deadline and tenant fairness policy;
an incomplete admitted population is never rendered as a plausible prefix.

When an explicitly bound test has retained path rounds, the verdict reads the
complete admitted window and keeps the original round IDs in
`control_plane_path` citations. These traces ran on the control-plane host;
they do not describe an agent's route. A measured destination reply supplies
limited contrary evidence, while unanswered intermediate hops cannot establish
a carrier or wider-internet failure. Legacy rounds without the trusted discovery
clock, completion clock and measurement-fidelity receipt remain unavailable for
this inference. Both ends of the original execution must fall inside the selected
window; a later reply cannot acquire an earlier incident timestamp.
The final publication check reads the same selected rounds and current test/path
bindings, without replacing them with a newer discovery.

To include this result in the signed incident package, send the selection
`{"verdict":{"from":"2026-11-01T00:00:00Z","to":"2026-11-01T01:00:00Z"}}`
to `POST /v1/incidents/{id}/exports`, or pass it to
`probectl incident export <id> --body-file <file|->`. The incident room's
**Export signed fault evidence** action uses the evaluated window. Exports
require `ai.query` in addition to the verdict's source permissions because
the package also gathers cited RCA. An optional `impact` selection can share
the same package. The server recomputes both selections and rechecks current
access and original documents immediately before publication; callers cannot
supply a verdict as evidence.

The `incident.fault_domain` attachment retains every hypothesis, supporting
and contradicting citation, missing coverage and original authority deadline.
It is labelled an inference, or unknown, rather than an independent measurement.
Use the generated Go `ExportIncidentEvidenceBytes` or TypeScript
`exportIncidentEvidenceBytes` method for offline verification. The original
parsed method remains available for inspection; decoding and re-encoding a
package does not preserve its signed bytes. Pin the expected signer as described
above. The four-domain lab qualification remains pending.
