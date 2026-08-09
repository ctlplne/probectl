# ADR: retain derived eBPF history, not raw application-call history

- **Status:** accepted
- **Decision date:** 2026-08-09
- **Approver:** founder/product owner (explicitly approved in the backlog completion session)
- **Revisit trigger:** an MSP design partner produces a concrete investigation that
  cannot be answered from derived edges, aggregates, detections, incident evidence,
  or latest TLS posture.

## Decision, ELI5

Keep the useful summary, not a recording of every conversation. probectl retains
tenant-scoped eBPF flow/service-edge aggregates and derived security evidence.
For TLS it retains certificate and handshake **metadata** plus honest visibility
state. It does **not** retain the raw stream of eBPF L7 calls or decrypted request
content.

This is the product contract, not a temporary implementation accident. UI/API
surfaces must say raw history is absent. A future reversal requires its own
tenant-isolated schema, migration, store/query API, retention/erase policy,
capacity measurement, threat model, and explicit approval.

## Evidence and assumptions

The current founder evidence is directional: the next customer-learning step is
an MSP design partner, and no observed design-partner workflow currently requires
raw replay. That makes a privacy-expanding feature unjustified today.

The reproducible fixed fixture in
`internal/ebpf/history_cost_test.go` measured on 2026-08-09:

| Encoding | Fixed-fixture bytes | Meaning |
| --- | ---: | --- |
| one raw L7 protobuf call | 197 | repeated for every captured call before storage/compression overhead |
| one derived latest-posture JSON record | 276 | one latest record per target, not per call |

Run `go test ./internal/ebpf -run TestRawHistoryCostFixture -v -count=1` to
reproduce the byte counts. These are serialization measurements, **not** a
production storage forecast. Calls/target/day, compression, index amplification,
replication, and operator query load have not been measured at representative
scale and therefore remain **unknown**, not zero. Frequency dominates: even a
smaller raw record repeated for every call can cost far more than one latest
record per target.

## Alternatives considered

1. **Retain all raw L7 calls.** Rejected now: no validated user need, largest
   cardinality/cost surface, and the highest privacy/subject-erasure burden.
2. **Sample raw calls.** Rejected now: sampled history looks complete when it is
   not unless every query carries complex missingness semantics; it still retains
   sensitive application metadata.
3. **Opt-in raw capture.** Deferred, not silently enabled. Opt-in does not remove
   tenancy, retention, privacy, and storage obligations.
4. **Derived-only (chosen).** Existing tenant-partitioned flow/L7 edge history,
   incident evidence, detections, and latest TLS posture answer current workflows
   with a materially smaller privacy blast radius.

## Privacy, tenancy, and security consequences

- No method, URL/resource, body, header value, or decrypted payload is copied into
  TLS posture. The projection test fails if method/resource data appears.
- Derived storage remains tenant-first; wrong-tenant or mixed-tenant batches fail
  closed before any posture mutation.
- `observed`, `unknown`, and `unsupported` remain distinct. Encrypted or sidecar
  visibility without a trustworthy handshake is recorded as unknown.
- Existing retention, tenant erasure, export, and storage-layer isolation apply
  to the derived eBPF stores. There is no hidden raw-history retention clock.

## Reversal work (separately estimated)

If validated customer evidence changes the decision, create separate backlog
items for: (1) tenant-isolated migration/schema; (2) bounded ingest and durable
store; (3) tenant-first query/API/UI with explicit sampling gaps; (4) retention,
subject/tenant erase, export, and backup/restore; (5) representative capacity and
cost tests; and (6) privacy/security/counsel review. Do not fold those into an
unreviewed extension of the current aggregate store.
