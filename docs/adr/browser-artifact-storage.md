# ADR: durable browser artifacts use the tenant-bound S3/MinIO store

- **Status:** accepted and implemented
- **Decision date:** 2026-08-09
- **Approver:** founder/product owner

## Decision, ELI5

The filesystem backend remains the small/local-development option. Durable
deployments use probectl's native S3/MinIO-compatible backend. Both sit behind
the same `objectstore.Store` contract and both are wrapped by `ForTenant`, so a
browser worker can name only a relative artifact path while the storage layer
prepends the tenant namespace.

The backend is operator-configured and self-hosted. It never discovers a cloud,
fetches pricing, or phones home. Remote endpoints require verified HTTPS; static
credentials are SigV4-signed through `internal/crypto`, may be resolved from the
existing secret backends, and are never logged or placed in a ConfigMap.

## Why this choice

- S3 semantics cover AWS S3 and self-hosted MinIO without a new Go dependency.
- The already-shipped tenant wrapper, bounded reads/listing, lifecycle
  export/erase, and storage router remain the single isolation boundary.
- The control plane and browser agent use the same backend/prefix configuration,
  so tenant deletion can inventory and delete the artifacts the agent wrote.
- Filesystem remains useful for air-gapped single-node/dev installs, but it is
  no longer presented as the durable scale answer.

## Failure policy

Object storage is evidence storage, not test execution. If an upload fails, the
browser test still reports its success/failure and logs an artifact-storage
error, but publishes **no** screenshot reference. It never returns a key for an
object that was not stored, never falls back into another tenant's prefix, and
never includes a partial response body. Listing pagination that does not advance,
oversized objects/responses, invalid credentials, plaintext remote endpoints,
and non-2xx responses fail closed.

## Proof boundary

`internal/objectstore/s3_test.go` exercises tenant A/B put/list/read/delete,
bounded reads, SigV4 headers, configuration rejection, and upstream outage.
Existing object-store and browser-fleet tests cover traversal rejection,
tenant-prefix routing, silo-prefix routing, and the no-reference-on-upload-error
behavior. A real managed-bucket latency/availability receipt belongs to the
representative infrastructure wave; it is not invented by this ADR.
