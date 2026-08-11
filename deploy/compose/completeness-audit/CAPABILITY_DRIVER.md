# Completeness delivery-audit driver contract

This directory is audit infrastructure, not a second product implementation. The
runner starts release binaries built from one clean Git SHA, records one bounded
human path, and signs the resulting evidence. A signature proves byte integrity;
promotion additionally requires a zero-diagnostic semantic lint and an auditor
key/fingerprint trusted out of band.

## Exact-tree authority

`docs/quality/delivery-audit-review-protocols.json` is the single authority for
both executable and governed-review receipts. The runner reads it from the
immutable `git archive` source tree. An environment variable or a driver cannot
relabel an observation as another backlog item, capability, human path, or
privilege plane.

The built-in executable path is currently the registry-authorized
`CL-002` / `F50` / `f50-tenant-oidc-isolation` / `tenant_plane` tuple. It uses:

- release control and CLI binaries built with empty Go tags from the exact SHA;
- tenant OIDC sessions in real Dex for WebKit;
- separate tenant-bound MCP bearer credentials for the release CLI;
- natural browser API traffic with request interception and TLS bypass disabled;
- bidirectional CLI/API foreign-object rejection and PostgreSQL `FORCE RLS`;
- an internal-only Compose network with no published ports.

## Source-bound capability driver

Only a tuple already present in the authority registry may use an extension
driver. Supply a tracked regular file during `prepare`:

```sh
PROBECTL_AUDIT_ITEM=CL-NNN \
PROBECTL_AUDIT_CAPABILITY_ID=FNN \
PROBECTL_AUDIT_CAPABILITY_DRIVER=scripts/audit-fnn.sh \
bash scripts/run_completeness_audit.sh prepare
```

Prepare freezes the driver from the exact source archive and binds its source
path, SHA-256, and Git blob SHA. Resumed phases reject live driver overrides.
The driver receives the state directory as argument 1 and these additional
environment variables:

- `AUDIT_TOKEN_A_FILE` and `AUDIT_TOKEN_B_FILE`: mode-0600 tenant bearer-token
  files; read them only for the bounded run and never copy their values into an
  artifact.
- all `AUDIT_*` values frozen in the mode-0600 state environment file.

It must produce `artifacts/capability-manifest.json`,
`artifacts/cli-transcript.json`, and `private/postgres-proof.json`. The
declarative manifest is checked against the frozen stack scope and exact-tree
authority tuple. Arbitrary browser code is rejected; all UI observations use
the fixed `scripts/completeness_audit_browser.mjs` driver.

Every CLI observation binds two separate attachments:

- `cli_output_artifact` (`cli_output`) is the bounded release-CLI stdout/stderr;
- `response_artifact` (`api_observation`) is strict, redacted JSON recording
  auth mode, subject, command, method, path, status, and response body.

A successful structured CLI response must canonically equal the API-observation
body. A foreign-object denial must pair a nonzero release-CLI exit with a direct
HTTPS request made using the same tenant credential, and both records must agree
on the structured error code and 401/403/404 result.

## Governed review profile

Static, methodology, legal, and release work must not invent API, CLI, browser,
TLS, or store observations. Use the disjoint governed-review phases:

```sh
PROBECTL_AUDIT_REVIEW_SPEC=docs/quality/my-review-spec.json \
PROBECTL_AUDIT_REVIEW_ATTESTATION=/secure/inbox/completed-attestation.json \
PROBECTL_AUDIT_AUDITOR=independent-auditor \
PROBECTL_AUDIT_IMPLEMENTATION_OWNER=implementation-owner \
bash scripts/run_completeness_audit.sh review-all
```

The tracked review spec has this strict shape:

```json
{
  "schema": "probectl.completeness-audit-review-spec/v1",
  "item": "CL-NNN",
  "capability_id": "CL-NNN",
  "review_id": "bounded-review-id",
  "kind": "methodology",
  "methodology_path": "docs/research/method.md",
  "subjects": ["docs/research/method.md"],
  "required_checks": ["scope", "reproducibility"],
  "summary": "One independently completed governed review."
}
```

The external attestation has this strict shape and must contain exactly the
required check IDs:

```json
{
  "schema": "probectl.completeness-audit-review-attestation/v1",
  "review_id": "bounded-review-id",
  "conclusion": "passed",
  "checks": [
    {"id": "scope", "outcome": "passed", "detail": "Bounded detail."},
    {"id": "reproducibility", "outcome": "passed", "detail": "Bounded detail."}
  ]
}
```

The authority registry controls the allowed kind, methodology roots, and subject
roots for each exact item/capability pair. The runner automatically includes the
registry itself as a reviewed, Git-blob-bound authority subject.

## Phases and retained state

Executable phases are `static`, `prepare`, `run`, `seal`, `verify`, `cleanup`,
and `all`. Governed equivalents are `review-prepare`, `review-seal`,
`review-verify`, `review-cleanup`, and `review-all`. Resume a phase by setting
the printed `PROBECTL_AUDIT_STATE_DIR` or `PROBECTL_AUDIT_REVIEW_STATE_DIR`.

Successful verification removes bearer tokens, passwords, leaf private keys,
runtime authentication config, and any state-local receipt signing key. Public
certificates, screenshots, bounded structured observations, signed receipts,
and lint reports remain. A failed executable run retains prepared service
credentials for diagnosis/retry but still removes bearer tokens; invoke
`cleanup` to remove the remaining transient secrets and Compose volumes.

## Current product-path boundary

The audit describes each real store only as strongly as the bytes prove:

- PostgreSQL is the actual release-control store and proves bidirectional RLS.
- Kafka must contain the exact tenant-keyed OTLP metrics and traces protobufs
  accepted by the release receiver. A separate authenticated `SASL_SSL`
  tenant-tag probe remains supplemental; reader isolation is not claimed.
- Release control uses real Prometheus through an origin-pinned Basic Auth file
  mounted at `/run/secrets/prom-basic-auth.json`. The proof follows an OTLP
  metric through Kafka and the release consumer, then reads the exact marker
  through the tenant-forcing `/v1/grafana/api/v1/query` path.
- Release control uses the real ClickHouse OTLP store through an origin-pinned
  Basic Auth file mounted at `/run/secrets/ch-basic-auth.json`. The proof follows
  an OTLP trace through Kafka and the release consumer, then reads the exact
  trace/service through tenant-authenticated release CLI/API. The same release
  reader must also run the canonical tenant-predicate-free two-trace query with
  `SQL_probectl_tenant` set to tenant A, tenant B, and its empty fail-closed
  default. The typed `clickhouse_isolation` artifact binds the three hashed
  `clickhouse_isolation_raw` responses: exactly A's row, exactly B's row, and
  zero bytes for the unset setting.
- The unfiltered Prometheus label-integrity probe remains a defense-in-depth
  observation. It cannot substitute for the product round trip, and Prometheus
  reader isolation is not claimed.

`product-pipeline.json` is the authoritative correlated store proof. It binds
the exact receipt ID, source Git/tree SHAs, control image ID, CLI SHA-256, and a
non-empty evidence window contained by the signed receipt. Every emitted event
and every ingest, release-query, direct-store, Kafka-group, and ClickHouse
isolation observation carries a timestamp inside that window. The receipt ID
and completion timestamp are frozen once and reused for both seal drafts, so a
second draft cannot silently relabel or extend the run.

For each of two distinct tenants the manifest requires:

- one uncompressed OTLP metrics protobuf with exactly the `tenant_id` and
  `service.name` resource attributes, one `marker` point attribute, and one
  `Gauge` `AsDouble` value; and one OTLP trace protobuf with those exact resource
  attributes and one canonical `SERVER` span;
- byte-identical, tenant-bucketed Kafka key/payload evidence for metrics and
  traces, plus typed `kafka_group_offset` observations (and hashed raw
  `kafka-consumer-groups` output) showing the release groups committed beyond
  all four exact records;
- an exact release Prometheus query using only the marker selector, an exact
  direct query using marker then tenant, and a one-series response containing
  only `__name__`, `tenant_id`, `marker`, and `service_name`;
- an exact release ClickHouse trace read and direct predicate-free read of
  `default.probectl_otel_spans`, with event nanoseconds cross-checked to the raw
  row. The audit pins ClickHouse's authenticated HTTP
  `output_format_json_quote_64bit_integers=0` setting so those Int64
  nanoseconds are deterministic JSON numbers rather than server-default quoted
  strings; and
- successful empty release queries for the other tenant's exact metric marker
  and trace ID.

Raw `/metrics` counter snapshots bracket the entire product window. Received
and stored counters must increase by at least two for both signals, while every
malformed, rejected, shed, truncated, unsupported, dead-lettered, and dropped
counter remains unchanged. Any missing reference, reused product artifact,
orphan product artifact, timestamp outside the window, or Kafka count other
than the exact four correlated records is non-promotable.

The OTLP/HTTP receiver is a distinct TLS listener even though it reuses the
control certificate. The runner performs separate CA- and hostname-verified
handshakes against `control:8443` and `control:4318`, plus Dex, PostgreSQL
STARTTLS, Kafka TLS, ClickHouse HTTPS, and Prometheus HTTPS. For each socket it
hashes the actual served leaf's DER bytes, compares that fingerprint to the
expected generated public leaf, and only then writes the listener evidence as
`peer_certificate_sha256`. This proves which leaf each runtime socket served;
merely hashing a file mounted somewhere in the stack is insufficient.

Evidence separately proves trusted TLS, plaintext rejection, missing/invalid
bearer rejection, and a valid database-backed tenant-token request. A missing
product-pipeline artifact, marker mismatch, or false product-path flag makes
`seal` save a signed candidate plus its lint report and exit nonzero.
Limitations text can never upgrade a manual probe into product-path evidence.

Every completed seal also plants one separate signed `FAILED` control receipt.
The positive candidate binds that receipt, the planted artifact, and the exact
two linter diagnostics. This checks that the same linter rejects known-bad
evidence; it is not a substitute for a real failed audit observation.
