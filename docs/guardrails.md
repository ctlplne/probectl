# Guardrails

These twelve invariants are non-negotiable properties of probectl. They are not
style preferences and not aspirations: each one is enforced somewhere you can
check — a CI gate, a test, or a build constraint — and a change that requires
violating one is refused rather than accommodated.

Source files cite them directly. When you read `docs/guardrails.md G7-1` in a
comment, that is the code telling you which invariant the surrounding lines
exist to hold, so a later reader can tell a deliberate constraint from an
accident of implementation.

They are published deliberately. probectl is source-available, and the security
properties an operator is trusting are more useful stated plainly here than
inferred from the code.

## G7-1 — Tenant isolation is the outermost boundary

Catastrophic if broken. Every tenant-scoped query is enforced at the storage
layer — row-level security, partitioning, or a per-tenant silo — never in handler
code alone, and always above RBAC. Every data-path change ships with an isolation test, and CI
runs a standing cross-tenant isolation suite. AI and MCP paths resolve tenant
first, then RBAC. Provider operators get no implicit telemetry read: access is
explicit, time-bounded, consented, and separately audited break-glass. In doubt,
fail closed.

## G7-2 — No phone-home, ever

No default outbound telemetry, beacons, or update checks. License verification is
offline math against baked-in public keys. Adoption metrics are opt-in or
download-proxy only. Consumption reporting for resellers is export-based — the
deployment never calls home to report usage.

## G7-3 — Crypto only through `internal/crypto`

One door for every cryptographic primitive, so the implementation is
FIPS 140-3 swappable. Per-tenant keys and BYOK build on it rather than beside it.
A CI import gate keeps other packages from reaching for primitives directly.

## G7-4 — mTLS between agents and the control plane

SPIFFE-style, tenant-bound identity established at enrollment; the tenant comes
from the certificate, never from the payload. There is no plaintext agent
transport.

## G7-5 — Tenant boundary plus RBAC/ABAC on every path

Including AI answers and MCP tools. A path that cannot express its tenant scope
does not get built.

## G7-6 — Secrets

Never hardcoded, never logged, never in URLs, never in git. Envelope encryption
at rest. No plaintext private keys server-side.

## G7-7 — Audit everything

Immutable, tamper-evident per-tenant audit streams, with a separate stream for
provider and break-glass activity so cross-tenant action cannot hide inside
tenant history.

## G7-8 — Remediation is observe-only or human-gated

Explicit approval, dry-run, blast-radius limits, tenant and RBAC scoping, fully
audited. Never un-gated autonomous action.

## G7-9 — Detection is a signal, never an IPS

Confidence-scored, tunable, suppressible, SIEM-exportable. probectl never blocks
traffic inline.

## G7-10 — Open data and threat intelligence

Read-only, ingested once then scoped per tenant, cached, and degrading
gracefully when a source is unavailable. TLS is validated and never disabled.
Fetched content is untrusted input. Per-source acceptable-use terms and
provenance are tracked.

## G7-11 — No browser storage beyond the design

The UI stores only what the design calls for, and stays usable without
third-party calls. No third-party or phoning-home assets.

## G7-12 — TLS everywhere, fail closed

TLS on every listener (1.2 minimum, 1.3 preferred). Deployments are HTTPS by
default with HSTS, CSP, and secure cookies. Every ingest surface is
authenticated, tenant-scoped, and signature-verified where senders sign, and
treats its input as untrusted. Datastore and bus traffic is encrypted in
transit; outbound connections validate certificates. A missing channel,
credential, or signature fails closed.
