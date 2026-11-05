# Tenant-defined tags (preview)

Use tags for tenant-owned customer, site, role, circuit and contract metadata.
The current extension is preview: its store, API, CLI, Admin and native MCP
paths are implemented, but complete integrated real-sender, source, consumer
and served-surface acceptance is still required. A registered test or a source
fixture is not evidence of a live external account or a hardware sender.

## Ownership and permissions

Tag definitions belong to the authenticated tenant. Rules and assignments also
belong to one routing context and an owned exporter, interface, prefix, device,
agent or test. An exporter uses its existing collector/exporter pair; the other
subjects use their current registered identity. An identifier supplied by the
caller does not establish ownership.

Every metadata query runs in the tenant-routed Postgres scope with storage-layer
isolation. Reads require `tags.read`, writes require `tags.write`, and resolving
subjects or importing metadata additionally requires their current source and
context permissions. Missing, foreign, revoked or unverifiable sources refuse
or remain undisclosed. Mutations and the tenant audit record commit together.

In **Admin**, use the tag definition, rule, assignment, resolution and NetBox
cards. Cards appear only with the corresponding grants. Tenant/context changes
clear scoped form state; a result from an older request cannot establish a new
context's authority. Deleting a tag is an explicit operator action.

## Rules, history and provenance

Rules match supported collected names, CIDRs and exact SNMP fields. A prefix's
explicit network and a sender-attested interface or agent address are distinct
facts; an arbitrary label is never an address or an identity alias. Unavailable
or ambiguous evidence does not produce a guessed association.

Manual and reviewed imported assignments retain their source. Effective
resolution returns the tag revision, evaluation time and winning source so the
operator can inspect the result. Metadata is joined at query time: changing a
rule changes a new query over retained history, without rewriting telemetry.
An already frozen result retains its recorded values, while every subsequent
read still checks current source/context/credential authority and retention.

Explorer exposes tags in its current tenant vocabulary as dimensions and
filters. Saved-source reports use that same current-authorized query path.
Test-backed alert metadata selection and cited-test RCA expose only currently
authorized owned metadata; tags are not instructions to remediate or to block
traffic. The original alert condition and human approval boundaries remain.

## Reviewed NetBox import

An operator first configures the existing provider-managed probectl-tenant to
NetBox-tenant mapping. A source name or private IP alone never proves tenancy.
Preview resolves the current owned destination before reading the configured
source, verifies the mapped NetBox tenant and shows the proposed role or site
value with source identity. Apply requires explicit confirmation of the
unchanged preview and repeats current destination/source checks. Changed,
missing, ambiguous or foreign source metadata refuses. Imported values retain
their provenance and cannot be silently overwritten as a manual assignment.

No automatic remote discovery, upstream reporting or new external account is
enabled by creating tags. See [canonical entity ownership](entity-registry.md)
and the existing CMDB configuration for source credentials and TLS.

## API, CLI and native MCP

`/v1/tags` manages definitions. Routing-context paths under
`/v1/entity-contexts/{context_id}/` provide `tag-rules`, `tag-assignments`,
`resolved-tags`, and the explicit NetBox preview/apply operations. Their full
request and response shapes are in the shipped OpenAPI specification.

The CLI uses the same authenticated operations:

```text
probectl tags list
probectl tags rules-list <context-id> --query limit=200
probectl tags assignments-list <context-id> --query limit=200
probectl tags netbox-preview <context-id> --body-file preview.json
probectl tags netbox-apply <context-id> --body-file confirmed-preview.json
```

Follow returned continuation cursors for complete rule and assignment listings.
Native MCP exposes the same typed operations and current tenant/source grants;
MCP transport consent and credential ceilings still apply. A cursor or imported
preview is not a reusable authorization grant.

## Complete results and finite resource admission

Vocabulary and rule/assignment populations are admitted by the existing finite
query memory, response and operation profiles. Physical page sizes do not cap
retained history. An operation that cannot complete within its configured
budget refuses rather than returning an apparently complete truncated result.
Tune the documented `PROBECTL_FLOW_QUERY_MAX_MEMORY_BYTES`,
`PROBECTL_FLOW_QUERY_MAX_RESPONSE_BYTES` and `PROBECTL_FLOW_QUERY_TIMEOUT` for
the intended complete workload, retaining tenant fairness.

Values support up to 24,000 Unicode code points and 96,000 UTF-8 bytes, with
the corresponding escaped-input envelope. This describes the current value
representation; it is not a reason to reduce a required workload. See
[configuration](configuration.md) for positive operator resource settings and
[dashboard reports](dashboard-reporting.md) for independent complete-output
admission and stored-body verification.
