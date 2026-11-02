# Incumbent NMS import

The LibreNMS importer reads one tenant's configured HTTPS source into a
redacted, inert plan. The source record belongs to an operator-selected
routing context. The control plane obtains the tenant from authentication and
checks the context in FORCE-RLS storage before resolving a credential or
contacting the source. The deployment must explicitly configure approved
egress CIDRs, CA trust, a tenant-scoped secret-reference prefix and a timeout;
with no approved policy, live fetching is disabled. See
[`configuration.md`](configuration.md) for the `PROBECTL_NMS_IMPORT_*` keys.

1. Configure a source with `POST /v1/nms-imports/sources` using `context_id`,
   `instance_ref`, `https_origin` and `credential_ref`. The CLI operation is
   `probectl nms-import configure-source --body-file <owner-only-file>`.
   Credentials remain in the configured secret store; the API returns an
   opaque source ID and never echoes the origin or reference.
2. Start an inert plan with `POST /v1/nms-imports/live-plans`. Call
   `POST /v1/nms-imports/{id}/advance` with its context ID until the final
   response reports a `snapshot_hash`. Each call reads at most one
   server-selected endpoint. A second pass compares normalized page hashes
   because LibreNMS does not provide one atomic generation token across the
   inventory endpoints. A failed or changed response leaves the plan inert.
3. Page the redacted source rows with `GET /v1/nms-imports/{id}/rows`, passing
   `context_id`, `limit` at most 100, and the returned cursor. Every row lists
   the fields and fixed unmapped reason codes that survived normalization.
   Raw rule expressions, notification destinations, communities, tokens and
   macro values have no plan column.
4. Submit explicit choices in batches of at most 100 to
   `POST /v1/nms-imports/{id}/review-choices`, with `context_id`, the exact
   `snapshot_hash`, and `{row_number,action,target_entity_id?}` entries.
   A device or site create requires an unambiguous candidate; update requires
   an exact entity ID in the same tenant and routing context. A static group
   and a captured group/device membership may also be selected for create.
   The group's dynamic predicate stays listed as unmapped and is never run.
   Group/member create remains source-keyed; a member can bind only an
   explicitly imported device from that same source and routing context.
   A later reviewed plan may repeat an identical source-keyed group and member
   without duplicating them. For a changed group label or dynamic-predicate
   marker, choose `update` on that exact source-keyed group with no target ID;
   the existing group's content and revision are frozen in the review hash.
   A changed target conflicts before the write. Missing members are never
   silently removed; member removal needs a separate reviewed choice.
   The selected entity target's identity fields and revision are fingerprinted
   in the reviewed row, so a later destination write can refuse a target
   changed after selection. A source address or label never selects an update
   target.
   Choose `unmapped` for a row carrying unsupported fields, or `skip` after
   reviewing it. Retrying identical choices is inert.
5. `POST /v1/nms-imports/{id}/finalize-review` freezes a `review_hash` only
   after every row has a choice. The plan enters `preview`. Page its destination
   comparison with `GET /v1/nms-imports/{id}/dry-run`, passing `context_id`,
   the exact `review_hash`, a limit of at most 100 and the returned cursor.
   Each entity create/update shows the proposed device or site label, and an
   update shows its current exact target label. A group create or update shows
   its current and proposed label, changed fields, and retained predicate
   warning; a membership create shows its source
   group/device pair. Unsupported rows keep their unmapped codes. A deleted
   or changed exact target returns a conflict instead of a
   stale comparison. This dry run writes no entities, groups, polling settings,
   alerts or agent evidence. After a partial apply, the same URL lists only
   pending choices, so an interrupted import can be resumed with its exact
   plan ID and review hash.
6. After final review, call
   `POST /v1/nms-imports/{id}/verify-before-apply` with `context_id`, the
   exact `snapshot_hash` and `review_hash` until `ready` is true. The CLI
   operation is `probectl nms-import verify-before-apply`. Each request
   re-reads only the server-selected next source endpoint and compares its
   normalized page receipts. A changed response marks the plan stale. A
   complete pass yields a 60-second proof for one future destination chunk;
   that chunk consumes it, so another chunk needs a new complete pass.
   LibreNMS does not provide a source-wide generation token, so a source
   change between the final re-read and a destination transaction remains
   possible. The verification route never writes a destination.
7. Call `POST /v1/nms-imports/{id}/apply` with the same `context_id`,
   `snapshot_hash` and `review_hash`. The CLI operation is
   `probectl nms-import apply`. Each call commits at most 100 reviewed rows in
   one tenant transaction with its audit event and returns `remaining`. For a
   configured live source, one complete verification pass is required before
   each chunk and is consumed by it. Repeat until `state` is `applied`;
   repeating an already completed plan is inert. Source rows cannot enable
   alerts, write agent evidence or install credentials. An unsupported row
   remains explicitly skipped with its unmapped reason.

MCP tools `nms_import_rows` and `nms_import_dry_run` page the same redacted
source rows and frozen destination comparison. Both require `nms.import.read`
and an explicit routing context and plan ID; the principal supplies the tenant.
The dry-run tool also requires the exact review hash. These tools are read-only
and cannot finalize, verify or apply an import.

The destination schema reserves a tenant/context/source-keyed group set and
membership table. A membership can reference only a device with an exact
applied import provenance in that same scope. A group name or member address
cannot select a routing context or canonical device.

The bounded one-endpoint route has a ten-second source-fetch budget inside
the listener deadline. LibreNMS v0 device lists have no documented page token;
a source that cannot finish one list in that budget cannot complete a live
plan by repeated requests. The importer must prove a larger real inventory
before it can claim bulk readiness. Orion and PRTG parsing remains preview
until live Windows trials; Zabbix export ingestion is not yet wired to a live
source. Zabbix poll items and triggers retain their documented host key as a
bounded parent reference for a later same-source provenance mapping; a host
key, address or label never selects a destination device by itself. Imported
alert expressions and delivery targets remain unmapped and
no imported alert can be enabled by this review path.
