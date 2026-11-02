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
   A changed target conflicts before the write. After a complete configured
   live source capture and replay, an imported member missing from a captured
   group appears as a `member_removal_candidate` row. Only an explicit
   `remove` choice on that exact source-keyed pair can delete it. File and
   partial captures cannot propose removals; absence alone never prunes a
   group. The old member fingerprint and group revision are frozen in the
   review hash, and a changed member or group refuses the write.
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
   warning; a membership create shows its source group/device pair. A reviewed
   removal shows `membership_removed` for that same exact pair. Unsupported
   rows keep their unmapped codes. A deleted
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

Admin shows the source ID and each row's apply state and source-keyed binding,
and refreshes that page after a chunk. Its review menu offers the exact
source-group update and candidate member removal without asking for an entity
ID; device and site updates still require an exact canonical target ID. The
destination comparison lists the changed fields before apply.

MCP tools `nms_import_rows` and `nms_import_dry_run` page the same redacted
source rows and frozen destination comparison. Both require `nms.import.read`
and an explicit routing context and plan ID; the principal supplies the tenant.
The dry-run tool also requires the exact review hash. These tools are read-only
and cannot finalize, verify or apply an import. The rows tool reports each
row's pending, applied or skipped state and applied timestamp. For imported
devices and sites, it reports the source-keyed bound entity and the plan that
established that binding; the page identifies the source. A binding from a
previous plan remains visible when a later reviewed update changes that
entity, so the binding plan and the row's applied timestamp have distinct
meanings.

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
source. A Zabbix host group and each exported host membership are separate
review choices keyed by the exact group UUID and host key. A missing or
ambiguous source group does not create a destination membership; host group
names and addresses never select an existing destination. Zabbix poll items
and triggers retain their documented host key as a
bounded parent reference for a later same-source provenance mapping; a host
key, address or label never selects a destination device by itself. Source
item transport and status are reduced to fixed unmapped reason codes; their
raw values are not returned. The documented missing status defaults to
enabled; an explicit unknown status remains unmapped. An enabled SNMP item's
delay is eligible for a
later reviewed host cadence only when it is a literal 15s–24h interval and
it has a stable item identity; this carries the fixed `poll_proposal` code.
Zabbix host exports may omit an item UUID. In that case a nonempty, bounded
item key yields an opaque 32-digit ID derived through the crypto door from
the host key and item key. The item key itself is never returned or logged;
an invalid explicit UUID fails closed instead of using the fallback.
Conflicting intervals or an unsupported delay among
one host's enabled SNMP items mark its otherwise eligible rows with
`poll_cadence_conflict` and leave them unmapped. Other transports and disabled items cannot nominate a
host cadence. A reviewed create/update may persist an eligible item as a
tenant/context/source-keyed polling proposal only after its host has an exact
same-source applied device binding. The dry run shows current and proposed
seconds; a changed interval needs an explicit update against the current
proposal fingerprint and revision. Reimporting an identical item leaves that
revision unchanged. A proposal is inert until an operator exports and applies
the device-agent configuration with a separate device credential reference;
the NMS API credential is never copied. Imported
alert expressions and delivery targets remain unmapped. A disabled LibreNMS
rule with one positive device selector and an exact supported port-status
condition retains that source device ID for a later reviewed mapping; it is
still an unmapped row and creates no alert. Global, inverted, custom-query
and changed expressions retain no candidate selector. No imported alert can
be enabled by this review path.

`POST /v1/nms-imports/alert-target-preview` accepts the routing-context UUID,
LibreNMS source UUID, reviewed rule ID, exact agent ID and exact configured
target address. It requires `nms.import.read` and `entities.read` and returns
only the finite `port_down` candidate when the disabled source rule was
reviewed as unmapped in an applied plan, its selected source device has
same-source applied canonical provenance, and the current tenant-bound agent
identity and operator-owned `device_target` assignment anchor that device.
The response contains only source/canonical IDs, plan hash, safe name and
severity, fixed rule kind, and `enabled:false`; it does not contain source
SQL, delivery operations or credentials. A source IP, display name or another
tenant's identical agent/target string never selects a destination. The CLI
`nms-import alert-target-preview` exposes this read. It creates no native
alert. To create one disabled native alert, the operator submits the exact
`context_id`, `source_id`, `rule_external_id`, `agent_id`, `target_address`,
`plan_id`, `snapshot_hash` and `entity_id` from that preview to
`POST /v1/nms-imports/alert-target-apply` (or
`probectl nms-import alert-target-apply --body-file ...`). The write requires
`nms.import.write`, `entities.read` and `alert.write`. A configured source is
re-read through its fixed rules endpoint and every normalized page is checked
against the sealed receipts before the tenant transaction. The transaction
locks and rechecks the source, applied provenance, current sender identity
and operator-owned target. It creates only a disabled, channel-free native
`probectl_device_if_oper_status == 0` rule with exact `agent_id` and `device`
labels; it never imports source SQL, source delivery operations or a
credential. Repeating an unchanged source rule returns the same native alert
ID without changing its enabled state. Enabling or adding a channel is a
separate human-authorized alert operation.
The native MCP tools `nms_import_alert_target` and `nms_import_alert_apply`
share the same context, permission, receipt and disabled-write checks; MCP
cannot activate or add a notification channel through this import.

To find applied Zabbix proposals, page
`GET /v1/nms-imports/poll-proposals?context_id=UUID&source_id=UUID&limit=50`.
The optional `cursor` is the last returned 32-digit item ID; at most 100
items are returned per page. The response shows each source host key, item ID,
cadence, reviewed plan, revision and apply time, without a device credential or
agent assignment. It is a live read, so a subsequent export still rechecks
the exact proposal revision. `probectl nms-import poll-proposals --query
context_id=UUID --query source_id=UUID` and the read-only MCP tool
`nms_import_poll_proposals` expose the same bounded list; Admin can select an
item from it before a separate target preview.

To prepare one Zabbix polling proposal, call
`POST /v1/nms-imports/poll-target-preview` with the routing-context UUID,
source UUID, reviewed item ID, exact agent ID and exact configured target
address. The read requires `nms.import.read` and `entities.read`, and returns
only an applied proposal whose source host maps to the same tenant's canonical
device, current operator-assigned `device_target` anchor and active agent
identity. It returns the current plan ID, revision and seconds without a
credential. A source IP cannot select the target. The read-only MCP tool
`nms_import_poll_target` and Admin preview use the same check.

With that current plan ID and revision, run
`probectl nms-import config-export --context-id UUID --source-id UUID
--item-id ITEM_UUID --agent-id AGENT --target-address ADDRESS
--expected-plan-id UUID --expected-revision N --transport snmpv3
--credential-name-file NAME_FILE --out NEW_CONFIG`. The name file must be a
real 0600 file containing only a device-agent credential name, such as
`edge-ro`; keep the community or SNMPv3 passphrases in the agent's separate
credential source. `snmpv2c` also needs an explicit choice. Use `--port N`
for an operator-confirmed nondefault SNMP UDP port (default 161). The command
refuses a changed proposal or binding, checks the generated complete
`probectl.io/device-agent/v1` YAML with the shipped parser, and creates a new
0600 file without overwriting an existing config. It does not install or
reload the agent config. The operator must review that file, supply the
agent's normal bus and evidence settings where needed, and install it on the
matching tenant-bound agent. Until the running agent emits a poll receipt at
the reviewed cadence, this is a configuration proposal, not an active poll.

## Orion and PRTG documented-export preview

Orion and PRTG can be captured from saved JSON pages without a server-side
vendor credential or outbound request. These paths are labelled **preview**
until a live Windows trial proves the source responses and inventory
completeness. Orion uses the SWIS [Query API](https://solarwinds.github.io/OrionSDK/swagger-ui/)
`results` envelope. PRTG uses the JSON arrays defined by its
[experimental device, group and probe lists](https://www.paessler.com/support/prtg/api/v2/oas/prtg.api.yaml);
the [PRTG overview](https://www.paessler.com/support/prtg/api/v2/overview/index.html)
describes Link-header pagination. Capture every page of a chosen resource in
source order; do not use a partial export to infer that a source object was
removed.

Start with `POST /v1/nms-imports/export-plans` and
`{context_id,source_kind:"orion"|"prtg",instance_ref}`. For each saved page,
send the raw JSON body to `POST /v1/nms-imports/{id}/export-pages` with query
parameters `context_id`, `resource`, `page_number` and `first_row`. Page
numbers start at zero, and `first_row` is the total normalized rows in all
earlier pages. Orion resources are `nodes`, `groups` and `rules`; PRTG
resources are `devices`, `groups` and `probes`. A PRTG page has at most 3,000
objects. The page receipt supports exact retries but refuses changed or
out-of-order content. Finish with `POST /v1/nms-imports/{id}/export-seal`
and `{context_id,expected_pages,expected_rows}`. The returned snapshot is
inert; inspect its redacted rows and unmapped reasons, then use the same
explicit review and dry-run flow as a live plan. A seal verifies only the
submitted pages and totals, not unseen vendor inventory.

The CLI exposes `nms-import export-start`, `export-page` and `export-seal`.
Use `--body-file` with a real owner-only 0600 JSON file or stdin for each
export page; the source body can contain fields that the importer discards,
so the CLI refuses it in command arguments. For example:

```text
probectl nms-import export-page PLAN_ID --query context_id=CONTEXT_ID --query resource=devices --query page_number=0 --query first_row=0 --body-file prtg-devices-0.json
```

The Admin import card provides the same start, saved-file page and seal
controls. MCP clients with `nms.import.write` may use
`nms_import_export_start`, `nms_import_export_page` and
`nms_import_export_seal`; the page tool accepts a JSON object or array and
returns only a normalized page hash. All four surfaces use the same stored
tenant/context plan and review path.

The preview retains source IDs, safe labels, addresses, PRTG parent IDs and
bounded Orion poll intervals for review. Source-only credentials, dynamic
predicates and alert delivery settings are discarded. Site/ancestry,
polling and alert translation stay explicitly unmapped until an operator can
bind exact destinations; the preview itself creates no agent, entity, poll
or alert rule.
