# AS-path history for monitored prefixes

Open **Planes → BGP → Public prefix visibility**, select a prefix and open
**AS-path history**. The timeline lists observed paths from owned BMP routers
and the public collectors supplied to the local cache. Filter by source, time
range or vantage. Select an event to inspect the previous and current paths
and their original source evidence.

The default range is the previous 30 days. An explicit range can reach
earlier retained observations. A continuation carries the original time
range and vantage filter, and keeps separate source operations at the same
observation clock. Public events compare file clock and record position; the
evidence shows the original ordinal within its file. Removing the prefix
monitor deletes its history.

## Interpret a path

An ordered sequence shows each ASN, including repetitions caused by
prepending. A set shows possible ASNs as a group. Confederation segments
retain their original order or set membership. The BGP selection length
counts each sequence member and each AS set once, and excludes confederation
segments. The adjacent upstream appears when the origin and neighboring
external ASN are both supported by ordered evidence.

An admitted baseline starts a source epoch. A complete baseline can show
that an exact prefix had no announcement. A gap closes continuous history
until another complete source is available. Changes in possible origins are
marked separately from changes between two verified origin ASNs.

| Source | Evidence in a retained event |
| --- | --- |
| Owned BMP router | Current authorized routing view, generation, original message clock and operation order. A completed End-of-RIB can supply a baseline. The event can link to the exact routing change when the caller has current change access. |
| Public collector | Original baseline and update SHA-256 values, collector, peer, file record number and operation index. A retained RIB entry includes its peer index and original sequence. Whole-file validation and source continuity govern the path evidence. |
| Incident context | A visibility incident can share the exact public archive and monitor. A nearby owned-router incident shares the current routing identity, exact prefix and configured time window. |

The public path history consumes the same sealed, whole RouteViews archives
as prefix visibility. The fetch command uses the published collector and
archive clock, and the watch set stays local. The public source configuration
is shared with prefix visibility. [Supply public routing archives](bgp-prefix-visibility.md)

## Read from tools

```sh
probectl --json bgp path-history MONITOR_ID --query source=router_bmp
probectl --json bgp path-history MONITOR_ID --query from=2026-10-01T00:00:00Z
probectl --json bgp path-history MONITOR_ID --query cursor=NEXT_CURSOR
```

The REST operation is `GET /v1/bgp/visibility/{id}/paths`. The native MCP
tool is `bgp_as_path_history`. Both follow the same current tenant and
resource permissions. Private router history requires `events.read` and
`entities.read`. MCP also requires `ai.query` and follows the tenant's
egress redaction policy. Incident and change links use their corresponding
read permissions.

## RPKI posture for an owned prefix

Open **RPKI posture** for the monitored prefix and select the routing context
that owns the same network in inventory. The view uses complete, current
owned BMP sources. A complete local validator distinguishes a valid origin,
an invalid origin or prefix length, and an announcement with no covering
authorization. Unavailable validator evidence or an ambiguous path origin
shows as unknown.

The trend includes the original local validator generation from retained
owned path observations. Earlier path records without a captured validator
result show unknown. Historical results continue to use the validator received
at the route observation clock. The current view links related hijack incidents only when the scope,
prefix, origin and observation time match and the viewer can read the incident.

An optional intended origin lets the view suggest an exact ROA for a currently
observed owned origin. The suggestion uses the announced prefix and omits
`maxLength`, which gives the ROA the same length as the exact prefix. Review
this evidence before editing any authorization in the existing RPKI authority.
[ROA profile](https://www.rfc-editor.org/rfc/rfc9582.html#section-4.3.2.2)

```sh
probectl --json bgp rpki-posture MONITOR_ID \
  --query context_id=CONTEXT_ID --query prefix_id=PREFIX_ID --query intended_asn=64500
```

The matching read-only native MCP tool is `bgp_rpki_posture`. It requires
`events.read`, `entities.read` and `ai.query`, with current resource and
credential checks and the tenant's egress redaction policy.
