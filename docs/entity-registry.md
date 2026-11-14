# Canonical entity registry (FX-2)

The registry gives a device, interface, address, prefix, service, site or
customer one tenant-owned ID within one routing context. It keeps the original
source identifiers and observation times beside that ID. A missing, stale or
conflicting observation stays unresolved; the registry never guesses a merge.

## Explicit prefix network metadata (preview)

A canonical `prefix` can carry an optional `network_prefix` CIDR. Set it
explicitly when creating the entity, or edit **Admin → Canonical entity
registry → Inspect prefix → Network range**. The server masks host bits and
returns the canonical IPv4 or IPv6 range. A display label never supplies a
range; old entities remain unset until an operator supplies one.

`POST /v1/entities` accepts `network_prefix` only on a prefix. To change an
existing prefix, use `PUT /v1/entities/{id}/network-prefix` with required
`context_id` and `network_prefix`. An explicit empty string clears it; omitted,
null, malformed or overlong fields are refused. This preserves the ID and its
tag assignments. Overlapping ranges do not merge entities or create source
identity aliases. Other entity kinds cannot store a network range.

The equivalent CLI is:

```sh
probectl --json entities network-set PREFIX_ID --body '{"context_id":"CONTEXT_ID","network_prefix":"192.0.2.0/24"}'
probectl --json entities network-set PREFIX_ID --body '{"context_id":"CONTEXT_ID","network_prefix":""}'
```

The user-only MCP tool `entity_network_prefix_set` takes `id`, `context_id`
and required `network_prefix`, with the same empty-string clear. Creates use
`entity_create` with the optional field. Writes require `agent.write` and
current context authorization; the tenant transaction atomically updates the
row and audit. The update audit records the context and whether a range is
configured, without the raw CIDR. Reads through entity GET/list and MCP
GET/list require `entities.read` and current context authorization. Pooled RLS
and physical-silo checks enforce the same prefix-only storage rule.

Effective prefix tags read this explicit range in the same tenant snapshot as
the rules. A CIDR rule must contain the entire range. Conflicting current
observations fail closed. This is operator metadata, with no claim that a
live routing collector observed the prefix; live prefix and full tag-consumer
proofs remain required before the tagging capability leaves preview.

## Complete observed interface prefixes (preview)

The authenticated evidence protocol also accepts optional complete RFC4293
interface-prefix snapshots on the configured device's address observation.
Each row retains its positive ifIndex, canonical IPv4/IPv6 network and on-link
flag. An absent snapshot means unavailable or legacy metadata; an empty,
duplicate, malformed or incomplete table cannot clear an earlier complete set.
Source, tenant, routing context and canonical device still come from the live
certificate and operator assignment. Prefixes and ifIndexes confer none of
that authority. A retry must preserve the normalized complete set and original
observation time, including whether the snapshot was absent.

The complete request must fit the existing 1 MiB evidence envelope. Its JSONB
storage representation may expand within an 8 MiB physical bound; receivers
refuse an oversized complete request rather than truncate rows. Steady-state prefix polling and current role-source loading support the
[role explanation preview](features/interface-roles.md). Explorer role dimensions
and complete real-router acceptance remain unfinished.

## Original physical BMP session observations (preview)

The existing restricted evidence mTLS channel retains complete global physical
Peer Up and Peer Down frames, their digest and receipt time, and the exact
verified router SVID serial. The receiver derives address, full 32-bit ASN,
flags, down reason, available FSM event and notification code/subcode from the
original bytes. A separate typed-retention count distinguishes durable session
metadata from a generic identity acknowledgment. An exclusive request envelope makes older
receivers refuse the operation before writing generic identities. Retries preserve the original
UUID, document and observation clock.

Every actual transition bypasses stable identity refresh suppression. Down
observations do not publish fresh address or peer-up identity. Reason 5 means
monitoring withdrawn; Loc-RIB lifecycle stays on its separate routing path.
Missing frames, source reset and collector loss do not prove carrier failure.
Current canonical source, sender/router certificates and tenant/context storage
checks remain necessary. Pooled and private schemas retain the same document
checks, tenant RLS, export and deletion lifecycle. Carrier attribution still
requires hand-off ownership and corroborating measurements.

## Set up a routing context

In **Admin → Canonical entity registry**, create a context with a site name and
VRF name, such as `West DC` and `Customer A`. The server derives stable site
and VRF IDs for that tenant and mints an opaque context ID. Reusing a site
name with another VRF keeps the site ID; another tenant receives different
IDs even with the same names and private IPs. A duplicate named pair is
refused so the operator can select the existing context. The names are for
display and setup; no packet or collector may use a name to select a context.

Create or choose a canonical device in the context, then bind a **registered**
collector's configured source reference to that context and, for a device
target, its device anchor. The assignment requires `agent.write` and shares a
transaction with the tenant audit record. One evidence sender identity belongs
to one context. A collector serving another VRF needs another registered
identity. Rebinding or revoking a source stops its former current joins while
leaving evidence history visible. An unchanged repeated assignment keeps its
current evidence; changing or reactivating a binding starts a new authority
interval. Earlier observations stay historical, and a fresh sender-bound
observation is needed before current identity resolves again.

An operator can bind a path test to a context separately. The current path
identity view requires both `test.read` and `entities.read`. It resolves hop
addresses against **current** evidence in that context and labels the result
as current; it does not rewrite saved traces or historical rounds.
Only a discovery that **started** strictly after the operator's test/context
assignment can appear in this current view. The control plane captures that
start time from PostgreSQL, the same clock that dates assignments, before the
trace begins. A short test-row lock orders this capture against a concurrent
context assignment, and a delayed ClickHouse batch keeps that original time.
Earlier rounds lack a proven routing context and return `awaiting_trace` with
no current responders. ClickHouse's millisecond precision also leaves a same-millisecond
round in that state. A fresh trace makes the view available. REST, CLI, MCP and
the Path page share this boundary; raw path history stays raw.
The REST path identity response declares `coverage`: `no_bound_context`,
`no_post_binding_trace`, or `registered_sources_only`. An empty current join
therefore never claims that unregistered devices or silent collectors do not
exist. Entity, evidence, link and context pages are bounded registry records;
an empty page describes the registry, not complete network coverage.
Path rounds written before the PostgreSQL-clock marker shipped retain their raw
history but cannot pass the current join, even if an old control-plane clock
dated one after an assignment. New discovery rows carry that server-owned
marker through pooled and siloed ClickHouse path tables.
Path rounds are keyed by tenant and normalized destination. Multiple tests may
bind the same destination when they share its one canonical context. A
FORCE-RLS target anchor and compound per-test foreign key enforce that invariant
in storage, including concurrent writes and managed silos. A test in another
context cannot borrow the shared trace. Each test keeps its own assignment
clock, and still requires a discovery that began after that binding. Removing
the last binding also removes its unused target anchor.

Changing a test's target clears its old context binding in the test-update
transaction. The operator assigns a context for the new destination.

The same explicit test-context binding supports a valid `noop` test with no
target, so its name rules and manual tags can resolve in the owned context.
It creates only general test metadata context. It creates no path destination
binding or discovery authority, and removes any earlier path binding for that
test. Multiple targetless noop tests do not claim a shared empty destination.
Tenant ownership, `agent.write`, context policy and atomic audit still apply.

## Sender-bound evidence

Raw device, flow, BMP and agent telemetry keeps its existing transport.
Canonical claims use the restricted `SubmitEntityEvidence` RPC on the existing
agent mTLS listener. Its additional `plane=entity` certificate is issued with
an operator-minted, one-use token pinned to the existing registered agent ID
and a collector-owned CSR. The request has no tenant, context or entity ID:
the verified certificate and current operator assignment select them. Agent,
BMP-router and eBPF certificates cannot call this RPC. A BMP claim also pins
the verified router certificate serial; a revoked router certificate makes
its evidence historical.
An observation is canonical evidence only when its timestamp falls within
the sender certificate's issuance window and, for BMP, the router
certificate's window too. A queued or future-dated frame outside either
window remains raw telemetry and produces no canonical join.
The receiver admits only aliases from the authenticated source family:
SNMP device/interface/neighbor for device sources, exporter/address for flow,
peer/address for BMP, hop/address for path agents and site for synthetic
agents. A cross-family alias is rejected before the tenant transaction.
Public routing collectors use `public_bgp` assignments through the same
tenant-owned source API, with no `anchor_entity_id`. Their source reference
identifies the operator-configured feed, format and collector. This assignment
does not authorize any entity alias, router identity or complete RIB claim.
Routing authority additionally requires the exact current entity-purpose
collector credential, current context assignment and an observation born after
both assignments and credential issuance. Revocation, expiry, withdrawal and
rebinding invalidate retained authority. Existing physical tenant silos receive
the same source-family and anchor/selector shape constraints on catch-up.
Flow address and exporter aliases must name the exact configured exporter;
the protocol/domain in an exporter alias must match its provenance.
BMP peer provenance must name the verified router source and the peer alias's
ASN. Synthetic site evidence can name only its own registered agent's site
label source.
That site observation can carry a complete local-address snapshot for agent
CIDR tags. It adds no address identity aliases. Legacy/unavailable metadata is
distinct from a complete empty clear; replay cannot change either presence or
values on an existing observation UUID. The latest site epoch remains a cutoff
after expiration or revocation, preventing an older address set from becoming
current again. Same-epoch contradictory current sets fail closed. The field is
source-family and host-address checked in pooled and physical-silo storage and
does not appear in public raw-evidence projections. Current ordinary agent
identity and the complete evidence sender/source/context predicate remain
required before tags can use the private address facts.

### ICMP collector facts (preview)

Version 2 additionally retains one terminal network-error outcome per original
probe index: actual responder, ICMP type/code, receipt clock, whole-packet digest
and an explicit conflict flag. The collector requires the current run's random
challenge in the quoted original echo request and verifies the outer checksum;
short quotes, unrelated probes and unwritten sequences remain unavailable. Full
probe indices survive the 16-bit wire sequence wrap. Different terminal outcomes
remain conflicting, never a selected winner. A network error is packet provenance,
not ASN ownership or router-down authority. Existing tenant/source assignments,
current test definition, certificate checks, immutable retries and typed retention
receipts still apply. The finite transport admission supports the complete
configured population; it never keeps an outcome prefix. Subject export/erasure
matches these responder addresses exactly through the same tenant-scoped lifecycle.

A `path_agent` source can retain typed ICMP measurement metadata on its address
observation. Its configured reference is the current enabled test UUID. The
receiver checks the exact executable-definition digest, packet population and
explicit test/context binding under the same tenant transaction as the issued
sender certificate and operator-owned canonical device anchor. Both collection
clocks must follow the current credential and assignments; literal targets must
match the observed destination. The actual responder set preserves IPv6 anycast
replies from a different unicast address.

The metadata records requested, attempted, transmitted and received packets,
local send errors, reply-window completion, cancellation and local IO failure.
Incomplete IO remains unknown health. Ordinary result metrics cannot provide
this evidence. A typed retention receipt is required: a legacy server's generic
address acknowledgment cannot certify that it retained the measurement. Exact
UUID retries preserve every normalized field and original clock.

The optional agent `evidence` configuration enables background delivery. Current
observations are coalesced per test definition; the existing `buffer.max_records`
and positive `buffer.max_bytes` values bound pending plus in-flight memory. A
records-only disk setting uses the normal 256 MiB memory budget. Exhaustion
refuses a whole observation, logs usage and increments the existing error metric;
probes and ordinary buffered results continue. Retry never replaces newer
unknown/healthy data with an older failure. No additional retained agent queue
or listener is created.

The original metadata uses the existing evidence lifecycle and tenant boundary.
Subject export/erasure matches responder IPs exactly, including IPv6, and keeps
nearby addresses and the other tenant intact. Observations before the existing
erasure cutoff cannot recreate deleted evidence. Dependency notification
routing remains a preview and still needs complete current graph/incident proof.

The internal current-health reader selects the newest measurement for one exact
agent/test in an explicit tenant/context. It reads the live test definition,
canonical anchor, both context assignments, issued sender and erasure cutoff in
one database snapshot. A newer incomplete sample replaces older health, and
conflicting equal-clock samples remain unknown. Only a complete transmitted
batch with a completed reply window and no local IO failure can establish
reachability or total echo loss. Stale, unadmitted, disabled, rebound or revoked
sources remain unknown; a source snapshot alone never authorizes a hold.

The configured-target SNMP address observation may also carry bounded raw
`sysName` and `sysDescr` metadata. These fields never select identity or context.
Raw system-name presence distinguishes a legacy omission from an explicit
empty clear, and UUID replay compares that presence as well as the exact bytes.
Identity aliases retain their existing normalization. Current tag reads keep
the raw name separate and reject a contradictory same-poll identity alias.
An SNMP interface address is stored on its ifIndex entity when that entity
exists, preserving its own detail provenance. Address resolution projects the
interface's parent device for cross-plane joins; a device target IP that also
appears on one of its interfaces remains one canonical device candidate.
An unanchored flow exporter or BMP peer may resolve to a device only when one
independent, current SNMP device/interface address observation in the same
tenant and routing context names that device. Its evidence row stores the exact
SNMP support evidence ID. Current reads recheck that row's source assignment,
sender certificate, expiry and address uniqueness; a later conflict or rebind
retires the inferred join while preserving its original observation. An
explicit operator anchor uses its own assignment and has no inferred support.
An idempotent replay keeps the original support row even if a delayed SNMP
observation is now the preferred support for a new claim. The replay cannot
rewrite historical provenance or create a second evidence row.

### Configured-test outcomes (preview)

The same evidence-only mTLS RPC accepts an optional non-ICMP outcome from a
registered agent's explicitly assigned `path_agent` test source. A
`configured_test_id` alias names the exact canonical test UUID. The receiver
checks the enabled executable definition, general test/context assignment,
current source anchor, issued sender and erasure cutoff in one tenant
transaction. An HTTP test needs no path-trace binding. Retargeting or removing
the general assignment withdraws authority; an address or a bus result cannot
create it.

Version 1 outcomes contain only their version, exact definition digest,
canary type, original runtime start/completion, success and cancellation. Raw
errors, response bodies, targets and secret-bearing parameters are excluded.
Each execution keeps its own observation UUID; a later success cannot replace
an earlier failure in the delivery queue. Pending and in-flight outcomes share
the existing finite record/byte admission. Delivery retries require an explicit
typed retention count, and the same UUID cannot rewrite the stored body.
Legacy generic acknowledgments do not acknowledge typed metadata.

Version 2 HTTP outcomes also retain the primary response's numeric status,
verified TLS flag and whether its final origin equals the configured origin.
Nonstandard status values accepted by the HTTP transport are preserved.
Posture-only TLS handshakes create no primary response fact. These fields come
from the collector's actual request, never result attributes or ordinary bus
JSON. Wrong versions, unknown fields and malformed values fail closed. Version
1 bodies remain byte-compatible and readable. These are original observations,
not a verdict about a provider or fault location. Upgrade the control plane
before agents that emit version 2: an older receiver refuses new typed evidence
without acknowledging or downgrading it.

This is observed application-test evidence, not packet-loss measurement, an
upstream cause or a rolling SLO-budget verdict. Cancellation is unavailable
health. Historical reads retain original clocks and recheck the current
definition and source rather than making older observations current. Storage
and lifecycle use the existing pooled/silo tenant boundary and evidence
retention. Structural test UUIDs are excluded from personal-text erasure
matching; actual personal labels and responder IPs retain their normal privacy
semantics.
The same rule holds after source rebind or expiry: an exact UUID replay only
acknowledges the historical row, while any changed collector field is rejected.
Physical LLDP/CDP evidence requires a current, independently observed remote
device in the same tenant and context. Deleting that remote device cascades
the physical link but keeps the local signed observation as historical
evidence. Its neighbor alias then stops resolving and its detail row shows
`current=false`; an exact UUID retry acknowledges the old row without
reattaching it to a replacement device using the same address.
The storage index permits only one physical edge for each signed observation
within its tenant and context.
The current read also rechecks the remote SNMP source assignment, signed
evidence freshness and uniqueness. If the remote proof expires or a second
device claims the same management address, the physical alias and local
observation become historical until unique support is restored.
The control plane exposes `probectl_entity_evidence_batches_total` with fixed
`accepted`, `partial`, `unresolved`, and `rejected` outcomes, plus
`probectl_entity_evidence_observations_total` with fixed `accepted` and
`unresolved` outcomes. These counters have no tenant, source address, agent,
or canonical entity labels. A rejected batch records no accepted observation.

Place each evidence certificate at `cert.pem`, its private key at `key.pem`,
and the control-plane server trust at `server-ca.pem` in a dedicated identity
directory. Configure the HTTPS rotation URL as well as the evidence listener
address. The collector renews the certificate at two thirds of its lifetime;
a renewal failure leaves raw telemetry running and canonical joins expire.
After an atomic renewal, the sender replaces its long-lived gRPC connection
so the next evidence RPC presents the new SVID. It immediately restates the
current observed identity even if the unchanged snapshot was recently accepted.
If reconnect fails, later optional submissions retry it while raw telemetry
continues. A changed tenant, agent or certificate plane is refused.
The optional evidence channel has its own per-tenant fairness bucket, bounded
batch size and five-second client deadline.
Failed SNMP polls can submit a `device.poll_failed` observation on this same
RPC. The fault carries a bounded UUID, configured source and observed IP, but
no tenant, agent, context or entity authority. The live evidence SVID and
current source assignment select those. Device and flow fault targets must
equal their configured IP source. A FORCE-RLS receipt records one observation
per tenant, sender and UUID in the incident correlation transaction, including
after incident resolution; conflicting UUID reuse is rejected. A failure of
this optional channel leaves the original device collection outcome intact.
The correlation transaction locks and rechecks the exact source and agent
assignments at both fault time and ingest time. A live certificate cannot
submit a fault for a removed or expired configured source.
The flow collector also turns its existing `no_recent_packets` quality state
into `flow.exporter_silent` only for an explicitly configured exporter that
has previously sent packets. All protocol windows for that exporter must be
stale; one live protocol suppresses the fault. A one-batch evidence queue and
64-fault RPC batches keep the quality/bus path independent of the mTLS call.
A dropped invalid protocol window also suppresses that exporter's optional
silence fault for the tick, since not all observed protocols are known stale.
The worker checks whether a packet arrived after the queued stale window
before submitting; a dropped recovery batch cannot make that old window a
current silence fault. If bounded quality-window eviction removed a later
recovery packet, the queued window is incomplete and the optional fault is
suppressed until a later complete stale window.
A pending UUID is retried after a lost response; a sustained outage refreshes
at most once per five minutes, and a recovered exporter resets that throttle.
The device adapter uses the same five-minute refresh and stable pending UUID
rule. A successful SNMP poll clears its outage throttle. Rotation restates an
unacknowledged fault at the new certificate's time, because the new SVID
cannot attest an event from before its issuance.
Agent counters distinguish accepted and failed fault submissions without
tenant, source or target metric labels. The fault adapter and receipt are a
draft until their Go, PostgreSQL, mTLS and real-stack proofs pass.

## Read the result

Admin pages entity records, evidence and typed links; source-specific
permissions apply before provenance is returned. Path, Topology, Explorer and
incident views offer current identity pivots only in an explicit context.
REST and MCP recheck `entities.read` against the resolved routing context even
for empty pages and unresolved addresses; context-bound writes recheck
`agent.write`. Those decisions use tenant-scoped stored `context_id`, `site_id`,
`vrf_id` and site/VRF labels, never request-supplied policy attributes.
Context creation checks the proposed labels before writing. A context-specific
ABAC denial therefore applies across entity reads and assignments. Context
enumeration checks every returned item before releasing the page.
An inferred flow/BMP candidate also needs the device-plane read permission
because its canonical match depends on SNMP evidence; the source-plane
permission alone cannot reveal the supporting ID or the inferred identity.
Explorer resolves one selected observed IP at a time rather than querying
every result row. A conflict shows candidate evidence and truncation, and a
historical or frozen result remains unchanged. All authoritative tables use
tenant-first FORCE RLS and tenant/context compound keys, including in silos.

## Incident identity and human overrides

The current incident-room pivot reads registry identity on demand without
rewriting the original signal or its cited timestamp. The correlator's
canonical rule requires an authenticated evidence-plane sender, a current
operator source assignment, and a current address observation from that exact
sender and certificate serial. It persists the verified tenant/context/entity
tuple beside each incident and signal. A different raw target can join the
same entity; a reused private IP in another VRF or tenant cannot. An
evidence row observed after the fault cannot retroactively make that fault
canonical, even if the same sender later reports the address. The exact
sender SVID and operator assignment must also cover the fault time. An
unassigned, ambiguous, stale or unavailable identity lookup stays ungrouped
and never falls back to raw private-IP matching. Contextless legacy signals
keep the existing time/target/prefix rule, including the G4a demonstration.

An operator's **ungroup** instruction follows the same verified tuple.
An override for one VRF cannot detach or annotate an incident in another VRF
with the same raw address. Deleting a canonical entity preserves the original
incident timeline and its context tombstone; a tombstoned override does not
match a new, unrelated device. These correlation rules remain a draft until
the fault adapter's real sender proof and full FX-2 gate are completed; the
current pivot is a read-time view, not a historical rewrite.

The incident-impact API accepts `include_tests: true` to compare these original
observations with the same window one week earlier. This additionally requires
current `test.read` at the tenant, context and exact test resources. Tests with
no retained observations stay unavailable; local IO errors and cancellation
stay unknown. Every returned observation cites its retained evidence UUID and
body/header digest. The final publication snapshot rechecks those original
selectors and current permissions without running the historical query again.
The incident room, SDK, CLI JSON input, MCP and signed export share this optional
selection. Matching current SLO definitions cite failed original inputs using
the producer's exact selector semantics; they do not infer rolling budget state.
Customer classification uses current effective test tags only for original
failures or complete measured echo loss, and cites the matching SLO failed
inputs. It requires current tag disclosure for each exact affected test and
rechecks that metadata before returning; configuration alone is never a hit.

## Original polled hop health (preview)

`GET /v1/tests/{id}/path/entities?include_health=true` adds the six original
in/out octet, error and discard counters to each uniquely resolved, currently
polled interface. The test's assigned routing context selects the canonical
interface and its exact current device-agent source. An IP match alone never
selects a device's other port. Unresolved, conflicting and unpolled hops carry
explicit availability; they do not receive invented zero values.

The default health window is the last 15 minutes. `health_from` and
`health_to` accept RFC3339 timestamps, and `health_poll_gap` accepts a positive
Go duration (default `5m`). Windows have no fixed age/row cap; the existing
per-tenant fairness, memory, complete-response and execution admission applies.
A refusal never returns shortened history. Original source validity and
current user, credential, context, lifecycle and evidence grants are rechecked
before publication. Health additionally requires `metrics.read`.

```sh
probectl --json entities path-resolve TEST_ID --query include_health=true
probectl --json entities path-resolve TEST_ID --query include_health=true --query health_max_bps=10000000000
```

Every observed direction retains the two original capture keys/digests, poll
clocks, exact decimal counter words, counter width and independently observed
interface speed. A rational rate uses the interval between original poll starts;
it is a mean over those polls, with polling latency still present. Matching
uptime and discontinuity clocks are required. Missing/stale/overlapping polls,
changed width or a restart keep the original observations with an explicit
unavailable rate. A modular delta alone is only a minimum, even if its counter
word rose: complete hidden wraps are possible. No maximum is inferred from a
current interface speed or a financial agreement.

`health_max_bps` is an optional, operator-supplied physical upper bound in
bits/second, applied to each selected interface. An octet delta is exact under
that explicit bound only when no extra complete wrap fits; contradictory deltas
are unavailable. Error/discard rates remain minima because there is no packet
upper-bound assumption. Utilisation is an exact rational percentage of the
polled speed, explicitly conditional on that speed having remained constant
between the two polls. An absent, zero or changed speed does not yield a
percentage. Raw words remain strings, including integers above JavaScript's
exact-number range.

`config_coverage=unavailable_no_context_bound_archive` means the archive reader
is unavailable. `no_bound_archive_in_window` means it found no archive for the
exact current source in the selected window. This preview never attaches
configurations by matching global device names or addresses.
`path_interface_health` exposes the same admitted reader over native MCP
with full source-text redaction and exact original numeric/receipt metadata.
Operator-bound configuration references share that exact current source and
assignment. `health.config_changes` retains every original archive in the
admitted interval, including an original predecessor outside it; it never
truncates to a fixed row count. `config_coverage` distinguishes a missing archive
from an operator-bound archive. References attest the operator association,
not device collection, and contain no configuration content. An erased or
changed reference refuses publication rather than substituting a same-name or
same-hash record. See [device archives](device-telemetry.md#syslog-and-config-archive).

`POST /v1/ai/ask` with `subject.path_test_id=TEST_ID` and the Path screen's
explanation action use only this owned path's complete original health document.
The optional `health_*` subject fields have the same meaning as the reader's
query parameters; `range` overrides the health window. Every admitted responder,
including unresolved ones, is in `evidence.fields.path_health`; evidence IDs
ground the explanation and original capture keys identify the polls. Current
grants/source identity and the exact credential are checked again before model
dispatch and publication. These explanations are live/stateless, and do not
populate the optional answer-artifact store. Empty, stale and foreign path IDs
refuse rather than widening to unrelated data. The native counterpart is
`path_interface_health_explain`. The Path inspector exposes the complete cited
snapshot, which can differ from a historical trace round selected in the graph.

```sh
probectl --json ai ask --body '{"question":"Explain original path interface observations without assuming causation","subject":{"path_test_id":"00000000-0000-4000-8000-000000000001"}}'
```

Context-bound recent configuration references, physical
traceroute/SNMP validation and the complete served-surface proof remain required
before this feature leaves preview.
