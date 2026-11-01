# Canonical entity registry (FX-2)

The registry gives a device, interface, address, prefix, service, site or
customer one tenant-owned ID within one routing context. It keeps the original
source identifiers and observation times beside that ID. A missing, stale or
conflicting observation stays unresolved; the registry never guesses a merge.

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
Path rounds written before the PostgreSQL-clock marker shipped retain their raw
history but cannot pass the current join, even if an old control-plane clock
dated one after an assignment. New discovery rows carry that server-owned
marker through pooled and siloed ClickHouse path tables.
Path rounds are keyed by tenant and normalized destination. Only one test per
destination can hold a context binding; another test for that host must use
the same existing path view or wait until the first binding is removed.
Changing a test's target clears its old context binding in the test-update
transaction. The operator assigns a context for the new destination.

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
Flow address and exporter aliases must name the exact configured exporter;
the protocol/domain in an exporter alias must match its provenance.
BMP peer provenance must name the verified router source and the peer alias's
ASN. Synthetic site evidence can name only its own registered agent's site
label source.
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
