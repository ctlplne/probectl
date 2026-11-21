# BMP session history

The BGP console shows session transitions, router-connection lifecycle,
observed UPDATE counts and reported RIB gauges for one assigned BMP source.
Use **Planes → BGP → BMP session history**. Supply the routing context, device
ID, listener agent ID and router source reference from the existing BMP source
assignment. A neighbor address narrows the peer history and keeps the enclosing
connection's lifecycle visible.

The history uses the listener's observation clock. A peer record can also
carry the original router clock. A single connection UUID and exact sequence
retain ordering when two observations share a clock. The source can report
separate global and AFI/SAFI measurements. Decimal values preserve unsigned
64-bit counts in browsers and SDKs.

A report may contain distinct RIB and policy-stage gauges. Choose a neighbor, a published
BMP statistic type and, for a family-scoped type, a complete AFI/SAFI pair
before setting an inclusive minimum and maximum. The measured state can be
within range, outside the range, missing or affected by a coverage gap. A
zero gauge is a measured value. An observation gap leaves the peer state
unknown until a fresh supported observation establishes coverage.

The ownership boundary is the current, explicitly assigned listener and
router in the tenant routing context. The preview consumes global physical
peer observations for that assigned context. Loc-RIB generations and
delegated routing views retain their existing routing paths. Reassignments
fence the old session source. Credential revocation removes historical access
to that source. Router-originated description and optional text stay out of
the session projection.

## Query the same history

The REST request selects one source and defaults to the previous 24 hours.
Set RFC 3339 bounds for another window. Follow the returned cursor with the
same routing context, router and source identifiers. Results are newest first.

```sh
probectl bgp session-history "$ROUTER_ID" \
  --query "context_id=$CONTEXT_ID" \
  --query "collector_agent_id=$LISTENER_AGENT_ID" \
  --query "source_ref=$ROUTER_SOURCE_REF" \
  --query "peer=192.0.2.1" \
  --query "statistic=18" \
  --query "expected_min=0" \
  --query "expected_max=50000"
```

The route is `GET /v1/bgp/sessions/{router_id}`. Current event and entity access
and the assigned router's resource policy apply. The Go and TypeScript SDKs
expose the same typed query. The read-only native `bgp_session_history` tool
also requires current AI query access. Its results redact neighbor addresses,
router text and source strings. Repeat your original scope and filters when
continuing a native page.

## Session signals

An explicit Peer Down can produce a session-loss finding when the same
continuous source observed a preceding Peer Up for that physical peer.
Monitoring withdrawal, transport closure and coverage gaps leave peer loss
unconfirmed. Repeated confirmed losses can produce a flap finding. The
existing incident correlation and configured notification paths receive
these findings with original connection, sequence, reason and digest.

Observed UPDATE windows count framed route updates for one peer and policy
view within one BMP connection. They exclude End-of-RIB markers. The first
and last update clocks bound the observation. A quiet peer has no UPDATE
sample. Router-provided cumulative duplicate-update counters remain separate.
Existing [BMP listener settings](configuration.md) and the session signal
settings allow operators to tune or suppress findings. Session analytics
observes routing and reports findings through the tenant's existing controls.

[BMP formats and reason codes](https://www.iana.org/assignments/bmp-parameters/bmp-parameters.xhtml)
