# Cross-plane context contract

The web UI uses one typed URL contract when an operator pivots between an
incident, Ask, topology, path, and the BGP/flow/device/eBPF workspaces. Think of
it as a small investigation envelope: the destination receives the same clock,
filters, and focus instead of making the operator rebuild the investigation.

The implementation is `web/src/routes/pivotContext.ts`. All registered plane
links use its `planePivotHref` helper; other surfaces use `pivotHref` and
`parsePivotContext`.

## Wire fields

| Query field | Meaning | Validation |
| --- | --- | --- |
| `ctx_v` | Contract version (`1`) | Unknown or absent versions invalidate references. |
| `ctx_expires` | Absolute expiry | RFC 3339; serializers default to 30 minutes. |
| `ctx_incident` | Incident focus | Length/control-character bounded, then destination-authorized. |
| `ctx_from`, `ctx_to` | Absolute investigation window | RFC 3339 and `from <= to`; relative windows are not accepted. |
| `ctx_filter` | Repeated `key:value` filter | Bounded count/key/value; tenant keys are rejected. |
| `ctx_selected_kind`, `ctx_selected_id` | `evidence` or `entity` focus | Both required; destination-authorized before use. |
| `ctx_return` | Return location | Local allow-listed route only; no nested context or tenant key. |

`tenant_id` is intentionally not part of the type or wire format. The active
server session supplies tenant identity. A destination may use an incident,
evidence, or entity ID only after finding it in a response already constrained
by storage-level tenant isolation and RBAC/ABAC. If the operator switches
tenant, the old ID is absent from that response, so the destination clears it.

## Fail-closed behavior

The URL is untrusted input. A malformed, expired, unauthorized, or unavailable
incident/selection becomes an empty selection. Valid absolute time and ordinary
filter values survive because they contain no authority. This gives the
operator useful orientation without treating a URL-carried object ID as proof
of access.

Pages canonicalize rejected context with `replacePivotContext`. This removes
the unsafe reference from browser history state instead of repeatedly trying it.
Incident, topology, and path destinations validate references against their
tenant-scoped API results; Ask validates evidence against its returned answer.

## History and saved views

Selection changes are normal URL history entries, so browser Back and Forward
replay focus. Filter edits use replacement entries to avoid one history entry
per keystroke. Saved views remain server-side records; applying one copies its
filters into the URL envelope. The contract never reads or writes
`localStorage` or `sessionStorage`.

Tests live in:

- `web/src/test/context-contract.test.tsx` for codec, expiry, authorization,
  saved-view, and registered-plane invariants.
- `web/src/test/cross-plane-pivots.test.tsx` for native pivots, browser history,
  and tenant-switch invalidation behavior.
