# proto/

Protobuf schemas for probectl's gRPC services and bus messages. Protobuf is a
compact binary serialization format in which every field travels as a *number*,
never a name — the `.proto` files here assign those numbers — and it is the
wire format for both the message bus and gRPC; JSON is a development-only
fallback. These schemas are the contract between deployed agents, the bus (whose
history is replayable), and the control plane — which is why they are treated as
append-only (see below): old bytes on the bus mean only what the field numbers
say, so renumbering or reusing a field silently re-types every event already
recorded.

## Layout

probectl's own schemas live under `probectl/<domain>/v1/` (the `v1` directory is
the wire version; schemas are additive-only and never renumber a field). A few
upstream schemas are vendored so probectl interoperates with the real ecosystem.

| File | Package | What it carries |
| ---- | ------- | --------------- |
| `probectl/agent/v1/agent.proto` | `probectl.agent.v1` | `AgentService` — Register / Attest / Heartbeat + the streaming config/result RPCs (agent ↔ control plane over mTLS) |
| `probectl/result/v1/result.proto` | `probectl.result.v1` | the canonical probe-result envelope (`Result` / `ResultBatch`), modeled on OTel resource + network semantic conventions; tenant carried as `probectl.tenant.id` |
| `probectl/bgp/v1/bgp.proto` | `probectl.bgp.v1` | `BGPEvent` / `BGPEventBatch` — the canonical form the Go bridge republishes from the Python analyzer |
| `probectl/flow/v1/flow.proto` | `probectl.flow.v1` | `FlowRecord` / `FlowBatch` — NetFlow/IPFIX/sFlow records |
| `probectl/ebpf/v1/ebpf.proto` | `probectl.ebpf.v1` | `Flow` / `ServiceEdge` / `L7Call` — eBPF host/L7 observations |
| `probectl/device/v1/device.proto` | `probectl.device.v1` | `DeviceMetric` / `DeviceMetricBatch` — SNMP/gNMI device telemetry |
| `prometheus/v1/remote.proto` | `prometheus.v1` | a minimal Prometheus remote-write schema (so probectl avoids the large Prometheus Go module) |
| `gnmi/`, `gnmi_ext/` | `gnmi`, `gnmi_ext` | vendored openconfig/gNMI schemas (kept wire-compatible; lint-exempt in `buf.yaml`) |

## Workflow

Configuration lives at the repo root (`buf.yaml`, `buf.gen.yaml`). Generated Go
(messages + gRPC stubs) lands in `internal/gen/` (mirroring the package path).

```sh
make proto-tools   # one-time: install buf + the Go codegen plugins into GOPATH/bin
make proto         # buf lint + buf generate (regenerate internal/gen)
```

`make proto` runs `buf lint` then `buf generate` (`buf` is the protobuf
toolchain — linter, breaking-change checker, code generator) with **local**
plugins: no remote BSR calls (the Buf Schema Registry, a hosted service —
deliberately never contacted, per the sovereignty/air-gap posture). Schemas are
**versioned and backward-compatible**: additive changes only, never renumber or
reuse a field tag.

**Retiring a field (SCHEMA-006):** when a field is removed, its number **and**
name are immediately fenced with a `reserved` clause in the same message, e.g.

```proto
message Foo {
  reserved 4, 7;            // numbers of removed fields
  reserved "old_name";      // names of removed fields
  string current = 8;
}
```

This makes "never reuse a retired tag" a compiler-enforced invariant rather than
a convention `buf breaking` only catches indirectly. `TestProtoNoUnreservedTagGaps`
(internal/gen) flags any gap in a message's field numbers that is not covered by
a `reserved` entry, so a silent reuse cannot slip in.

The `proto` CI job enforces append-only with a blocking
`buf breaking` check against `main` and then asserts the committed generated
code in `internal/gen/` is current — regeneration must reproduce the reviewed
tree exactly, so neither hand-edits nor codegen drift can hide there. If you
genuinely need an incompatible change, ship a new versioned package instead —
the process is in
[CONTRIBUTING.md](../CONTRIBUTING.md#proto-schemas-are-append-only).
