# proto/

Protobuf schemas for probectl's gRPC services and bus messages. Protobuf is the
wire format for both the message bus and gRPC; JSON is a development-only
fallback (CLAUDE.md §4).

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

`make proto` runs `buf lint` then `buf generate` with **local** plugins (no
remote BSR calls — sovereignty/air-gap posture). Schemas are **versioned and
backward-compatible**: additive changes only, never renumber or reuse a field
tag (CLAUDE.md §6); `buf breaking` guards this in CI.
