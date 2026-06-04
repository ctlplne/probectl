# proto/

Protobuf schemas for probectl's gRPC services and bus messages. Protobuf is the
wire format for both the message bus and gRPC; JSON is a development-only
fallback (CLAUDE.md §4).

## Status (S0)

No schemas exist yet. They are introduced by their owning sprints:

| File                | Sprint | Purpose                                            |
| ------------------- | ------ | -------------------------------------------------- |
| `agent.proto`       | S4     | Agent transport: Register/Attest/Heartbeat/Stream  |
| `result.proto`      | S6     | Canary result envelope (tenant_id + OTel naming)   |
| `*.events`          | S14+   | BGP / threat / change event messages               |

## Workflow

Configuration lives at the repo root (`buf.yaml`, `buf.gen.yaml`). Generate Go
stubs into `internal/gen/` with:

```sh
make proto
```

`make proto` is a no-op until the first `.proto` lands. Schemas are
**versioned and backward-compatible** — additive changes only (CLAUDE.md §6).
