# test/

Integration / end-to-end test harness.

These are **black-box** tests: they drive the running services only through
their public doors (REST, gRPC, the bus) against the real dev stack defined in
[`deploy/compose/dev.yml`](../deploy/compose/dev.yml) — Postgres, Kafka,
ClickHouse, and Prometheus (services and ports:
[`deploy/compose/README.md`](../deploy/compose/README.md)) — rather than
importing `internal/` packages. That restriction is the value: a black-box
test can only pass if the *deployed* interfaces work, so it cannot be fooled
by an internal shortcut a unit test might take.

```
test/
├── integration/   # build-tagged `integration` black-box tests
└── e2e/           # full-stack end-to-end test (real binaries + public API)
```

## Why a separate module

`test/` is its own Go module (`github.com/ctlplne/probectl/test`) tied
into the workspace via `go.work`. This keeps heavy, test-only dependencies
(Kafka/ClickHouse/Postgres drivers, testcontainers, …) out of the main module's
`go.mod`/`go.sum` — anyone importing probectl's main module never inherits
them.

## Running

```sh
make test-integration   # go test -tags=integration across modules (needs the dev stack up)
make e2e                # PROBECTL_E2E=1 full-stack e2e (release image + Dex + compose deps; CI verify-all + nightly)
```

The integration tests are build-tagged `integration` (a build tag is a
compile-time label — files marked `//go:build integration` are invisible to a
plain `go test`), so they never run during the default `make test`. The e2e
test (`test/e2e`, `TestE2E`) builds the release control-plane image from
`deploy/docker/Dockerfile` (or uses `PROBECTL_E2E_IMAGE`, as CI does), runs it
the way the shipped Compose stack does — verify-full Postgres, a
least-privilege serve login, `PROBECTL_AUTH_MODE=session` against a real Dex
(`scripts/ci_dex.sh`) — signs two tenants' admins in through Dex's password
form, and has each tenant write and read tests and alert rules over HTTPS with
the API tokens those sessions mint: any cross-tenant visibility, or a by-id
read, update or delete of the other tenant's object that is not refused,
fails the run. It then redeems a one-time join token for a tenant-bound SVID, sends
a noop canary result through the agent's mTLS gRPC transport, reads that result
through the HTTPS API, and then checks two tenants' Kafka flow lanes. Both the
synthetic result and topology assertions include **cross-tenant negative
checks** (no bleed in either direction). The test is skipped unless
`PROBECTL_E2E=1` is set.

The unit-level **cross-tenant isolation** gate is separate — `make
test-isolation` runs the `isolation`-tagged suite across the main module, with
`internal/tenancy/` as the enforcement choke point. Both exist for the same
non-negotiable: see
[CONTRIBUTING.md → Non-negotiables](../CONTRIBUTING.md#non-negotiables).
