// The integration-test module. Black-box tests live here and exercise the
// running services over their public interfaces against the real dev stack
// (deploy/compose/dev.yml). Keeping them in a separate module isolates heavy
// test-only dependencies (Kafka/ClickHouse/Postgres drivers, testcontainers,
// ...) from the production module added in S6+.
module github.com/ctlplne/probectl/test

go 1.26.7

// Patched toolchain. Keep in sync with the root module + go.work.
toolchain go1.26.7
