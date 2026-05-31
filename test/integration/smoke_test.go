//go:build integration

// Package integration holds netctl's black-box integration tests. They exercise
// the running services over their public interfaces against the real dev stack
// (Postgres + Kafka + ClickHouse + Prometheus) defined in deploy/compose/dev.yml,
// rather than importing internal packages.
//
// S0 scaffold: a single placeholder so the harness and the `make test-integration`
// target exist. Real integration tests arrive with the result pipeline (S6+).
package integration

import "testing"

func TestDevStackHarnessPlaceholder(t *testing.T) {
	t.Log("integration harness placeholder — real integration tests land in S6+")
}
