// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package config

import "testing"

// PLAT-01/RTO-04: VolatileStores reports every memory-backed plane regardless of
// profile (it drives the loud operator-facing surfaces), while
// volatileProductionModes keeps its profile gate (the HARD refusal for
// production-like profiles).
func TestVolatileStoresReportsEveryMemoryPlaneRegardlessOfProfile(t *testing.T) {
	mem := &Config{
		BusMode: "memory", TSDBMode: "memory", PathStoreMode: "memory",
		FlowStoreMode: "memory", OTelStoreMode: "memory", EBPFStoreMode: "memory",
		EndpointStoreMode: "memory",
	}
	if got := mem.VolatileStores(); len(got) != 7 {
		t.Fatalf("all-memory config: VolatileStores = %v, want 7 planes", got)
	}

	// The default "single" profile must NOT hard-error (it is the dev/sovereign
	// quickstart) — but VolatileStores still reports so the deployment is loud.
	mem.DeploymentProfile = "single"
	if got := volatileProductionModes(mem); got != nil {
		t.Errorf("single profile must not hard-error on volatile modes, got %v", got)
	}
	if got := mem.VolatileStores(); len(got) != 7 {
		t.Errorf("VolatileStores must report regardless of profile, got %v", got)
	}

	// A production-like profile still refuses every memory plane at config load.
	mem.DeploymentProfile = "multi-tenant"
	if got := volatileProductionModes(mem); len(got) != 7 {
		t.Errorf("production profile must refuse all 7 memory planes, got %v", got)
	}

	durable := &Config{
		BusMode: "nats", TSDBMode: "prometheus", PathStoreMode: "postgres",
		FlowStoreMode: "clickhouse", OTelStoreMode: "clickhouse", EBPFStoreMode: "clickhouse",
		EndpointStoreMode: "clickhouse",
	}
	if got := durable.VolatileStores(); len(got) != 0 {
		t.Errorf("durable config must report no volatile planes, got %v", got)
	}
}

func TestVolatileAcknowledged(t *testing.T) {
	c := &Config{}
	if c.VolatileAcknowledged() {
		t.Error("empty PROBECTL_ALLOW_VOLATILE must not acknowledge")
	}
	c.AllowVolatile = "yes"
	if c.VolatileAcknowledged() {
		t.Error("an arbitrary value must not acknowledge — the exact phrase is required")
	}
	c.AllowVolatile = "  " + VolatileAckPhrase + "  "
	if !c.VolatileAcknowledged() {
		t.Error("the exact ack phrase (trimmed) must acknowledge")
	}
}
