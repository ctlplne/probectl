// SPDX-License-Identifier: LicenseRef-probectl-TBD

//go:build integration

package endpointstore

import (
	"context"
	"os"
	"testing"
	"time"
)

func TestEndpointDurableClickHouseIsolation(t *testing.T) {
	rawURL := os.Getenv("PROBECTL_TEST_CLICKHOUSE_URL")
	if rawURL == "" {
		t.Skip("PROBECTL_TEST_CLICKHOUSE_URL not set")
	}
	store, err := NewClickHouse(rawURL, 30)
	if err != nil {
		t.Fatal(err)
	}
	// A second control-plane boot must converge through the migration ledger;
	// CREATE/TTL application is deliberately idempotent.
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = NewClickHouse(rawURL, 30)
	if err != nil {
		t.Fatalf("second migration application: %v", err)
	}
	defer store.Close()
	ctx := context.Background()
	suffix := time.Now().UTC().Format("20060102150405.000000000")
	tenantA, tenantB := "endpoint-a-"+suffix, "endpoint-b-"+suffix
	defer func() {
		_, _ = store.DeleteTenant(ctx, tenantA)
		_, _ = store.DeleteTenant(ctx, tenantB)
	}()
	at := time.Now().UTC()
	if err := store.Insert(ctx, []Event{
		{TenantID: tenantA, AgentID: "agent-a", Type: "endpoint.wifi", Target: "visible-a", ObservedAt: at},
		{TenantID: tenantB, AgentID: "decoy-b", Type: "endpoint.wifi", Target: "SECRET-B", ObservedAt: at},
	}); err != nil {
		t.Fatal(err)
	}
	rows, err := store.Latest(ctx, tenantA)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].TenantID != tenantA || rows[0].Target != "visible-a" {
		t.Fatalf("tenant A query crossed partition: %+v", rows)
	}
}
