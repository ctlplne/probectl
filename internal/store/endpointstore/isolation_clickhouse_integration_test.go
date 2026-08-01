// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//go:build integration

package endpointstore

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/testsupport"
)

func TestEndpointDurableClickHouseIsolation(t *testing.T) {
	rawURL := os.Getenv("PROBECTL_TEST_CLICKHOUSE_URL")
	if rawURL == "" {
		testsupport.SkipOrFatal(t, "PROBECTL_TEST_CLICKHOUSE_URL not set — endpoint isolation integration needs ClickHouse")
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
