// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package control

import (
	"errors"
	"testing"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/auth"
	"github.com/imfeelingtheagi/probectl/internal/fairness"
	"github.com/imfeelingtheagi/probectl/internal/store"
	"github.com/imfeelingtheagi/probectl/internal/store/pathstore"
)

func TestMCPListTestsBoundsAndFairness(t *testing.T) {
	if store.DefaultTestPageSize != 200 {
		t.Fatalf("shared test-page limit = %d, want 200", store.DefaultTestPageSize)
	}
	if mcpMaxListedTests != store.DefaultTestPageSize {
		t.Fatalf("MCP list_tests limit = %d, want shared %d-row test-page limit", mcpMaxListedTests, store.DefaultTestPageSize)
	}

	t.Run("query concurrency", func(t *testing.T) {
		gate := fairness.NewGate(fairness.Policy{QueryConcurrency: 1}, nil)
		release, err := gate.BeginQuery(t.Context(), "tenant-a")
		if err != nil {
			t.Fatal(err)
		}
		defer release()

		backend := mcpBackend{gate: gate}
		_, err = backend.ListTests(t.Context(), &auth.Principal{TenantID: "tenant-a"})
		if !errors.Is(err, fairness.ErrQueryConcurrency) {
			t.Fatalf("ListTests error = %v, want %v", err, fairness.ErrQueryConcurrency)
		}
		snapshot := gate.SnapshotTenant(t.Context(), "tenant-a")
		if snapshot.Queries.RejectedConcurrency != 1 {
			t.Fatalf("tenant query rejection accounting = %+v, want one concurrency rejection", snapshot.Queries)
		}
	})

	t.Run("query budget", func(t *testing.T) {
		gate := fairness.NewGate(fairness.Policy{QueriesPerMin: 1}, nil).
			WithNow(func() time.Time { return time.Unix(1_800_000_000, 0) })
		release, err := gate.BeginQuery(t.Context(), "tenant-a")
		if err != nil {
			t.Fatal(err)
		}
		release()

		backend := mcpBackend{gate: gate}
		_, err = backend.ListTests(t.Context(), &auth.Principal{TenantID: "tenant-a"})
		if !errors.Is(err, fairness.ErrQueryBudget) {
			t.Fatalf("ListTests error = %v, want %v", err, fairness.ErrQueryBudget)
		}
		snapshot := gate.SnapshotTenant(t.Context(), "tenant-a")
		if snapshot.Queries.RejectedBudget != 1 {
			t.Fatalf("tenant query rejection accounting = %+v, want one budget rejection", snapshot.Queries)
		}
	})
}

func TestMCPReadToolsUsePerTenantFairness(t *testing.T) {
	gate := fairness.NewGate(fairness.Policy{QueryConcurrency: 1}, nil)
	release, err := gate.BeginQuery(t.Context(), "tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	defer release()

	backend := mcpBackend{
		gate:      gate,
		pathStore: pathstore.NewMemory(),
	}
	tenantA := &auth.Principal{TenantID: "tenant-a"}
	calls := []struct {
		name string
		call func() error
	}{
		{
			name: "get_path",
			call: func() error {
				_, err := backend.GetPath(t.Context(), tenantA, "router.example")
				return err
			},
		},
		{
			name: "get_incident",
			call: func() error {
				_, err := backend.GetIncident(t.Context(), tenantA, "incident-1")
				return err
			},
		},
		{
			name: "correlate_incident",
			call: func() error {
				_, err := backend.CorrelateIncident(t.Context(), tenantA, "incident-1")
				return err
			},
		},
		{
			name: "explain_degradation",
			call: func() error {
				_, err := backend.ExplainDegradation(t.Context(), tenantA, "why?", nil)
				return err
			},
		},
	}
	for _, tc := range calls {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.call(); !errors.Is(err, fairness.ErrQueryConcurrency) {
				t.Fatalf("error = %v, want %v", err, fairness.ErrQueryConcurrency)
			}
		})
	}

	// Tenant A holding its one slot must not consume tenant B's budget. This
	// calls the real shipping GetPath backend, not the gate helper alone.
	if _, err := backend.GetPath(t.Context(), &auth.Principal{TenantID: "tenant-b"}, "router.example"); err != nil {
		t.Fatalf("independent tenant B GetPath: %v", err)
	}
	if got := gate.SnapshotTenant(t.Context(), "tenant-a").Queries.RejectedConcurrency; got != int64(len(calls)) {
		t.Fatalf("tenant A concurrency rejections = %d, want %d", got, len(calls))
	}
	if got := gate.SnapshotTenant(t.Context(), "tenant-b").Queries.Allowed; got != 1 {
		t.Fatalf("tenant B allowed queries = %d, want 1", got)
	}
}
