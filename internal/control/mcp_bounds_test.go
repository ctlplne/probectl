// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package control

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/ai"
	"github.com/ctlplne/probectl/internal/ai/mcp"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/fairness"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/pathstore"
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

func TestMCPFairnessAuditIsTerminalAndTenantScoped(t *testing.T) {
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
	egress := ai.NewEgressGate(
		func(context.Context, string) (bool, error) { return true, nil },
		func(context.Context, ai.EgressEvent) error { return nil },
		ai.RedactionPolicy{},
	)
	var events []mcp.CallEvent
	server := mcp.New(
		backend,
		egress,
		mcp.WithRateLimit(0),
		mcp.WithCallAudit(func(_ context.Context, event mcp.CallEvent) error {
			events = append(events, event)
			return nil
		}),
	)
	call := func(t *testing.T, principal *auth.Principal, raw string) map[string]any {
		t.Helper()
		var response struct {
			Result map[string]any `json:"result"`
			Error  map[string]any `json:"error"`
		}
		if err := json.Unmarshal(server.Handle(t.Context(), principal, []byte(raw)), &response); err != nil {
			t.Fatalf("decode MCP response: %v", err)
		}
		if response.Error != nil {
			t.Fatalf("MCP transport error: %+v", response.Error)
		}
		return response.Result
	}

	tenantA := &auth.Principal{
		TenantID:    "tenant-a",
		UserID:      "user-a",
		Permissions: map[string]bool{"test.read": true},
	}
	result := call(t, tenantA, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_tests","arguments":{}}}`)
	if result["isError"] != true {
		t.Fatalf("saturated tenant A returned tool data: %+v", result)
	}
	if len(events) != 2 ||
		events[0].TenantID != "tenant-a" || events[0].Phase != mcp.CallPhaseAdmission || !events[0].Allowed ||
		events[1].TenantID != "tenant-a" || events[1].Phase != mcp.CallPhaseTerminal || events[1].Allowed ||
		events[1].Denial != "fairness_concurrency" {
		t.Fatalf("tenant A fairness audit is not a closed admission/outcome pair: %+v", events)
	}

	tenantB := &auth.Principal{
		TenantID:    "tenant-b",
		UserID:      "user-b",
		Permissions: map[string]bool{"test.read": true},
	}
	result = call(t, tenantB, `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"get_path","arguments":{"target":"router.example"}}}`)
	if result["isError"] == true {
		t.Fatalf("independent tenant B was denied by tenant A saturation: %+v", result)
	}
	if len(events) != 4 ||
		events[2].TenantID != "tenant-b" || events[2].Phase != mcp.CallPhaseAdmission || !events[2].Allowed ||
		events[3].TenantID != "tenant-b" || events[3].Phase != mcp.CallPhaseTerminal || !events[3].Allowed {
		t.Fatalf("tenant B success audit is not an independent closed pair: %+v", events)
	}
}
