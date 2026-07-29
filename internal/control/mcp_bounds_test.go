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
