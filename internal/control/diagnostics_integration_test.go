// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//go:build integration

package control

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/store"
	"github.com/imfeelingtheagi/probectl/internal/support"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
)

func TestSupportBundleTopologyTwoTenantIsolationPostgres(t *testing.T) {
	srv, db := setupAPIServerWithLatest(t, nil)
	ctx := context.Background()

	tenantA, err := store.NewTenants(db.Pool()).Create(
		ctx, fmt.Sprintf("diagnostics-a-%d", time.Now().UnixNano()), "Diagnostics A",
	)
	if err != nil {
		t.Fatalf("create tenant A: %v", err)
	}
	tenantB, err := store.NewTenants(db.Pool()).Create(
		ctx, fmt.Sprintf("diagnostics-b-%d", time.Now().UnixNano()), "Diagnostics B",
	)
	if err != nil {
		t.Fatalf("create tenant B: %v", err)
	}
	if _, err := db.Pool().Exec(ctx,
		`UPDATE tenants SET isolation_model = 'hybrid' WHERE id = $1`, tenantB.ID); err != nil {
		t.Fatalf("set tenant B isolation model: %v", err)
	}

	seedAgents := func(tenantID string, count int) {
		t.Helper()
		err := tenancy.InTenant(
			tenancy.WithTenant(ctx, tenancy.ID(tenantID)),
			db.Pool(),
			func(ctx context.Context, scope tenancy.Scope) error {
				for i := 0; i < count; i++ {
					agentID := uuid(t)
					if _, err := (store.Agents{}).Register(
						ctx,
						scope,
						agentID,
						fmt.Sprintf("diagnostics-agent-%d", i),
						fmt.Sprintf("diagnostics-host-%d", i),
						"1.0.0",
						"spiffe://probectl/tenant/"+tenantID+"/agent/"+agentID,
						[]string{"tcp"},
					); err != nil {
						return err
					}
				}
				return nil
			},
		)
		if err != nil {
			t.Fatalf("seed %d agents for %s: %v", count, tenantID, err)
		}
	}
	seedAgents(tenantA.ID, 1)
	seedAgents(tenantB.ID, 3)

	for _, tc := range []struct {
		name       string
		tenantID   string
		wantAgents int
		wantModel  string
	}{
		{name: "tenant A", tenantID: tenantA.ID, wantAgents: 1, wantModel: "pooled"},
		{name: "tenant B", tenantID: tenantB.ID, wantAgents: 3, wantModel: "hybrid"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := apiReq(t, srv.Handler(), http.MethodGet, "/v1/diagnostics/bundle", tc.tenantID, nil)
			if rec.Code != http.StatusOK {
				t.Fatalf("support bundle = %d: %s", rec.Code, rec.Body)
			}
			files, err := support.ReadBundle(bytes.NewReader(rec.Body.Bytes()))
			if err != nil {
				t.Fatal(err)
			}
			var got support.TopologySummary
			if err := json.Unmarshal(files["topology-summary.json"], &got); err != nil {
				t.Fatalf("decode topology summary: %v", err)
			}
			if got.Tenants != 1 || got.Agents != tc.wantAgents {
				t.Fatalf(
					"topology summary crossed the tenant boundary: tenants=%d agents=%d, want tenants=1 agents=%d",
					got.Tenants,
					got.Agents,
					tc.wantAgents,
				)
			}
			if len(got.IsolationModels) != 1 || got.IsolationModels[tc.wantModel] != 1 {
				t.Fatalf(
					"topology isolation models crossed the tenant boundary: got %#v, want only %q=1",
					got.IsolationModels,
					tc.wantModel,
				)
			}
		})
	}
}
