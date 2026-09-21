// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package control

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/incident"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestIncidentShareArtifactTenantIsolationAndExpiry(t *testing.T) {
	h, db := setupAPI(t)
	ctx := context.Background()
	tenantA, err := store.NewTenants(db.Pool()).Create(ctx, fmt.Sprintf("share-a-%d", time.Now().UnixNano()), "Share A")
	if err != nil {
		t.Fatal(err)
	}
	tenantB, err := store.NewTenants(db.Pool()).Create(ctx, fmt.Sprintf("share-b-%d", time.Now().UnixNano()), "Share B")
	if err != nil {
		t.Fatal(err)
	}
	correlator := BuildCorrelator(db.Pool(), 5*time.Minute, quietLog())
	inc, err := correlator.Ingest(ctx, incident.Signal{
		TenantID: tenantA.ID, Plane: "bgp", Kind: "bgp.origin_change", Severity: incident.SeverityCritical,
		Title: "route changed password=hunter22", Summary: "Authorization: Bearer raw-token",
		Target: "192.0.2.10", Prefix: "192.0.2.0/24", OccurredAt: time.Now().UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}

	created := apiReq(t, h, http.MethodPost, "/v1/incidents/"+inc.ID+"/shares", tenantA.ID, map[string]any{
		"context": map[string]any{
			"from": inc.StartedAt, "to": inc.LastSeenAt,
			"filters":   map[string]string{"incident_status": "open"},
			"selection": map[string]string{"kind": "evidence", "id": inc.ID + ":0"},
		},
	})
	if created.Code != http.StatusCreated {
		t.Fatalf("create share: status=%d body=%s", created.Code, created.Body)
	}
	if strings.Contains(created.Body.String(), tenantA.ID) || strings.Contains(created.Body.String(), "hunter22") || strings.Contains(created.Body.String(), "raw-token") {
		t.Fatalf("share body leaked tenant or secret material: %s", created.Body)
	}
	var artifact incidentShareResponse
	if err := json.Unmarshal(created.Body.Bytes(), &artifact); err != nil {
		t.Fatal(err)
	}
	if artifact.ID == "" || artifact.Context.Selection == nil || artifact.Context.Selection.ID != inc.ID+":0" {
		t.Fatalf("share did not preserve authorized context: %+v", artifact)
	}

	ownerRead := apiReq(t, h, http.MethodGet, "/v1/incident-shares/"+artifact.ID, tenantA.ID, nil)
	if ownerRead.Code != http.StatusOK {
		t.Fatalf("owner read: status=%d body=%s", ownerRead.Code, ownerRead.Body)
	}
	foreignRead := apiReq(t, h, http.MethodGet, "/v1/incident-shares/"+artifact.ID, tenantB.ID, nil)
	missingRead := apiReq(t, h, http.MethodGet, "/v1/incident-shares/share_missing", tenantB.ID, nil)
	var foreignError, missingError struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(foreignRead.Body.Bytes(), &foreignError); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(missingRead.Body.Bytes(), &missingError); err != nil {
		t.Fatal(err)
	}
	if foreignRead.Code != http.StatusNotFound || missingRead.Code != http.StatusNotFound || foreignError != missingError {
		t.Fatalf("cross-tenant and missing artifacts must be indistinguishable: foreign=%d %s missing=%d %s",
			foreignRead.Code, foreignRead.Body, missingRead.Code, missingRead.Body)
	}

	if err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenantA.ID)), db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `UPDATE incident_share_artifacts
			SET created_at = clock_timestamp() - interval '2 days',
			    expires_at = clock_timestamp() - interval '1 second'
			WHERE tenant_id = $1 AND id = $2`, tenantA.ID, artifact.ID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	expiredRead := apiReq(t, h, http.MethodGet, "/v1/incident-shares/"+artifact.ID, tenantA.ID, nil)
	if expiredRead.Code != http.StatusNotFound {
		t.Fatalf("expired artifact status=%d body=%s", expiredRead.Code, expiredRead.Body)
	}
}
