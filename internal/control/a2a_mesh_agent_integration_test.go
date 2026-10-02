// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package control

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ctlplne/probectl/internal/a2a"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// TestMeshRejectsUnenrolledAgent is the AI-01 regression for unvalidated
// agent_ids: POST /v1/a2a/mesh accepted any agent id, so a caller could inflate
// the in-memory broker/scheduler queues with never-polling ghost agents (the
// retention/quadratic-work DoS). Every agent_id must be one of the tenant's
// enrolled agents; an unknown one is a 400.
func TestMeshRejectsUnenrolledAgent(t *testing.T) {
	srv, db := setupAPIServerWithLatest(t, nil)
	srv.WithA2ABroker(a2a.NewBroker())
	h := srv.Handler()
	ctx := context.Background()

	tenantID := freshTenant(t, db, "mesh")
	enrolled1, enrolled2 := uuid(t), uuid(t)
	enroll := func(id string) {
		t.Helper()
		err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenantID)), db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
			_, e := (store.Agents{}).Register(ctx, sc, id, id+"-secret", id+".example", "v1.4.0",
				"spiffe://probectl/tenant/"+tenantID+"/agent/"+id, []string{"http"})
			return e
		})
		if err != nil {
			t.Fatalf("enroll %s: %v", id, err)
		}
	}
	enroll(enrolled1)
	enroll(enrolled2)

	mesh := func(a1, a2 string) *httptest.ResponseRecorder {
		return apiReq(t, h, http.MethodPost, "/v1/a2a/mesh", tenantID, map[string]any{
			"mode": "udp",
			"agents": []map[string]string{
				{"agent_id": a1, "site": "s1"},
				{"agent_id": a2, "site": "s2"},
			},
		})
	}

	// Both enrolled: the mesh is scheduled.
	if rec := mesh(enrolled1, enrolled2); rec.Code != http.StatusCreated {
		t.Fatalf("mesh over two enrolled agents = %d, want 201: %s", rec.Code, rec.Body.String())
	}
	// A well-formed but unenrolled agent id is rejected 400, no sessions.
	if rec := mesh(enrolled1, uuid(t)); rec.Code != http.StatusBadRequest {
		t.Fatalf("mesh naming an unenrolled agent = %d, want 400 (unknown agent_ids must be rejected): %s", rec.Code, rec.Body.String())
	}
	// A malformed (non-UUID) agent id is also a 400, not a 500 — it must never
	// reach the uuid-typed column and abort the tenant transaction.
	if rec := mesh(enrolled1, "not-a-real-agent-id"); rec.Code != http.StatusBadRequest {
		t.Fatalf("mesh naming a malformed agent id = %d, want 400: %s", rec.Code, rec.Body.String())
	}
}

// TestA2ASessionRejectsUnenrolledAgent is the AI-01 regression for the
// single-session endpoint: POST /v1/a2a/sessions called Broker.StartSession with
// arbitrary responder/initiator strings and no validation, so it could seed
// ghost broker tasks. It must validate both agents against the caller tenant's
// enrolled agents, like /v1/a2a/mesh.
func TestA2ASessionRejectsUnenrolledAgent(t *testing.T) {
	srv, db := setupAPIServerWithLatest(t, nil)
	srv.WithA2ABroker(a2a.NewBroker())
	h := srv.Handler()
	ctx := context.Background()

	tenantID := freshTenant(t, db, "a2asess")
	responder, initiator := uuid(t), uuid(t)
	for _, id := range []string{responder, initiator} {
		err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenantID)), db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
			_, e := (store.Agents{}).Register(ctx, sc, id, id+"-secret", id+".example", "v1.4.0",
				"spiffe://probectl/tenant/"+tenantID+"/agent/"+id, []string{"http"})
			return e
		})
		if err != nil {
			t.Fatalf("enroll %s: %v", id, err)
		}
	}
	session := func(resp, init string) *httptest.ResponseRecorder {
		return apiReq(t, h, http.MethodPost, "/v1/a2a/sessions", tenantID, map[string]any{
			"responder_agent": resp, "initiator_agent": init, "mode": "udp",
		})
	}

	if rec := session(responder, initiator); rec.Code != http.StatusCreated {
		t.Fatalf("session over two enrolled agents = %d, want 201: %s", rec.Code, rec.Body.String())
	}
	if rec := session(responder, uuid(t)); rec.Code != http.StatusBadRequest {
		t.Fatalf("session naming an unenrolled initiator = %d, want 400: %s", rec.Code, rec.Body.String())
	}
}
