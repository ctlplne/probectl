// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package control

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/imfeelingtheagi/probectl/internal/ai"
	"github.com/imfeelingtheagi/probectl/internal/ai/author"
	"github.com/imfeelingtheagi/probectl/internal/auth"
	"github.com/imfeelingtheagi/probectl/internal/store/flowstore"
)

func TestHandleAIAuthor(t *testing.T) {
	h := testServer(nil).Handler()

	// A concrete prompt → a schema-valid HTTP proposal (air-gapped heuristic).
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, aiTestReq(http.MethodPost, "/v1/ai/author", map[string]any{"prompt": "monitor https://api.example.com/health"}))
	if rec.Code != http.StatusOK {
		t.Fatalf("author: status %d body %s", rec.Code, rec.Body.String())
	}
	var prop struct {
		Spec struct {
			Type   string `json:"type"`
			Target string `json:"target"`
		} `json:"spec"`
		Source string `json:"source"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &prop); err != nil {
		t.Fatal(err)
	}
	if prop.Spec.Type != "http" || prop.Source == "" {
		t.Errorf("proposal = %+v", prop)
	}

	// Empty prompt → 422.
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, aiTestReq(http.MethodPost, "/v1/ai/author", map[string]any{"prompt": "  "}))
	if rec.Code != http.StatusUnprocessableEntity {
		t.Errorf("empty prompt: status %d, want 422", rec.Code)
	}

	// A target-less prompt → 422 (could not author; propose nothing rather than guess).
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, aiTestReq(http.MethodPost, "/v1/ai/author", map[string]any{"prompt": "make everything good"}))
	if rec.Code != http.StatusUnprocessableEntity {
		t.Errorf("target-less prompt: status %d, want 422", rec.Code)
	}
}

func TestHandleAIAuthorProviderFailureDoesNotDiscloseResponseBody(t *testing.T) {
	const hostileBody = "provider-secret-body customer=alice@example.com token=remote-secret"
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, hostileBody, http.StatusBadGateway)
	}))
	defer provider.Close()

	model, err := ai.NewHTTPModel(ai.HTTPModelConfig{
		Kind:     ai.KindOllama,
		Endpoint: provider.URL,
		Model:    "test-model",
	})
	if err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	srv := testServer(nil)
	srv.log = log
	srv.authorEngine = author.NewEngine(author.NewModelAuthor(model, model.Name()))
	srv.http.Handler = srv.routes()

	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, aiTestReq(http.MethodPost, "/v1/ai/author", map[string]any{
		"prompt": "monitor api.example.com",
	}))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("author status = %d, want 503; body=%s", rec.Code, rec.Body.String())
	}
	if got := rec.Body.String(); strings.Contains(got, hostileBody) || strings.Contains(got, "remote-secret") {
		t.Fatalf("author API disclosed the untrusted provider body: %s", got)
	}
	if got := logs.String(); strings.Contains(got, hostileBody) || strings.Contains(got, "remote-secret") {
		t.Fatalf("author logs disclosed the untrusted provider body: %s", got)
	} else if !strings.Contains(got, "ollama") || !strings.Contains(got, "502") {
		t.Fatalf("author logs lost bounded provider/status context: %s", got)
	}
}

func TestHandleAIDiscoverNoData(t *testing.T) {
	h := testServer(nil).Handler()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, aiTestReq(http.MethodPost, "/v1/ai/discover", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("discover: status %d body %s", rec.Code, rec.Body.String())
	}
	var out struct {
		Proposals []any `json:"proposals"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Proposals) != 0 {
		t.Errorf("with no data there should be no proposals, got %v", out.Proposals)
	}
}

type discoverFlowStore struct {
	flowstore.Store
	query flowstore.TopQuery
	rows  []flowstore.TopRow
	err   error
}

func (s *discoverFlowStore) TopTalkers(_ context.Context, q flowstore.TopQuery) ([]flowstore.TopRow, error) {
	s.query = q
	return s.rows, s.err
}

type discoverProposalResponse struct {
	Proposals []struct {
		Spec struct {
			Type   string `json:"type"`
			Target string `json:"target"`
		} `json:"spec"`
		Rationale string `json:"rationale"`
		Score     int    `json:"score"`
		Source    string `json:"source"`
	} `json:"proposals"`
}

func TestHandleAIDiscoverFlowQueryIsBoundedAndProposeOnly(t *testing.T) {
	store := &discoverFlowStore{
		Store: flowstore.NewMemory(),
		rows: []flowstore.TopRow{
			{Key: "203.0.113.10", Flows: 9},
			{Key: "203.0.113.11", Flows: 1}, // below the flow noise threshold
		},
	}
	srv := testServer(nil).WithFlowStore(store)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, aiTestReq(http.MethodPost, "/v1/ai/discover", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("discover: status %d body %s", rec.Code, rec.Body.String())
	}
	if store.query.TenantID != "00000000-0000-0000-0000-000000000001" ||
		store.query.By != flowstore.ByDst ||
		store.query.Window != time.Hour ||
		store.query.Limit != 20 {
		t.Fatalf("unbounded or incorrectly scoped flow query: %+v", store.query)
	}
	var out discoverProposalResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Proposals) != 1 {
		t.Fatalf("proposals = %+v, want one thresholded destination", out.Proposals)
	}
	got := out.Proposals[0]
	if got.Spec.Target != "203.0.113.10" || got.Spec.Type != "icmp" ||
		got.Source != "flow" || got.Score != 9 ||
		!strings.Contains(got.Rationale, "Observed 9× on the flow plane") {
		t.Fatalf("flow proposal = %+v", got)
	}
	// The discovery handler owns no test-creation call or scheduler seam. A
	// proposal is the terminal effect until the separate POST /v1/tests action.
}

// TestAIDiscoverFlowDestinationTenantIsolation is the named two-tenant proof
// for the new discovery data path. Tenant B's much larger destination must
// never enter tenant A's proposal list.
func TestAIDiscoverFlowDestinationTenantIsolation(t *testing.T) {
	srv := testServer(nil)
	seedFlows(t, srv)

	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, aiTestReq(http.MethodPost, "/v1/ai/discover", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("discover: status %d body %s", rec.Code, rec.Body.String())
	}
	var out discoverProposalResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Proposals) != 1 || out.Proposals[0].Spec.Target != "10.0.0.9" {
		t.Fatalf("tenant-local proposals = %+v, want only 10.0.0.9", out.Proposals)
	}
	for _, proposal := range out.Proposals {
		if proposal.Spec.Target == "172.16.9.8" {
			t.Fatalf("CROSS-TENANT FLOW DISCOVERY LEAK: %+v", proposal)
		}
	}
}

func TestHandleAIDiscoverFlowSourceRequiresRBACAndABAC(t *testing.T) {
	const tenant = "00000000-0000-0000-0000-000000000001"
	newServer := func() *Server {
		store := &discoverFlowStore{
			Store: flowstore.NewMemory(),
			rows:  []flowstore.TopRow{{Key: "203.0.113.10", Flows: 5}},
		}
		return testServer(nil).WithFlowStore(store)
	}
	call := func(t *testing.T, srv *Server, principal *auth.Principal) discoverProposalResponse {
		t.Helper()
		req := aiTestReq(http.MethodPost, "/v1/ai/discover", nil)
		req = req.WithContext(auth.WithPrincipal(req.Context(), principal))
		rec := httptest.NewRecorder()
		apiHandler(srv.handleAIDiscover).ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("discover: status %d body %s", rec.Code, rec.Body.String())
		}
		var out discoverProposalResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		return out
	}

	t.Run("tenant boundary precedes source RBAC", func(t *testing.T) {
		srv := newServer()
		req := aiTestReq(http.MethodPost, "/v1/ai/discover", nil)
		req = req.WithContext(auth.WithPrincipal(req.Context(), &auth.Principal{
			Permissions: map[string]bool{permTestWrite: true},
		}))
		rec := httptest.NewRecorder()
		apiHandler(srv.handleAIDiscover).ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("missing tenant must fail before flow RBAC: status %d body %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("RBAC missing", func(t *testing.T) {
		out := call(t, newServer(), &auth.Principal{
			TenantID: tenant, Permissions: map[string]bool{permTestWrite: true},
		})
		if len(out.Proposals) != 0 {
			t.Fatalf("caller without flow.read learned flow targets: %+v", out.Proposals)
		}
	})

	t.Run("ABAC deny overrides RBAC", func(t *testing.T) {
		srv := newServer()
		srv.abac = &abacCache{
			pool: new(pgxpool.Pool),
			data: map[string]abacEntry{
				tenant: {
					expiry: time.Now().Add(time.Hour),
					policies: []auth.Policy{{
						Name: "deny-flow", Effect: auth.PolicyDeny,
						Permission: permFlowRead, Enabled: true,
					}},
				},
			},
		}
		out := call(t, srv, &auth.Principal{
			TenantID: tenant,
			Permissions: map[string]bool{
				permTestWrite: true,
				permFlowRead:  true,
			},
		})
		if len(out.Proposals) != 0 {
			t.Fatalf("ABAC-denied caller learned flow targets: %+v", out.Proposals)
		}
	})
}

func TestHandleAIDiscoverReportsFlowStoreFailure(t *testing.T) {
	store := &discoverFlowStore{
		Store: flowstore.NewMemory(),
		err:   errors.New("flow store unavailable"),
	}
	srv := testServer(nil).WithFlowStore(store)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, aiTestReq(http.MethodPost, "/v1/ai/discover", nil))
	if rec.Code != http.StatusServiceUnavailable ||
		!strings.Contains(rec.Body.String(), "flow-derived discovery is temporarily unavailable") {
		t.Fatalf("flow failure must be explicit: status %d body %s", rec.Code, rec.Body.String())
	}
}
