// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration && local_ollama

package control

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/ai"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/config"
	"github.com/ctlplne/probectl/internal/incident"
	"github.com/ctlplne/probectl/internal/logging"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// TestLocalOllamaKeepsTenantAndRBACBoundaries uses the deployed AI constructor,
// persisted user grants, real signed sessions and tenant-scoped PostgreSQL.
// Both tenants ask about the same target, with different incident evidence.
// The local_ollama build tag selects the lab profile with a real model fixture.
func TestLocalOllamaKeepsTenantAndRBACBoundaries(t *testing.T) {
	endpoint := os.Getenv("PROBECTL_RCA_OLLAMA_ENDPOINT")
	models := strings.Fields(os.Getenv("PROBECTL_RCA_OLLAMA_MODELS"))
	if endpoint == "" || len(models) == 0 {
		t.Fatal("local Ollama endpoint and model name are required")
	}
	modelTimeout := time.Minute
	if value := os.Getenv("PROBECTL_AI_MODEL_TIMEOUT"); value != "" {
		configured, err := time.ParseDuration(value)
		if err != nil || configured <= 0 {
			t.Fatal("PROBECTL_AI_MODEL_TIMEOUT must be a positive duration")
		}
		modelTimeout = configured
	}
	model, err := ai.NewHTTPModel(ai.HTTPModelConfig{Kind: ai.KindOllama, Endpoint: endpoint, Model: models[0]})
	if err != nil || model.RemoteEgress() {
		t.Fatal("the model endpoint must be local")
	}
	markers := [2]string{"owned-lab-alpha switch failure", "owned-lab-bravo route withdrawal"}
	proxyURL, caFile, audit := auditLocalOllamaPrompts(t, endpoint, markers)

	_, db := setupSessionAPI(t, auth.Identity{})
	cfg := &config.Config{
		AuthMode: "session", SessionTTL: time.Hour,
		AIModelProvider: "ollama", AIModelEndpoint: proxyURL, AIModelName: models[0], AIModelCAFile: caFile,
		AIModelTimeout: modelTimeout, AIMaxEvidence: 50, AIMaxConcurrent: 2,
	}
	srv := New(cfg, logging.New(io.Discard, "error", "json"), db, db.Pool(), nil, nil).
		WithTenantStatus(NewTenantStatusCache(db.Pool(), 0))
	h := srv.Handler()

	const sharedTarget = "checkout.lab"
	var tenants [2]string
	for lane, slug := range []string{"ollama-alpha", "ollama-bravo"} {
		tenants[lane] = freshTenant(t, db, slug)
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenants[lane]))
		if err := tenancy.InTenant(ctx, db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
			now := time.Now().UTC()
			_, err := (store.Incidents{}).Create(ctx, sc, incident.Incident{
				Title: markers[lane], Target: sharedTarget, Severity: incident.SeverityCritical,
				StartedAt: now, LastSeenAt: now,
			})
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	const request = `{"question":"What caused the latest incident for checkout.lab?","subject":{"target":"checkout.lab"}}`
	const route = "/v1/ai/ask"
	for lane := range tenants {
		tenant := tenants[lane]
		const owner = "ollama-owner@example.invalid"
		cookie := authz15Session(t, srv, tenant, createUserWithPerms(t, db, tenant, owner, nil,
			permTenantRead, permAIQuery, ai.PermEntitiesRead, permIncidentRead), owner)
		audit.owner.Store(int64(lane) + 1)
		before := audit.requests.Load()
		beforeResponses := audit.responses.Load()
		started := time.Now()
		rec := sessionReq(t, h, http.MethodPost, route, cookie, request)
		elapsed := time.Since(started).Round(time.Millisecond)
		var answer ai.Answer
		if audit.requests.Load() <= before || rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &answer) != nil ||
			answer.Tenant != tenant || answer.Reasoning.Execution != ai.ReasoningLocalAdapter ||
			answer.Reasoning.Adapter != model.Name() || answer.Reasoning.EgressConsent != ai.ConsentNotRequired {
			t.Fatalf("tenant %d did not receive an owned local answer in %s: API HTTP %d, model responses %d (last HTTP %d), reasoning %+v",
				lane, elapsed, rec.Code, audit.responses.Load()-beforeResponses, audit.lastStatus.Load(), answer.Reasoning)
		}
		if !strings.Contains(rec.Body.String(), markers[lane]) || strings.Contains(rec.Body.String(), markers[1-lane]) {
			t.Fatalf("tenant %d answer failed the own/sibling evidence boundary", lane)
		}
		t.Logf("tenant %d received its local answer in %s", lane, elapsed)

		audit.owner.Store(0)
		before = audit.requests.Load()
		const denied = "no-query@example.invalid"
		noQuery := authz15Session(t, srv, tenant, createUserWithPerms(t, db, tenant, denied, nil,
			permTenantRead, ai.PermEntitiesRead, permIncidentRead), denied)
		if rec := sessionReq(t, h, http.MethodPost, route, noQuery, request); rec.Code != http.StatusForbidden || audit.requests.Load() != before {
			t.Fatalf("tenant %d user without ai.query escaped model admission: HTTP %d", lane, rec.Code)
		}

		const limited = "limited-query@example.invalid"
		noEvidence := authz15Session(t, srv, tenant, createUserWithPerms(t, db, tenant, limited, nil,
			permTenantRead, permAIQuery), limited)
		rec = sessionReq(t, h, http.MethodPost, route, noEvidence, request)
		answer = ai.Answer{}
		if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &answer) != nil ||
			answer.Tenant != tenant || !answer.InsufficientEvidence || len(answer.Evidence) != 0 {
			t.Fatalf("tenant %d user without evidence grants did not receive empty scoped evidence: HTTP %d", lane, rec.Code)
		}
		for _, marker := range markers {
			if strings.Contains(rec.Body.String(), marker) {
				t.Fatalf("tenant %d user without evidence grants received an incident", lane)
			}
		}
	}
}

type localOllamaPromptAudit struct {
	owner      atomic.Int64
	requests   atomic.Uint64
	responses  atomic.Uint64
	lastStatus atomic.Int64
}

// The test sends each request through a TLS loopback observer to the real
// Ollama server. Inspect the input because an isolated-looking answer alone
// cannot establish which evidence the model was given.
func auditLocalOllamaPrompts(t *testing.T, endpoint string, markers [2]string) (string, string, *localOllamaPromptAudit) {
	t.Helper()
	target, err := url.Parse(endpoint)
	if err != nil || target.User != nil || target.Scheme != "http" || target.Port() == "" ||
		target.Path != "" || target.RawQuery != "" || target.Fragment != "" {
		t.Fatal("the lab Ollama server requires a literal loopback HTTP origin")
	}
	address, err := netip.ParseAddr(target.Hostname())
	if err != nil || !address.Unmap().IsLoopback() {
		t.Fatal("the lab Ollama server is outside loopback")
	}
	audit := new(localOllamaPromptAudit)
	transport := &http.Transport{}
	proxy := &httputil.ReverseProxy{
		Rewrite:   func(request *httputil.ProxyRequest) { request.SetURL(target) },
		Transport: transport,
		ModifyResponse: func(response *http.Response) error {
			audit.lastStatus.Store(int64(response.StatusCode))
			audit.responses.Add(1)
			return nil
		},
	}
	t.Cleanup(transport.CloseIdleConnections)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		audit.requests.Add(1)
		if r.Method != http.MethodPost || r.URL.Path != "/api/chat" {
			t.Error("unexpected local model request")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
		if err != nil {
			t.Error("could not read the bounded local model request")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		owner := audit.owner.Load()
		for lane, marker := range markers {
			if bytes.Contains(body, []byte(marker)) != (owner == int64(lane)+1) {
				t.Error("the local model prompt did not match the current tenant and evidence grants")
				w.WriteHeader(http.StatusForbidden)
				return
			}
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		proxy.ServeHTTP(w, r)
	}))
	t.Cleanup(server.Close)
	ca := filepath.Join(t.TempDir(), "ollama-prompt-observer-ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	return server.URL, ca, audit
}
