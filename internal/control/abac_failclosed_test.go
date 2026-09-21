// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/ai"
	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/config"
	"github.com/ctlplne/probectl/internal/store/pathstore"
)

func TestABACColdLoadFailureFailsClosed(t *testing.T) {
	s := &Server{abac: newClosedABACCache(t)}
	ran := false
	protected := s.requirePermission("test.read", func(http.ResponseWriter, *http.Request) error {
		ran = true
		return nil
	})
	req := httptest.NewRequest(http.MethodGet, "/v1/tests", nil)
	req = req.WithContext(auth.WithPrincipal(req.Context(), &auth.Principal{
		TenantID:    "t-acme",
		Permissions: map[string]bool{"test.read": true},
	}))

	err := protected(httptest.NewRecorder(), req)
	domainErr, ok := apierror.As(err)
	if !ok || domainErr.Kind != apierror.KindUnavailable {
		t.Fatalf("cold ABAC load failure = %v, want unavailable", err)
	}
	if ran {
		t.Fatal("protected handler ran without a safely loaded ABAC policy set")
	}
}

func TestABACExpiredCacheRefreshFailureFailsClosed(t *testing.T) {
	tests := []struct {
		name     string
		tenantID string
		policies []auth.Policy
	}{
		{
			name:     "tenant A empty policy set",
			tenantID: "t-acme-a",
		},
		{
			name:     "tenant B stale allow",
			tenantID: "t-acme-b",
			policies: []auth.Policy{{
				ID:         "allow-read",
				Effect:     auth.PolicyAllow,
				Permission: "test.read",
				Enabled:    true,
			}},
		},
		{
			name:     "tenant C stale deny",
			tenantID: "t-acme-c",
			policies: []auth.Policy{{
				ID:         "deny-read",
				Effect:     auth.PolicyDeny,
				Permission: "test.read",
				Enabled:    true,
			}},
		},
	}

	cache := newClosedABACCache(t)
	for _, tt := range tests {
		cache.data[tt.tenantID] = abacEntry{
			expiry:   time.Now().Add(-time.Minute),
			policies: tt.policies,
		}
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Server{abac: cache}
			ran := false
			protected := s.requirePermission("test.read", func(http.ResponseWriter, *http.Request) error {
				ran = true
				return nil
			})
			req := httptest.NewRequest(http.MethodGet, "/v1/tests", nil)
			req = req.WithContext(auth.WithPrincipal(req.Context(), &auth.Principal{
				TenantID:    tt.tenantID,
				Permissions: map[string]bool{"test.read": true},
			}))

			err := protected(httptest.NewRecorder(), req)
			domainErr, ok := apierror.As(err)
			if !ok || domainErr.Kind != apierror.KindUnavailable {
				t.Fatalf("expired ABAC refresh failure = %v, want unavailable", err)
			}
			if ran {
				t.Fatal("protected handler ran with an expired ABAC policy set")
			}
		})
	}
}

func TestABACUnexpiredPolicyStillDeniesWithinTTL(t *testing.T) {
	cache := newClosedABACCache(t)
	cache.data["t-acme"] = abacEntry{
		expiry: time.Now().Add(time.Minute),
		policies: []auth.Policy{{
			ID:         "deny-read",
			Effect:     auth.PolicyDeny,
			Permission: "test.read",
			Enabled:    true,
		}},
	}
	s := &Server{abac: cache}
	ran := false
	protected := s.requirePermission("test.read", func(http.ResponseWriter, *http.Request) error {
		ran = true
		return nil
	})
	req := httptest.NewRequest(http.MethodGet, "/v1/tests", nil)
	req = req.WithContext(auth.WithPrincipal(req.Context(), &auth.Principal{
		TenantID:    "t-acme",
		Permissions: map[string]bool{"test.read": true},
	}))

	err := protected(httptest.NewRecorder(), req)
	domainErr, ok := apierror.As(err)
	if !ok || domainErr.Kind != apierror.KindForbidden {
		t.Fatalf("unexpired deny policy decision = %v, want forbidden", err)
	}
	if ran {
		t.Fatal("protected handler ran despite an unexpired deny policy")
	}
}

func TestABACInvalidationPreventsStalePolicyPublication(t *testing.T) {
	const tenantID = "tenant-race"

	oldLoadStarted := make(chan struct{})
	releaseOldLoad := make(chan struct{})
	var loadCalls atomic.Int32
	deny := []auth.Policy{{
		ID:         "deny-test-read",
		Name:       "deny test reads",
		Effect:     auth.PolicyDeny,
		Permission: "test.read",
		Enabled:    true,
	}}
	cache := &abacCache{
		ttl:  time.Hour,
		data: map[string]abacEntry{},
		load: func(context.Context, string) ([]auth.Policy, error) {
			if loadCalls.Add(1) == 1 {
				// This result represents a pre-commit snapshot with no deny.
				close(oldLoadStarted)
				<-releaseOldLoad
				return nil, nil
			}
			// Every post-invalidation read sees the committed deny.
			return deny, nil
		},
	}
	server := &Server{abac: cache}
	principal := &auth.Principal{
		TenantID:    tenantID,
		Permissions: map[string]bool{"test.read": true},
	}
	request := httptest.NewRequest(http.MethodGet, "/v1/tests", nil)
	request = request.WithContext(auth.WithPrincipal(request.Context(), principal))
	var handlerCalls atomic.Int32
	protected := server.requirePermission("test.read", func(http.ResponseWriter, *http.Request) error {
		handlerCalls.Add(1)
		return nil
	})
	httpResult := make(chan error, 1)
	go func() {
		httpResult <- protected(httptest.NewRecorder(), request)
	}()

	<-oldLoadStarted
	// Model the required order: the policy mutation commits, then invalidation
	// completes, before the older load gets a chance to publish its snapshot.
	cache.invalidate(tenantID)
	close(releaseOldLoad)

	err := <-httpResult
	domainErr, ok := apierror.As(err)
	if !ok || (domainErr.Kind != apierror.KindForbidden && domainErr.Kind != apierror.KindUnavailable) {
		t.Errorf("in-flight HTTP authorization after invalidation = %v, want forbidden or unavailable", err)
	}
	if got := handlerCalls.Load(); got != 0 {
		t.Errorf("protected HTTP handler ran %d time(s) using a pre-invalidation allow", got)
	}

	// The colocated MCP server consumes this exact cache loader. Its subsequent
	// read must observe the deny too, never a stale entry published by HTTP.
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	egress := ai.NewEgressGate(func(context.Context, string) (bool, error) {
		return true, nil
	}, nil, ai.RedactionPolicy{})
	mcpServer := NewMCPServerWithPolicyLoader(
		&config.Config{AIMaxEvidence: 10},
		log,
		nil,
		pathstore.NewMemory(),
		120,
		egress,
		nil,
		nil,
		server.MCPPolicyLoader(),
	)
	raw := mcpServer.Handle(
		context.Background(),
		principal,
		[]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`),
	)
	var response struct {
		Result struct {
			Tools []struct {
				Name string `json:"name"`
			} `json:"tools"`
		} `json:"result"`
		Error any `json:"error"`
	}
	if err := json.Unmarshal(raw, &response); err != nil {
		t.Fatalf("decode MCP tools/list response: %v", err)
	}
	if response.Error != nil {
		t.Fatalf("MCP policy read after completed invalidation = %v, want committed deny", response.Error)
	}
	for _, tool := range response.Result.Tools {
		if tool.Name == "list_tests" {
			t.Error("MCP advertised list_tests using a stale pre-invalidation allow")
		}
	}
}

func TestABACRepeatedInvalidationDuringRefreshFailsClosed(t *testing.T) {
	const tenantID = "tenant-policy-churn"

	loadStarted := make(chan chan struct{}, abacLoadAttempts)
	cache := &abacCache{
		ttl:  time.Hour,
		data: map[string]abacEntry{},
		load: func(context.Context, string) ([]auth.Policy, error) {
			release := make(chan struct{})
			loadStarted <- release
			<-release
			return nil, nil
		},
	}
	result := make(chan error, 1)
	go func() {
		_, err := cache.policies(context.Background(), tenantID)
		result <- err
	}()

	for range abacLoadAttempts {
		release := <-loadStarted
		cache.invalidate(tenantID)
		close(release)
	}

	if err := <-result; !errors.Is(err, errABACInvalidatedDuringLoad) {
		t.Fatalf("policy churn error = %v, want fail-closed invalidation error", err)
	}
	cache.mu.Lock()
	_, cached := cache.data[tenantID]
	cache.mu.Unlock()
	if cached {
		t.Fatal("a repeatedly invalidated policy snapshot became authoritative")
	}
}

func TestABACInvalidationGenerationIsTenantScoped(t *testing.T) {
	const (
		changedTenant = "tenant-policy-change"
		loadingTenant = "tenant-independent-load"
	)

	loadStarted := make(chan struct{})
	releaseLoad := make(chan struct{})
	var loadCalls atomic.Int32
	want := []auth.Policy{{
		ID:         "independent-tenant-deny",
		Effect:     auth.PolicyDeny,
		Permission: "test.read",
		Enabled:    true,
	}}
	cache := &abacCache{
		ttl:  time.Hour,
		data: map[string]abacEntry{},
		load: func(_ context.Context, tenantID string) ([]auth.Policy, error) {
			if tenantID != loadingTenant {
				return nil, errors.New("loader received the wrong tenant")
			}
			if loadCalls.Add(1) == 1 {
				close(loadStarted)
				<-releaseLoad
			}
			return want, nil
		},
	}
	type policyResult struct {
		policies []auth.Policy
		err      error
	}
	result := make(chan policyResult, 1)
	go func() {
		policies, err := cache.policies(context.Background(), loadingTenant)
		result <- policyResult{policies: policies, err: err}
	}()

	<-loadStarted
	cache.invalidate(changedTenant)
	close(releaseLoad)

	got := <-result
	if got.err != nil {
		t.Fatalf("unrelated tenant load after invalidation: %v", got.err)
	}
	if len(got.policies) != 1 || got.policies[0].ID != want[0].ID {
		t.Fatalf("unrelated tenant policies = %#v, want %#v", got.policies, want)
	}
	if calls := loadCalls.Load(); calls != 1 {
		t.Fatalf("tenant %q invalidation retried tenant %q load; calls = %d, want 1",
			changedTenant, loadingTenant, calls)
	}
}

func newClosedABACCache(t *testing.T) *abacCache {
	t.Helper()
	cfg, err := pgxpool.ParseConfig("postgres://probectl@127.0.0.1:1/none?sslmode=disable&connect_timeout=1")
	if err != nil {
		t.Fatal(err)
	}
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	pool.Close()
	return newABACCache(pool)
}
