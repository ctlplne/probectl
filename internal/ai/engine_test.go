// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package ai

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/ctlplne/probectl/internal/auth"
)

// recordingSource implements all four source interfaces, recording the tenant it
// was asked for and returning that tenant's rows.
type recordingSource struct {
	mu      sync.Mutex
	tenants []string
	rows    map[string][]Row
}

func newRecordingSource(rows map[string][]Row) *recordingSource {
	return &recordingSource{rows: rows}
}

func (s *recordingSource) record(t string) {
	s.mu.Lock()
	s.tenants = append(s.tenants, t)
	s.mu.Unlock()
}

func (s *recordingSource) seen() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.tenants...)
}

func (s *recordingSource) QueryMetrics(_ context.Context, tenant string, _ map[string]string, _ TimeRange, _ int) ([]Row, error) {
	s.record(tenant)
	return s.rows[tenant], nil
}
func (s *recordingSource) QueryEvents(_ context.Context, tenant string, _ map[string]string, _ TimeRange, _ int) ([]Row, error) {
	s.record(tenant)
	return s.rows[tenant], nil
}
func (s *recordingSource) QueryEntities(_ context.Context, tenant string, _ map[string]string, _ int) ([]Row, error) {
	s.record(tenant)
	return s.rows[tenant], nil
}
func (s *recordingSource) QueryTopology(_ context.Context, tenant string, _ Query) ([]Row, error) {
	s.record(tenant)
	return s.rows[tenant], nil
}

func principal(tenant string, perms ...string) *auth.Principal {
	m := map[string]bool{}
	for _, p := range perms {
		m[p] = true
	}
	return &auth.Principal{TenantID: tenant, Permissions: m}
}

func TestQueryUsesPrincipalTenantNotQuery(t *testing.T) {
	src := newRecordingSource(map[string][]Row{"tenant-a": {{"k": "v"}}})
	e := NewEngine(WithMetrics(src))
	res, err := e.Query(context.Background(), principal("tenant-a", PermMetricsRead), Query{Domain: DomainMetrics})
	if err != nil {
		t.Fatal(err)
	}
	if res.Tenant != "tenant-a" || len(res.Rows) != 1 {
		t.Errorf("result = %+v", res)
	}
	for _, tn := range src.seen() {
		if tn != "tenant-a" {
			t.Errorf("source queried for tenant %q, want only the principal's (tenant-a)", tn)
		}
	}
}

func TestQueryRBACDeniesFailClosed(t *testing.T) {
	src := newRecordingSource(map[string][]Row{"tenant-a": {{"k": "v"}}})
	e := NewEngine(WithMetrics(src))
	if _, err := e.Query(context.Background(), principal("tenant-a"), Query{Domain: DomainMetrics}); !errors.Is(err, ErrForbidden) {
		t.Errorf("err = %v, want ErrForbidden", err)
	}
	if len(src.seen()) != 0 {
		t.Error("a denied query must not reach the source")
	}
}

func TestQuerySecondaryPermissionABAC(t *testing.T) {
	src := newRecordingSource(map[string][]Row{"tenant-a": {{"metric": "secret"}}})
	policyErr := errors.New("policy store unavailable")
	tests := []struct {
		name      string
		authorize PermissionAuthorizer
		wantErr   error
	}{
		{
			name: "deny overrides RBAC",
			authorize: func(_ context.Context, p *auth.Principal, permission string) (bool, error) {
				if p.TenantID != "tenant-a" || permission != PermMetricsRead {
					t.Fatalf("authorization scope = %q/%q", p.TenantID, permission)
				}
				return false, nil
			},
			wantErr: ErrForbidden,
		},
		{
			name: "policy failure fails closed",
			authorize: func(context.Context, *auth.Principal, string) (bool, error) {
				return false, policyErr
			},
			wantErr: policyErr,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			before := len(src.seen())
			engine := NewEngine(WithMetrics(src), WithPermissionAuthorizer(tt.authorize))
			_, err := engine.Query(context.Background(),
				principal("tenant-a", PermMetricsRead), Query{Domain: DomainMetrics})
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("secondary permission error = %v, want %v", err, tt.wantErr)
			}
			if got := len(src.seen()); got != before {
				t.Fatalf("ABAC-refused query reached the metrics source: before=%d after=%d", before, got)
			}
		})
	}
}

func TestCorrelateSecondaryPermissionABAC(t *testing.T) {
	metrics := newRecordingSource(map[string][]Row{"tenant-a": {{"metric": "secret"}}})
	topology := newRecordingSource(map[string][]Row{"tenant-a": {{"node": "allowed"}}})
	engine := NewEngine(
		WithMetrics(metrics),
		WithTopology(topology),
		WithPermissionAuthorizer(func(_ context.Context, _ *auth.Principal, permission string) (bool, error) {
			return permission != PermMetricsRead, nil
		}),
	)
	result, err := engine.Correlate(context.Background(),
		principal("tenant-a", PermMetricsRead, PermTopologyRead), nil, TimeRange{})
	if err != nil {
		t.Fatal(err)
	}
	if len(metrics.seen()) != 0 {
		t.Fatal("ABAC-denied metrics source was queried during correlation")
	}
	if len(topology.seen()) != 1 || len(result.Domains) != 1 || result.Domains[0] != DomainTopology {
		t.Fatalf("correlation provenance = %+v; topology reads=%v", result.Domains, topology.seen())
	}
}

func TestSecondaryPermissionABACTenantIsolation(t *testing.T) {
	src := newRecordingSource(map[string][]Row{
		"tenant-a": {{"metric": "tenant-a-secret"}},
		"tenant-b": {{"metric": "tenant-b-visible"}},
	})
	engine := NewEngine(
		WithMetrics(src),
		WithPermissionAuthorizer(func(_ context.Context, p *auth.Principal, _ string) (bool, error) {
			return p.TenantID != "tenant-a", nil
		}),
	)
	if _, err := engine.Query(context.Background(),
		principal("tenant-a", PermMetricsRead), Query{Domain: DomainMetrics}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("tenant A policy decision = %v, want forbidden", err)
	}
	result, err := engine.Query(context.Background(),
		principal("tenant-b", PermMetricsRead), Query{Domain: DomainMetrics})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Rows) != 1 || result.Rows[0]["metric"] != "tenant-b-visible" {
		t.Fatalf("tenant B result = %+v", result.Rows)
	}
	if seen := src.seen(); len(seen) != 1 || seen[0] != "tenant-b" {
		t.Fatalf("source tenant dispatch = %v, want tenant B only", seen)
	}
}

func TestQueryNoTenantFailsClosed(t *testing.T) {
	src := newRecordingSource(map[string][]Row{"tenant-a": {{"k": "v"}}})
	e := NewEngine(WithMetrics(src))
	if _, err := e.Query(context.Background(), nil, Query{Domain: DomainMetrics}); !errors.Is(err, ErrNoTenant) {
		t.Errorf("nil principal: err = %v, want ErrNoTenant", err)
	}
	noTenant := &auth.Principal{Permissions: map[string]bool{PermMetricsRead: true}}
	if _, err := e.Query(context.Background(), noTenant, Query{Domain: DomainMetrics}); !errors.Is(err, ErrNoTenant) {
		t.Errorf("empty tenant: err = %v, want ErrNoTenant", err)
	}
	if len(src.seen()) != 0 {
		t.Errorf("tenantless query must fail before source dispatch, got tenants %v", src.seen())
	}
}

func TestQueryCostGuardTruncates(t *testing.T) {
	rows := []Row{{"i": 0}, {"i": 1}, {"i": 2}, {"i": 3}, {"i": 4}}
	src := newRecordingSource(map[string][]Row{"t": rows})
	e := NewEngine(WithMetrics(src), WithMaxRows(2))
	res, err := e.Query(context.Background(), principal("t", PermMetricsRead), Query{Domain: DomainMetrics, Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Rows) != 2 || !res.Truncated {
		t.Errorf("cost guard: rows=%d truncated=%v, want 2 / true", len(res.Rows), res.Truncated)
	}
}

func TestQueryNoSourceAndUnknownDomain(t *testing.T) {
	e := NewEngine() // no sources
	if _, err := e.Query(context.Background(), principal("t", PermMetricsRead), Query{Domain: DomainMetrics}); !errors.Is(err, ErrNoSource) {
		t.Errorf("err = %v, want ErrNoSource", err)
	}
	if _, err := e.Query(context.Background(), principal("t"), Query{Domain: "bogus"}); !errors.Is(err, ErrUnknownDomain) {
		t.Errorf("unknown domain: err = %v, want ErrUnknownDomain", err)
	}
}
