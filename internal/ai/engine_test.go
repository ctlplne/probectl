package ai

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/imfeelingtheagi/probectl/internal/auth"
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

func TestQueryNoTenantFailsClosed(t *testing.T) {
	e := NewEngine(WithMetrics(newRecordingSource(nil)))
	if _, err := e.Query(context.Background(), nil, Query{Domain: DomainMetrics}); !errors.Is(err, ErrNoTenant) {
		t.Errorf("nil principal: err = %v, want ErrNoTenant", err)
	}
	noTenant := &auth.Principal{Permissions: map[string]bool{PermMetricsRead: true}}
	if _, err := e.Query(context.Background(), noTenant, Query{Domain: DomainMetrics}); !errors.Is(err, ErrNoTenant) {
		t.Errorf("empty tenant: err = %v, want ErrNoTenant", err)
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
