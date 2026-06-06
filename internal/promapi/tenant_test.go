package promapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// U-025: ForceTenant strips EVERY caller-supplied tenant matcher (equality,
// regex, negative) and pins exactly one tenant_id="<caller>".
func TestForceTenantStripsCallerMatchers(t *testing.T) {
	for _, expr := range []string{
		`up{tenant_id="other"}`,
		`up{tenant_id=~".+"}`,
		`up{tenant_id!="mine"}`,
		`up{tenant_id="a",tenant_id=~"b.*"}`,
		`up`,
	} {
		sel, err := ParseSelector(expr)
		if err != nil {
			t.Fatalf("parse %q: %v", expr, err)
		}
		forced := ForceTenant(sel, "mine")
		tenant, ok := forced.TenantScoped()
		if !ok || tenant != "mine" {
			t.Fatalf("%q forced to (%q,%v), want pinned to mine", expr, tenant, ok)
		}
		if !strings.Contains(forced.String(), `tenant_id="mine"`) {
			t.Fatalf("%q reconstruction lost the pin: %s", expr, forced.String())
		}
	}
}

// TenantScoped accepts only the ForceTenant shape.
func TestTenantScopedShape(t *testing.T) {
	bad := []Selector{
		{Metric: "up"}, // no pin
		{Metric: "up", Matchers: []Matcher{{Name: TenantLabel, Op: "=~", Value: ".*"}}},
		{Metric: "up", Matchers: []Matcher{{Name: TenantLabel, Op: "!=", Value: "x"}}},
		{Metric: "up", Matchers: []Matcher{{Name: TenantLabel, Op: "=", Value: ""}}},
		{Metric: "up", Matchers: []Matcher{
			{Name: TenantLabel, Op: "=", Value: "a"}, {Name: TenantLabel, Op: "=", Value: "b"}}},
	}
	for i, sel := range bad {
		if _, ok := sel.TenantScoped(); ok {
			t.Fatalf("case %d: unscoped selector accepted", i)
		}
	}
	if tenant, ok := ForceTenant(Selector{Metric: "up"}, "t9").TenantScoped(); !ok || tenant != "t9" {
		t.Fatal("the ForceTenant shape must be accepted")
	}
}

// The upstream boundary itself refuses unscoped forwards — a caller that
// forgets ForceTenant gets an error before anything reaches the wire.
func TestUpstreamRefusesUnscopedForwards(t *testing.T) {
	dialed := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		dialed = true
		_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"vector","result":[]}}`))
	}))
	defer srv.Close()
	u := NewUpstream(srv.URL)
	ctx := context.Background()
	unscoped := Selector{Metric: "up"}

	if _, err := u.QueryInstant(ctx, unscoped, time.Now()); !errors.Is(err, ErrUnscopedUpstreamQuery) {
		t.Fatalf("QueryInstant unscoped: %v", err)
	}
	if _, err := u.QueryRange(ctx, unscoped, time.Now().Add(-time.Hour), time.Now(), "15s"); !errors.Is(err, ErrUnscopedUpstreamQuery) {
		t.Fatalf("QueryRange unscoped: %v", err)
	}
	if _, err := u.Series(ctx, []Selector{ForceTenant(unscoped, "t1"), unscoped}, time.Now().Add(-time.Hour), time.Now()); !errors.Is(err, ErrUnscopedUpstreamQuery) {
		t.Fatalf("Series with one unscoped member: %v", err)
	}
	if _, err := u.LabelNames(ctx, []Selector{unscoped}, time.Now().Add(-time.Hour), time.Now()); !errors.Is(err, ErrUnscopedUpstreamQuery) {
		t.Fatalf("LabelNames unscoped: %v", err)
	}
	if _, err := u.LabelValues(ctx, "job", []Selector{unscoped}, time.Now().Add(-time.Hour), time.Now()); !errors.Is(err, ErrUnscopedUpstreamQuery) {
		t.Fatalf("LabelValues unscoped: %v", err)
	}
	if dialed {
		t.Fatal("an unscoped query reached the upstream")
	}

	// A forced selector passes and the wire query carries the pin.
	var wireQuery string
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wireQuery = r.URL.Query().Get("query")
		_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"vector","result":[]}}`))
	}))
	defer srv2.Close()
	u2 := NewUpstream(srv2.URL)
	if _, err := u2.QueryInstant(ctx, ForceTenant(unscoped, "t1"), time.Now()); err != nil {
		t.Fatalf("scoped forward: %v", err)
	}
	if !strings.Contains(wireQuery, `tenant_id="t1"`) {
		t.Fatalf("wire query lost the tenant pin: %q", wireQuery)
	}
}
