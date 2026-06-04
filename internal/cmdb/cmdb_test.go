package cmdb

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestCanonicalKey(t *testing.T) {
	cases := map[string]string{
		"10.0.0.1":                "10.0.0.1",
		" Core-SW1.ACME.example ": "core-sw1.acme.example",
		"https://web.example/x":   "web.example",
		"db.example:5432":         "db.example",
		"[2001:db8::1]:443":       "2001:db8::1",
		"2001:db8::1":             "2001:db8::1",
		"10.0.0.0/24":             "", // prefixes are not CI keys
		"not a host!":             "",
		"":                        "",
		"-bad.example":            "",
	}
	for in, want := range cases {
		if got := CanonicalKey(in); got != want {
			t.Errorf("CanonicalKey(%q) = %q, want %q", in, got, want)
		}
	}
}

// mockSNow serves the ServiceNow Table API shape for two known CIs.
func mockSNow(t *testing.T, calls *atomic.Int64, fail *atomic.Bool) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if fail.Load() {
			http.Error(w, "down", http.StatusBadGateway)
			return
		}
		if !strings.HasPrefix(r.URL.Path, "/api/now/table/cmdb_ci") {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		if r.Header.Get("Authorization") == "" {
			http.Error(w, "no auth", http.StatusUnauthorized)
			return
		}
		q := r.URL.Query().Get("sysparm_query")
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.Contains(q, "10.0.0.1"):
			fmt.Fprint(w, `{"result":[{"sys_id":"abc123","name":"core-sw1","sys_class_name":"cmdb_ci_ip_switch","ip_address":"10.0.0.1","fqdn":"core-sw1.acme.example"}]}`)
		case strings.Contains(q, "web.acme.example"):
			fmt.Fprint(w, `{"result":[{"sys_id":"def456","name":"web01","sys_class_name":"cmdb_ci_server","ip_address":"10.0.0.7","fqdn":"web.acme.example"}]}`)
		default:
			fmt.Fprint(w, `{"result":[]}`)
		}
	}))
}

func TestServiceNowLookupAndCorrelate(t *testing.T) {
	var calls atomic.Int64
	var fail atomic.Bool
	ts := mockSNow(t, &calls, &fail)
	defer ts.Close()

	r := NewResolver(NewServiceNow(ts.URL, "", "user:pass"), time.Minute)
	ctx := context.Background()

	cis, err := r.Lookup(ctx, "10.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if len(cis) != 1 || cis[0].SysID != "abc123" || cis[0].Class != "cmdb_ci_ip_switch" {
		t.Fatalf("cis = %+v", cis)
	}
	if !strings.Contains(cis[0].URL, "sys_id%3Dabc123") {
		t.Errorf("deep link = %q", cis[0].URL)
	}

	// THE correlation contract: incident-ish keys -> CIs (dedup + canonicalize +
	// skip unknowns/prefixes).
	matches := r.Correlate(ctx, []string{
		"10.0.0.1", "10.0.0.1", "WEB.ACME.EXAMPLE", "203.0.113.99", "10.0.0.0/24", "",
	})
	if len(matches) != 2 {
		t.Fatalf("matches = %+v, want 2", matches)
	}
	if matches[0].Key != "10.0.0.1" || matches[1].Key != "web.acme.example" {
		t.Fatalf("keys = %+v", matches)
	}
	if matches[1].CIs[0].Name != "web01" {
		t.Fatalf("web CI = %+v", matches[1].CIs[0])
	}
}

func TestResolverCacheAndGracefulDegrade(t *testing.T) {
	var calls atomic.Int64
	var fail atomic.Bool
	ts := mockSNow(t, &calls, &fail)
	defer ts.Close()

	r := NewResolver(NewServiceNow(ts.URL, "", "user:pass"), 50*time.Millisecond)
	ctx := context.Background()

	if _, err := r.Lookup(ctx, "10.0.0.1"); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Lookup(ctx, "10.0.0.1"); err != nil { // cache hit
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Fatalf("calls = %d, want 1 (cached)", calls.Load())
	}

	// TTL expiry + provider down -> stale entry is served, never an error.
	time.Sleep(60 * time.Millisecond)
	fail.Store(true)
	cis, err := r.Lookup(ctx, "10.0.0.1")
	if err != nil || len(cis) != 1 {
		t.Fatalf("stale-serve failed: cis=%v err=%v", cis, err)
	}

	// Uncached key while down -> ErrUnavailable (fail closed, not fabricated).
	if _, err := r.Lookup(ctx, "web.acme.example"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("err = %v, want ErrUnavailable", err)
	}

	// Correlate degrades to "no match" rather than erroring.
	if m := r.Correlate(ctx, []string{"web.acme.example"}); len(m) != 0 {
		t.Fatalf("correlate while down = %+v", m)
	}
}

func TestResolverNegativeCache(t *testing.T) {
	var calls atomic.Int64
	var fail atomic.Bool
	ts := mockSNow(t, &calls, &fail)
	defer ts.Close()

	r := NewResolver(NewServiceNow(ts.URL, "", "user:pass"), time.Minute)
	for i := 0; i < 3; i++ {
		if cis, err := r.Lookup(context.Background(), "203.0.113.99"); err != nil || len(cis) != 0 {
			t.Fatalf("lookup: cis=%v err=%v", cis, err)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("calls = %d, want 1 (negative result cached)", calls.Load())
	}
}
