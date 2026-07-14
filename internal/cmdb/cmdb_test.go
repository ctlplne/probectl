// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

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

func TestNetBoxLookupIPDeviceAndVM(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Token nb-token" {
			http.Error(w, "no token", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		base := "http://" + r.Host
		switch r.URL.Path {
		case "/api/ipam/ip-addresses/":
			if r.URL.Query().Get("q") != "10.0.0.1" {
				t.Errorf("ip query = %q", r.URL.RawQuery)
			}
			fmt.Fprint(w, `{"results":[{"id":101,"display":"10.0.0.1/32","address":"10.0.0.1/32","dns_name":"core-sw1.acme.example","url":"`+base+`/api/ipam/ip-addresses/101/","assigned_object":{"device":{"name":"core-sw1","display":"core-sw1"}}}]}`)
		case "/api/dcim/devices/":
			if r.URL.Query().Get("name") != "core-sw1.acme.example" {
				t.Errorf("device query = %q", r.URL.RawQuery)
			}
			fmt.Fprint(w, `{"results":[{"id":202,"name":"core-sw1.acme.example","display":"core-sw1","url":"`+base+`/api/dcim/devices/202/","role":{"name":"leaf"},"site":{"name":"iad1"},"device_type":{"model":"7050X"},"primary_ip4":{"address":"10.0.0.1/32"}}]}`)
		case "/api/virtualization/virtual-machines/":
			if r.URL.Query().Get("name") != "core-sw1.acme.example" {
				t.Errorf("vm query = %q", r.URL.RawQuery)
			}
			fmt.Fprint(w, `{"results":[{"id":303,"name":"core-sw1.acme.example","display":"core-sw1-vm","url":"`+base+`/api/virtualization/virtual-machines/303/","cluster":{"name":"lab"},"primary_ip4":{"address":"10.0.0.10/32"}}]}`)
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	provider := NewNetBox(ts.URL, "nb-token")
	cis, err := provider.Lookup(context.Background(), "10.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if len(cis) != 1 || cis[0].SysID != "netbox:ipam.ip_address:101" || cis[0].IPAddress != "10.0.0.1" {
		t.Fatalf("ip cis = %+v", cis)
	}
	if !strings.Contains(cis[0].URL, "/ipam/ip-addresses/101/") {
		t.Fatalf("netbox UI URL not normalized: %+v", cis[0])
	}

	cis, err = provider.Lookup(context.Background(), "CORE-SW1.ACME.EXAMPLE")
	if err != nil {
		t.Fatal(err)
	}
	if len(cis) != 2 {
		t.Fatalf("hostname cis = %+v, want device + vm", cis)
	}
	if cis[0].Class != "netbox.device" || cis[0].Extra["site"] != "iad1" || cis[0].Extra["model"] != "7050X" {
		t.Fatalf("device CI = %+v", cis[0])
	}
	if cis[1].Class != "netbox.virtual_machine" || cis[1].Extra["cluster"] != "lab" {
		t.Fatalf("vm CI = %+v", cis[1])
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
