// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package cmdb

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func netBoxCapacitySource(t *testing.T, mode *atomic.Int64, calls *atomic.Int64, padding int) *httptest.Server {
	t.Helper()
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if mode.Load() == 2 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		q := r.URL.Query()
		source, err := strconv.Atoi(q.Get("tenant_id"))
		if err != nil || (source != 7 && source != 8) || q.Get("limit") != "100" || q.Get("ordering") != "id" || r.Method != http.MethodGet || r.Header.Get("Authorization") != "Token test-token" {
			t.Error("capacity source received widened endpoint/tenant/credential query")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		offset, err := strconv.Atoi(q.Get("offset"))
		if err != nil || offset < 0 || offset > 17 {
			t.Error("invalid locally reconstructed source offset")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		count := 13
		ip := r.URL.Path == "/api/ipam/ip-addresses/"
		if ip {
			count = 17
			if q.Get("address") != "10.0.0.1" {
				t.Error("IP source filter changed")
			}
		} else if (r.URL.Path != "/api/dcim/devices/" && r.URL.Path != "/api/virtualization/virtual-machines/") || q.Get("name") != "shared.example" {
			t.Error("hostname source endpoint/filter changed")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		rows := []map[string]any{}
		end := min(offset+7, count) // A legitimate smaller server page size.
		for i := offset; i < end; i++ {
			owner, id := source, i+1
			if offset > 0 && mode.Load() == 1 && source == 7 {
				owner = 8
			}
			if offset > 0 && mode.Load() == 3 {
				id = 1
			}
			name := fmt.Sprintf("owned-%d-%d", owner, id)
			row := map[string]any{"id": id, "tenant": map[string]int{"id": owner}, "name": "shared.example", "display": name}
			if ip {
				row["address"], row["dns_name"] = "10.0.0.1/32", name
			}
			rows = append(rows, row)
		}
		next := ""
		if end < count {
			q.Set("offset", strconv.Itoa(end))
			q.Set("limit", "7")
			next = server.URL + r.URL.Path + "?" + q.Encode()
			if mode.Load() == 5 {
				next = "https://foreign.invalid" + r.URL.Path + "?" + q.Encode()
			}
		}
		if offset > 0 && mode.Load() == 4 {
			count++
		}
		response := map[string]any{"count": count, "next": next, "results": rows}
		if padding > 0 {
			response["custom_source_data"] = strings.Repeat("x", padding)
		}
		if mode.Load() == 6 {
			response["custom_source_data"] = strings.Repeat("x", 5<<20)
		}
		// Budget countercases deliberately close a larger source body early.
		_ = json.NewEncoder(w).Encode(response)
	}))
	t.Cleanup(server.Close)
	return server
}

func TestNetBoxCompleteLookupPagesKeepAllMatchesAndTenantBinding(t *testing.T) {
	var mode, calls atomic.Int64
	source := netBoxCapacitySource(t, &mode, &calls, 0)
	provider := NewNetBox(source.URL, "test-token", map[string]string{netBoxTenantA: "7", netBoxTenantB: "8"})
	provider.client.Transport = source.Client().Transport
	for lane, tenant := range []string{netBoxTenantA, netBoxTenantB} {
		for _, key := range []string{"10.0.0.1", "shared.example"} {
			cis, err := provider.Lookup(netBoxContext(tenant), key)
			want := 26 // Thirteen owned devices and thirteen owned VMs.
			if key == "10.0.0.1" {
				want = 17
			}
			if err != nil || len(cis) != want {
				t.Fatalf("complete plural lookup above ten refused: key=%s count=%d want=%d err=%v", key, len(cis), want, err)
			}
			seen := map[string]bool{}
			for _, ci := range cis {
				if !strings.HasPrefix(ci.Name, fmt.Sprintf("owned-%d-", lane+7)) || seen[ci.SysID] {
					t.Fatal("complete lookup changed tenant or repeated an object")
				}
				seen[ci.SysID] = true
			}
			last := "netbox:virtualization.virtual_machine:13"
			if key == "10.0.0.1" {
				last = "netbox:ipam.ip_address:17"
			}
			if cis[len(cis)-1].SysID != last {
				t.Fatal("last complete source match omitted")
			}
		}
	}
	resolver := NewResolver(provider, time.Nanosecond)
	if cis, err := resolver.Lookup(netBoxContext(netBoxTenantA), "10.0.0.1"); err != nil || len(cis) != 17 {
		t.Fatal("complete cache seed failed", err)
	}
	mode.Store(1)
	if cis, err := resolver.Lookup(netBoxContext(netBoxTenantA), "10.0.0.1"); !errors.Is(err, ErrTenantBinding) || cis != nil {
		t.Fatal("foreign late page published an earlier partial or stale result", err)
	}
	if cis, err := resolver.Lookup(netBoxContext(netBoxTenantB), "10.0.0.1"); err != nil || len(cis) != 17 {
		t.Fatal("sibling lookup affected by foreign-page refusal", err)
	}
	mode.Store(2)
	if cis, err := resolver.Lookup(netBoxContext(netBoxTenantA), "10.0.0.1"); err == nil || cis != nil {
		t.Fatal("revoked complete cache reappeared during outage", err)
	}
	for _, fault := range []int64{3, 4, 5} {
		mode.Store(fault)
		if cis, err := provider.Lookup(netBoxContext(netBoxTenantA), "10.0.0.1"); !errors.Is(err, ErrTenantBinding) || cis != nil {
			t.Fatalf("untrusted pagination fault%d published output: %v", fault, err)
		}
	}
	mode.Store(0)
	if cis, err := resolver.Lookup(netBoxContext(netBoxTenantA), "10.0.0.1"); err != nil || len(cis) != 17 {
		t.Fatal("complete cache reseed failed", err)
	}
	mode.Store(6)
	if cis, err := resolver.Lookup(netBoxContext(netBoxTenantA), "10.0.0.1"); !errors.Is(err, ErrLookupBudget) || cis != nil {
		t.Fatal("operation admission substituted stale or partial matches", err)
	}
	mode.Store(2)
	if cis, err := resolver.Lookup(netBoxContext(netBoxTenantA), "10.0.0.1"); err == nil || cis != nil {
		t.Fatal("capacity-refused cache reappeared during outage", err)
	}
}

type netBoxCapacityRoundTrip func(*http.Request) (*http.Response, error)

func (f netBoxCapacityRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestNetBoxCompleteLookupProfilesAreCumulativeAndRaiseable(t *testing.T) {
	var mode, calls atomic.Int64
	source := netBoxCapacitySource(t, &mode, &calls, 5<<20)
	policy := DefaultLookupPolicy()
	policy.Timeout, policy.ResponseBytes, policy.MemoryBytes = 25*time.Hour, 32<<20, 2<<30
	provider := NewNetBox(source.URL, "test-token", map[string]string{netBoxTenantA: "7"}, policy)
	if provider.client.Timeout != 25*time.Hour {
		t.Fatal("operator timeout replaced by fixed client deadline")
	}
	transport := source.Client().Transport
	provider.client.Transport = netBoxCapacityRoundTrip(func(r *http.Request) (*http.Response, error) {
		deadline, ok := r.Context().Deadline()
		if !ok || time.Until(deadline) < 24*time.Hour || time.Until(deadline) > 25*time.Hour {
			t.Error("operator whole-lookup deadline was not carried to source request")
		}
		return transport.RoundTrip(r)
	})
	cis, err := provider.Lookup(netBoxContext(netBoxTenantA), "10.0.0.1")
	if err != nil || len(cis) != 17 {
		t.Fatal("larger complete source response profile refused", len(cis), err)
	}
	for _, change := range []func(*LookupPolicy){
		func(p *LookupPolicy) { p.ResponseBytes = 6 << 20 }, // Each page fits; the entire operation does not.
		func(p *LookupPolicy) { p.MemoryBytes = 64 << 20 },
	} {
		limited := policy
		change(&limited)
		provider := NewNetBox(source.URL, "test-token", map[string]string{netBoxTenantA: "7"}, limited)
		provider.client.Transport = source.Client().Transport
		if partial, err := provider.Lookup(netBoxContext(netBoxTenantA), "10.0.0.1"); !errors.Is(err, ErrLookupBudget) || partial != nil {
			t.Fatal("cumulative admission returned partial matches", len(partial), err)
		}
	}
}

func TestNetBoxInvalidAndCancelledLookupProfilesDoNotFetch(t *testing.T) {
	var mode, calls atomic.Int64
	source := netBoxCapacitySource(t, &mode, &calls, 0)
	for _, policy := range []LookupPolicy{{}, {Timeout: time.Second, ResponseBytes: 1}, {Timeout: -time.Second, ResponseBytes: 1, MemoryBytes: 1}} {
		provider := NewNetBox(source.URL, "test-token", map[string]string{netBoxTenantA: "7"}, policy)
		provider.client.Transport = source.Client().Transport
		if cis, err := provider.Lookup(netBoxContext(netBoxTenantA), "10.0.0.1"); !errors.Is(err, ErrLookupBudget) || cis != nil {
			t.Fatal("invalid resource policy admitted source work", err)
		}
	}
	provider := NewNetBox(source.URL, "test-token", map[string]string{netBoxTenantA: "7"})
	provider.client.Transport = source.Client().Transport
	ctx, cancel := context.WithCancel(netBoxContext(netBoxTenantA))
	cancel()
	if cis, err := provider.Lookup(ctx, "10.0.0.1"); !errors.Is(err, context.Canceled) || cis != nil {
		t.Fatal("cancelled lookup returned output", err)
	}
	if calls.Load() != 0 {
		t.Fatal("invalid/cancelled lookup reached the source")
	}
}
