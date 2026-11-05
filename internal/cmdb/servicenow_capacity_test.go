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
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Explicit authorized corpus among137 physical records. Several physical pages
// have no visible rows; no real ServiceNow account or source-ownership claim.
var serviceNowVisible = []int{1, 2, 5, 6, 8, 9, 12, 14, 17, 20, 24, 33, 41, 56, 64, 78, 90, 100, 125, 136}

func serviceNowCapacitySource(t *testing.T, mode, calls *atomic.Int64) *httptest.Server {
	t.Helper()
	visible := map[int]bool{}
	for _, index := range serviceNowVisible {
		visible[index] = true
	}
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if mode.Load() == 2 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		q := r.URL.Query()
		limit, err := strconv.Atoi(q.Get("sysparm_limit"))
		user, password, authenticated := r.BasicAuth()
		if err != nil || limit <= 0 || !authenticated || user != "test-user" || password != "test-secret" || r.Method != http.MethodGet || r.URL.Path != "/api/now/table/cmdb_ci" || q.Get("sysparm_query_no_domain") != "false" || q.Get("sysparm_no_count") != "false" || q.Get("sysparm_suppress_pagination_header") != "false" || q.Get("sysparm_query") != "ip_address=10.0.0.1^ORfqdn=10.0.0.1^ORname=10.0.0.1^ORDERBYsys_id" {
			t.Error("source request changed its fixed credential/query/domain authority")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		offset, err := strconv.Atoi(q.Get("sysparm_offset"))
		if err != nil || offset < 0 || offset >= 137 {
			t.Error("invalid physical source offset")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		count := 137
		if mode.Load() == 1 && offset > 0 {
			count++
		}
		if mode.Load() != 7 {
			w.Header().Set("X-Total-Count", strconv.Itoa(count))
		}
		end := min(offset+min(limit, 7), 137)
		rows := []serviceNowCI{}
		for index := offset; index < end; index++ {
			if !visible[index] {
				continue
			}
			row := serviceNowCI{SysID: fmt.Sprintf("ci-%05d", index), Name: "shared.example", Class: "cmdb_ci_server", IPAddress: "10.0.0.1", FQDN: "shared.example"}
			if mode.Load() == 3 && offset > 0 {
				row.SysID = "ci-00001"
			}
			if mode.Load() == 4 {
				row.IPAddress = "10.0.0.9"
			}
			rows = append(rows, row)
		}
		if end < 137 && mode.Load() != 8 && (mode.Load() != 11 || offset < 42) {
			next := server.URL + r.URL.Path
			q.Set("sysparm_offset", strconv.Itoa(end))
			q.Set("sysparm_limit", "7")
			if mode.Load() == 5 {
				next = "https://foreign.invalid" + r.URL.Path
			}
			if mode.Load() == 9 {
				q.Set("sysparm_query_no_domain", "true")
			}
			if mode.Load() == 10 {
				q.Set("sysparm_offset", strconv.Itoa(offset+101))
			}
			if mode.Load() == 13 {
				q.Set("sysparm_offset", strconv.Itoa(offset))
			}
			next += "?" + strings.ReplaceAll(q.Encode(), "%2C", ",")
			link := "<" + next + `>; rel="next"; title="next, page", <` + server.URL + r.URL.Path + `>; rel="last"`
			if mode.Load() == 6 {
				link += `; title="unterminated`
			}
			w.Header().Set("Link", link)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"result": rows})
	}))
	t.Cleanup(server.Close)
	return server
}

func TestServiceNowCompletePhysicalPagesKeepAllAuthorizedCIs(t *testing.T) {
	var mode, calls atomic.Int64
	source := serviceNowCapacitySource(t, &mode, &calls)
	provider := NewServiceNow(source.URL, "", "test-user:test-secret")
	provider.client.Transport = source.Client().Transport
	resolver := NewResolver(provider, time.Nanosecond)
	ctx := netBoxContext(netBoxTenantA)
	cis, err := resolver.Lookup(ctx, "10.0.0.1")
	if err != nil || len(cis) != 20 {
		t.Fatal("complete ServiceNow physical-page scan omitted authorized CIs", len(cis), err)
	}
	for i, index := range serviceNowVisible {
		if cis[i].SysID != fmt.Sprintf("ci-%05d", index) || cis[i].IPAddress != "10.0.0.1" {
			t.Fatal("complete ServiceNow known corpus or final object changed")
		}
	}
	if calls.Load() != 20 {
		t.Fatal("source proof did not traverse all physical ranges including empty visible pages")
	}
	mode.Store(1)
	if partial, err := resolver.Lookup(ctx, "10.0.0.1"); !errors.Is(err, ErrLookupIncomplete) || partial != nil {
		t.Fatal("changing source count published partial or stale matches", err)
	}
	mode.Store(2)
	if stale, err := resolver.Lookup(ctx, "10.0.0.1"); err == nil || stale != nil {
		t.Fatal("incomplete source cache reappeared during outage", err)
	}
	for _, fault := range []int64{3, 4, 5, 6, 7, 8, 9, 10, 11, 13} {
		mode.Store(fault)
		partial, err := provider.Lookup(ctx, "10.0.0.1")
		if partial != nil || (!errors.Is(err, ErrLookupIncomplete) && !errors.Is(err, ErrTenantBinding)) {
			t.Fatalf("source pagination fault%d did not refuse whole output: %v", fault, err)
		}
	}
}

func TestServiceNowLookupAdmissionIsCumulativeAcrossPhysicalPages(t *testing.T) {
	var mode, calls atomic.Int64
	source := serviceNowCapacitySource(t, &mode, &calls)
	for _, change := range []func(*LookupPolicy){
		func(p *LookupPolicy) { p.ResponseBytes = 2048 },
		func(p *LookupPolicy) { p.MemoryBytes = 64 << 10 },
	} {
		policy := DefaultLookupPolicy()
		change(&policy)
		provider := NewServiceNow(source.URL, "", "test-user:test-secret", policy)
		provider.client.Transport = source.Client().Transport
		before := calls.Load()
		if partial, err := provider.Lookup(netBoxContext(netBoxTenantA), "10.0.0.1"); !errors.Is(err, ErrLookupBudget) || partial != nil {
			t.Fatal("ServiceNow physical pages reset admission or returned partial matches", err)
		}
		if calls.Load()-before <= 1 {
			t.Fatal("cumulative source refusal was not reached after a fitting first page")
		}
	}
}

func TestServiceNowCompleteLookupProfilesAreRaiseableAndCancelBeforeIO(t *testing.T) {
	var calls atomic.Int64
	source := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.Header().Set("X-Total-Count", "1")
		_ = json.NewEncoder(w).Encode(map[string]any{"result": []serviceNowCI{{SysID: "one-ci", IPAddress: "10.0.0.1", Name: "owned"}}, "custom_source_data": strings.Repeat("x", 5<<20)})
	}))
	defer source.Close()
	policy := DefaultLookupPolicy()
	policy.Timeout, policy.ResponseBytes, policy.MemoryBytes = 25*time.Hour, 8<<20, 1<<30
	provider := NewServiceNow(source.URL, "", "test-user:test-secret", policy)
	if provider.client.Timeout != 25*time.Hour {
		t.Fatal("ServiceNow fixed client deadline ignored operator profile")
	}
	provider.client.Transport = source.Client().Transport
	if cis, err := provider.Lookup(netBoxContext(netBoxTenantA), "10.0.0.1"); err != nil || len(cis) != 1 || cis[0].SysID != "one-ci" {
		t.Fatal("ServiceNow larger complete response profile refused", err)
	}
	before := calls.Load()
	if cis, err := provider.Lookup(t.Context(), "10.0.0.1"); !errors.Is(err, ErrTenantBinding) || cis != nil {
		t.Fatal("ServiceNow lookup without tenant scope reached source", err)
	}
	ctx, cancel := context.WithCancel(netBoxContext(netBoxTenantA))
	cancel()
	if cis, err := provider.Lookup(ctx, "10.0.0.1"); !errors.Is(err, context.Canceled) || cis != nil {
		t.Fatal("canceled ServiceNow request returned output", err)
	}
	if calls.Load() != before {
		t.Fatal("canceled ServiceNow request reached source")
	}
}

func TestServiceNowLinkMetadataPreservesFixedRequestAuthority(t *testing.T) {
	endpoint := "https://inventory.example/api/now/table/cmdb_ci"
	q := url.Values{"sysparm_offset": {"0"}, "sysparm_limit": {"100"}, "sysparm_query_no_domain": {"false"}}
	for _, raw := range []string{
		endpoint + "?sysparm_offset=7&sysparm_limit=7",
		"?sysparm_offset=7&sysparm_limit=7&sysparm_query_no_domain=false",
	} {
		if offset, err := serviceNowNextOffset(endpoint, q, raw); err != nil || offset != 7 {
			t.Fatal("valid physical source continuation refused", err)
		}
	}
	for _, raw := range []string{
		"https://foreign.invalid/api/now/table/cmdb_ci?sysparm_offset=7&sysparm_limit=7",
		endpoint + "?sysparm_offset=7&sysparm_offset=14&sysparm_limit=7",
		endpoint + "?sysparm_offset=7&sysparm_limit=0",
		endpoint + "?sysparm_offset=7&sysparm_limit=7&sysparm_query_no_domain=true",
		endpoint + "?sysparm_offset=7&sysparm_limit=7&unknown=authority",
	} {
		if _, err := serviceNowNextOffset(endpoint, q, raw); !errors.Is(err, ErrLookupIncomplete) {
			t.Fatal("source metadata changed request authority", err)
		}
	}
}
