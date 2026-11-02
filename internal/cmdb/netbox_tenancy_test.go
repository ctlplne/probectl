// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

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

	"github.com/ctlplne/probectl/internal/tenancy"
)

const netBoxTenantA = "11111111-1111-4111-8111-111111111111"
const netBoxTenantB = "22222222-2222-4222-8222-222222222222"

func netBoxContext(tenant string) context.Context {
	return tenancy.WithTenant(context.Background(), tenancy.ID(tenant))
}

func TestNetBoxTenantMapRejectsAmbiguousOwnership(t *testing.T) {
	for _, raw := range []string{
		`null`, `[]`, `{"bad":"7"}`, `{"` + netBoxTenantA + `":7}`,
		`{"` + netBoxTenantA + `":"0"}`, `{"` + netBoxTenantA + `":"07"}`,
		`{"` + netBoxTenantA + `":"7","` + netBoxTenantA + `":"8"}`,
		`{"` + netBoxTenantA + `":"7","` + netBoxTenantB + `":"7"}`,
		`{"` + netBoxTenantA + `":"7"} {}`,
	} {
		if _, err := ParseNetBoxTenantMap(raw); !errors.Is(err, ErrTenantBinding) {
			t.Fatalf("ambiguous binding accepted: %s: %v", raw, err)
		}
	}
	bindings, err := ParseNetBoxTenantMap(`{"` + netBoxTenantA + `":"7","` + netBoxTenantB + `":"8"}`)
	if err != nil || len(bindings) != 2 || bindings[netBoxTenantB] != "8" {
		t.Fatalf("valid tenant bindings: %v, %v", bindings, err)
	}
}

func TestNetBoxTenantPinPrecedesSourceAndCache(t *testing.T) {
	var calls atomic.Int64
	var down atomic.Bool
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if down.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		if r.URL.Query().Get("q") != "10.0.0.1" {
			t.Errorf("unexpected lookup key: %s", r.URL.RawQuery)
		}
		source := r.URL.Query().Get("tenant_id")
		if source != "7" && source != "8" {
			t.Errorf("source read without mapped tenant: %s", r.URL.RawQuery)
		}
		fmt.Fprintf(w, `{"count":1,"next":null,"results":[{"id":1,"tenant":{"id":%s},"address":"10.0.0.1/32","dns_name":"tenant-%s"}]}`, source, source)
	}))
	defer server.Close()
	bindings := map[string]string{netBoxTenantA: "7", netBoxTenantB: "8"}
	provider := NewNetBox(server.URL, "test-token", bindings)
	provider.client = server.Client()
	bindings[netBoxTenantA] = "8" // constructor must retain its own immutable map
	resolver := NewResolver(provider, time.Nanosecond)
	for _, row := range []struct{ tenant, name string }{{netBoxTenantA, "tenant-7"}, {netBoxTenantB, "tenant-8"}} {
		cis, err := resolver.Lookup(netBoxContext(row.tenant), "10.0.0.1")
		if err != nil || len(cis) != 1 || cis[0].Name != row.name {
			t.Fatalf("tenant %s resolved wrong CI: %+v, %v", row.tenant, cis, err)
		}
	}
	down.Store(true)
	for _, row := range []struct{ tenant, name string }{{netBoxTenantB, "tenant-8"}, {netBoxTenantA, "tenant-7"}} {
		cis, err := resolver.Lookup(netBoxContext(row.tenant), "10.0.0.1")
		if err != nil || len(cis) != 1 || cis[0].Name != row.name {
			t.Fatalf("tenant %s stale cache crossed ownership: %+v, %v", row.tenant, cis, err)
		}
	}
	before := calls.Load()
	for _, ctx := range []context.Context{context.Background(), netBoxContext("33333333-3333-4333-8333-333333333333")} {
		if cis, err := resolver.Lookup(ctx, "10.0.0.1"); !errors.Is(err, ErrTenantBinding) || len(cis) != 0 {
			t.Fatalf("unbound caller reached cached CI: %+v, %v", cis, err)
		}
	}
	if calls.Load() != before {
		t.Fatal("missing mapping reached the NetBox source")
	}
}

func TestNetBoxRejectsUnownedIncompleteOrAmbiguousResponses(t *testing.T) {
	for name, body := range map[string]string{
		"missing tenant":       `{"count":1,"results":[{"id":1,"address":"10.0.0.1/32"}]}`,
		"foreign tenant":       `{"count":1,"results":[{"id":1,"tenant":{"id":8},"address":"10.0.0.1/32"}]}`,
		"foreign nested owner": `{"count":1,"results":[{"id":1,"tenant":{"id":7},"address":"10.0.0.1/32","assigned_object":{"device":{"tenant":{"id":8}}}}]}`,
		"wrong key":            `{"count":1,"results":[{"id":1,"tenant":{"id":7},"address":"10.0.0.10/32"}]}`,
		"partial page":         `{"count":2,"next":"https://netbox.invalid/next","results":[{"id":1,"tenant":{"id":7},"address":"10.0.0.1/32"}]}`,
		"missing count":        `{"results":[{"id":1,"tenant":{"id":7},"address":"10.0.0.1/32"}]}`,
		"duplicate tenant":     `{"count":1,"results":[{"id":1,"tenant":{"id":8},"tenant":{"id":7},"address":"10.0.0.1/32"}]}`,
		"case alias":           `{"count":1,"results":[{"id":1,"Tenant":{"id":8},"tenant":{"id":7},"address":"10.0.0.1/32"}]}`,
		"oversized":            `{"count":0,"results":[],"padding":"` + strings.Repeat("x", 4<<20) + `"}`,
	} {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(body)) }))
			defer server.Close()
			provider := NewNetBox(server.URL, "test-token", map[string]string{netBoxTenantA: "7"})
			provider.client = server.Client()
			if cis, err := provider.Lookup(netBoxContext(netBoxTenantA), "10.0.0.1"); err == nil || len(cis) != 0 {
				t.Fatalf("untrusted response admitted: %+v, %v", cis, err)
			}
		})
	}
}

func TestNetBoxOwnershipMismatchEvictsStaleCache(t *testing.T) {
	var phase atomic.Int64
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		source := 7
		if phase.Load() == 1 {
			source = 8
		}
		if phase.Load() == 2 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		fmt.Fprintf(w, `{"count":1,"results":[{"id":1,"tenant":{"id":%d},"address":"10.0.0.1/32"}]}`, source)
	}))
	defer server.Close()
	provider := NewNetBox(server.URL, "test-token", map[string]string{netBoxTenantA: "7"})
	provider.client = server.Client()
	resolver := NewResolver(provider, time.Nanosecond)
	ctx := netBoxContext(netBoxTenantA)
	if _, err := resolver.Lookup(ctx, "10.0.0.1"); err != nil {
		t.Fatal(err)
	}
	phase.Store(1)
	if cis, err := resolver.Lookup(ctx, "10.0.0.1"); !errors.Is(err, ErrTenantBinding) || len(cis) != 0 {
		t.Fatalf("ownership move returned stale CI: %+v, %v", cis, err)
	}
	phase.Store(2)
	if cis, err := resolver.Lookup(ctx, "10.0.0.1"); err == nil || len(cis) != 0 {
		t.Fatalf("outage resurrected revoked cache entry: %+v, %v", cis, err)
	}
}

func TestNetBoxHostnameChecksDeviceAndVMTenant(t *testing.T) {
	for _, endpoint := range []string{"dcim/devices", "virtualization/virtual-machines"} {
		t.Run(endpoint, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Query().Get("tenant_id") != "7" || r.URL.Query().Get("name") != "router.example" {
					t.Errorf("hostname source query was not scoped: %s", r.URL.RawQuery)
				}
				if strings.Contains(r.URL.Path, endpoint) {
					_, _ = w.Write([]byte(`{"count":1,"results":[{"id":1,"name":"router.example","tenant":{"id":8}}]}`))
					return
				}
				_, _ = w.Write([]byte(`{"count":0,"results":[]}`))
			}))
			defer server.Close()
			provider := NewNetBox(server.URL, "test-token", map[string]string{netBoxTenantA: "7"})
			provider.client = server.Client()
			if cis, err := provider.Lookup(netBoxContext(netBoxTenantA), "router.example"); !errors.Is(err, ErrTenantBinding) || len(cis) != 0 {
				t.Fatalf("foreign hostname CI admitted: %+v, %v", cis, err)
			}
		})
	}
}

func TestNetBoxOwnershipRefusalFencesOlderInflightResponse(t *testing.T) {
	var calls atomic.Int64
	entered := make(chan struct{})
	release := make(chan struct{})
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		index := calls.Add(1) - 1
		source := 7
		if index == 1 {
			close(entered)
			select {
			case <-release:
			case <-r.Context().Done():
				return
			}
		}
		if index == 2 {
			source = 8
		}
		if index >= 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		fmt.Fprintf(w, `{"count":1,"results":[{"id":1,"tenant":{"id":%d},"address":"10.0.0.1/32"}]}`, source)
	}))
	defer server.Close()
	provider := NewNetBox(server.URL, "test-token", map[string]string{netBoxTenantA: "7"})
	provider.client = server.Client()
	resolver := NewResolver(provider, time.Nanosecond)
	ctx, cancel := context.WithTimeout(netBoxContext(netBoxTenantA), 10*time.Second)
	defer cancel()
	if _, err := resolver.Lookup(ctx, "10.0.0.1"); err != nil {
		t.Fatal(err)
	}
	completed := make(chan error, 1)
	go func() { _, err := resolver.Lookup(ctx, "10.0.0.1"); completed <- err }()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("older request did not reach the source")
	}
	if _, err := resolver.Lookup(ctx, "10.0.0.1"); !errors.Is(err, ErrTenantBinding) {
		t.Fatalf("new ownership mismatch was not refused: %v", err)
	}
	close(release)
	select {
	case err := <-completed:
		if !errors.Is(err, ErrTenantBinding) {
			t.Fatalf("older response restored revoked cache ownership: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("older request did not finish")
	}
	if cis, err := resolver.Lookup(ctx, "10.0.0.1"); err == nil || len(cis) != 0 {
		t.Fatalf("outage exposed an entry restored after revocation: %+v, %v", cis, err)
	}
}
