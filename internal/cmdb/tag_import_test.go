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
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

func TestNetBoxPreviewMissingOwnershipEvictsOnlyItsTenantCache(t *testing.T) {
	for _, refusal := range []string{"missing lookup", "ambiguous lookup", "missing related owner"} {
		t.Run(refusal, func(t *testing.T) {
			var phase atomic.Int64
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if phase.Load() == 2 {
					w.WriteHeader(http.StatusServiceUnavailable)
					return
				}
				source := r.URL.Query().Get("tenant_id")
				if source != "7" && source != "8" {
					t.Error("source request omitted its mapped tenant")
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				if phase.Load() == 1 && source == "7" {
					if refusal == "missing lookup" || (refusal == "missing related owner" && r.URL.Path == "/api/dcim/devices/") {
						_, _ = w.Write([]byte(`{"count":0,"results":[]}`))
						return
					}
					if refusal == "ambiguous lookup" {
						_, _ = w.Write([]byte(`{"count":2,"results":[{"id":10,"tenant":{"id":7},"address":"192.0.2.10/32"},{"id":11,"tenant":{"id":7},"address":"192.0.2.10/32"}]}`))
						return
					}
				}
				id, device := 10, 42
				if source == "8" {
					id, device = 20, 84
				}
				fmt.Fprintf(w, `{"count":1,"results":[{"id":%d,"tenant":{"id":%s},"address":"192.0.2.10/32","assigned_object":{"device":{"id":%d}}}]}`, id, source, device)
			}))
			defer server.Close()
			provider := NewNetBox(server.URL, "test-token", map[string]string{netBoxTenantA: "7", netBoxTenantB: "8"})
			provider.client = server.Client()
			resolver := NewResolver(provider, time.Hour)
			for _, tenant := range []string{netBoxTenantA, netBoxTenantB} {
				if cis, err := resolver.Lookup(netBoxContext(tenant), "192.0.2.10"); err != nil || len(cis) != 1 {
					t.Fatalf("cannot warm the independent tenant cache: %v", err)
				}
			}
			phase.Store(1)
			if candidate, err := previewOwnedIPTag(resolver, netBoxContext(netBoxTenantA), "192.0.2.10", "site"); !errors.Is(err, ErrNoTagCandidate) || candidate != (NetBoxTagCandidate{}) {
				t.Fatalf("fresh missing/ambiguous ownership was not refused: %v", err)
			}
			phase.Store(2)
			if cis, err := resolver.Lookup(netBoxContext(netBoxTenantA), "192.0.2.10"); !errors.Is(err, ErrUnavailable) || len(cis) != 0 {
				t.Fatal("outage revived cached enrichment after completed ownership refusal")
			}
			if cis, err := resolver.Lookup(netBoxContext(netBoxTenantB), "192.0.2.10"); err != nil || len(cis) != 1 || cis[0].SysID != "netbox:ipam.ip_address:20" {
				t.Fatal("one tenant's refusal evicted or replaced the other tenant's authorized enrichment")
			}
		})
	}
}

func TestNetBoxTagPreviewFreshlyAttestsRelatedCI(t *testing.T) {
	var down, foreign atomic.Bool
	var calls atomic.Int64
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if down.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		if r.URL.Query().Get("tenant_id") != "7" {
			t.Errorf("unscoped tag source read: %s", r.URL.RawQuery)
		}
		if r.URL.Path == "/api/ipam/ip-addresses/" {
			_, _ = w.Write([]byte(`{"count":1,"results":[{"id":10,"tenant":{"id":7},"address":"192.0.2.10/32","assigned_object":{"device":{"id":42,"name":"unattested-name"}}}]}`))
			return
		}
		if r.URL.Path != "/api/dcim/devices/" || r.URL.Query().Get("id") != "42" {
			t.Errorf("related CI was not selected by exact ID: %s", r.URL.String())
		}
		source := 7
		if foreign.Load() {
			source = 8
		}
		fmt.Fprintf(w, `{"count":1,"results":[{"id":42,"tenant":{"id":%d},"name":"owned-router","role":{"id":51,"name":"edge"},"site":{"id":71,"name":"iad"}}]}`, source)
	}))
	defer server.Close()
	provider := NewNetBox(server.URL, "test-token", map[string]string{netBoxTenantA: "7"})
	provider.client = server.Client()
	resolver := NewResolver(provider, time.Hour)
	ctx := netBoxContext(netBoxTenantA)
	if _, err := resolver.Lookup(ctx, "192.0.2.10"); err != nil {
		t.Fatal(err)
	}
	before := calls.Load()
	preview, err := previewOwnedIPTag(resolver, ctx, "192.0.2.10", "site")
	if err != nil || preview.Value != "iad" || preview.CIID != "netbox:dcim.device:42" ||
		preview.LookupCIID != "netbox:ipam.ip_address:10" || preview.SourceRef != "netbox:t7:ip10:d42:site:a71" ||
		preview.Name != "owned-router" || calls.Load() != before+2 {
		t.Fatalf("fresh related CI preview: %+v, %v, calls=%d", preview, err, calls.Load())
	}
	foreign.Store(true)
	if _, err := previewOwnedIPTag(resolver, ctx, "192.0.2.10", "site"); err == nil {
		t.Fatal("owned IP authorized metadata from a foreign related CI")
	}
	down.Store(true)
	if _, err := previewOwnedIPTag(resolver, ctx, "192.0.2.10", "site"); err == nil {
		t.Fatal("source outage accepted cached enrichment as an import suggestion")
	}
	if _, err := resolver.Lookup(ctx, "192.0.2.10"); err == nil {
		t.Fatal("known preview ownership refusal left stale enrichment authorized")
	}
}

// Exercise the shipping subject preview with the same owned single-IP fact
// used by the original regression. This adapter adds no source behavior.
func previewOwnedIPTag(resolver *Resolver, ctx context.Context, address, field string) (NetBoxTagCandidate, error) {
	selection, err := resolver.PreviewNetBoxSubjectTag(ctx, NetBoxTagFacts{Addresses: []netip.Addr{netip.MustParseAddr(address)}}, field, "")
	return selection.Candidate(), err
}
