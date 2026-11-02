// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package cmdb

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

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
		fmt.Fprintf(w, `{"count":1,"results":[{"id":42,"tenant":{"id":%d},"name":"owned-router","role":{"name":"edge"},"site":{"name":"iad"}}]}`, source)
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
	preview, err := resolver.PreviewNetBoxTag(ctx, "192.0.2.10", "site")
	if err != nil || preview.Value != "iad" || preview.CIID != "netbox:dcim.device:42" ||
		preview.LookupCIID != "netbox:ipam.ip_address:10" || preview.SourceRef != "netbox:t7:ip10:d42:site" ||
		preview.Name != "owned-router" || calls.Load() != before+2 {
		t.Fatalf("fresh related CI preview: %+v, %v, calls=%d", preview, err, calls.Load())
	}
	foreign.Store(true)
	if _, err := resolver.PreviewNetBoxTag(ctx, "192.0.2.10", "site"); err == nil {
		t.Fatal("owned IP authorized metadata from a foreign related CI")
	}
	down.Store(true)
	if _, err := resolver.PreviewNetBoxTag(ctx, "192.0.2.10", "site"); err == nil {
		t.Fatal("source outage accepted cached enrichment as an import suggestion")
	}
}
