// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/cmdb"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// Component provider: results vary by the authenticated tenant, without any
// provider-specific cache hook. This is not a real ServiceNow source receipt.
type contextCMDBProvider struct{ calls map[string]int }

func (*contextCMDBProvider) Name() string { return "context-fixture" }
func (p *contextCMDBProvider) Lookup(ctx context.Context, _ string) ([]cmdb.CI, error) {
	tenant, ok := tenancy.FromContext(ctx)
	if !ok {
		return nil, cmdb.ErrTenantBinding
	}
	p.calls[tenant.String()]++
	return []cmdb.CI{{SysID: "same-ci-id", Name: "private-" + tenant.String()}}, nil
}

func TestCMDBAPIEqualOwnedKeysKeepIndependentTenantCaches(t *testing.T) {
	const a = "11111111-1111-4111-8111-111111111111"
	const b = "22222222-2222-4222-8222-222222222222"
	provider := &contextCMDBProvider{calls: map[string]int{}}
	srv := testServer(fakePinger{}).WithCMDB(cmdb.NewResolver(provider, time.Hour))
	srv.cmdbKeyOwner = func(_ *http.Request, key string) (bool, error) { return key == "10.0.0.1", nil }
	lookup := func(tenant, key string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/v1/cmdb/lookup?key="+key, nil)
		req.Header.Set("X-Probectl-Tenant", tenant)
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)
		return rec
	}
	for range 2 {
		for _, lane := range []struct{ tenant, foreign string }{{a, b}, {b, a}} {
			rec := lookup(lane.tenant, "10.0.0.1")
			if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "private-"+lane.tenant) || strings.Contains(rec.Body.String(), "private-"+lane.foreign) {
				t.Fatalf("CMDB API cache crossed equal owned tenant keys: status=%d body=%s", rec.Code, rec.Body.String())
			}
		}
	}
	if provider.calls[a] != 1 || provider.calls[b] != 1 {
		t.Fatal("API did not exercise independent warm tenant caches")
	}
	if rec := lookup(b, "10.0.0.9"); rec.Code != http.StatusNotFound || strings.Contains(rec.Body.String(), "private-") {
		t.Fatal("unowned API key disclosed cached source metadata")
	}
	if provider.calls[a] != 1 || provider.calls[b] != 1 {
		t.Fatal("unowned API key reached source")
	}
}
