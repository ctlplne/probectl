// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.
// Production use requires a valid commercial agreement; resale additionally
// requires an MSP entitlement and reseller agreement.

package rmm

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/ctlplne/probectl/internal/device"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestDattoSiteInventoryKeepsTwoTenantsSeparate(t *testing.T) {
	left := Site{Vendor: DattoRMM, Account: "first", ID: "left-site"}
	right := Site{Vendor: DattoRMM, Account: "second", ID: "right-site"}
	ownerA := tenancy.WithTenant(t.Context(), tenantAlpha)
	ownerB := tenancy.WithTenant(t.Context(), tenantBeta)
	mappings := fixtureSiteMappings(t, fixtureSite(tenantAlpha, contextAlpha, left), fixtureSite(tenantBeta, contextBeta, right))
	var readsA, readsB, variant atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Error("inventory used a mutating method")
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		var site Site
		var token, ip string
		var next any
		switch r.URL.Path {
		case "/api/v2/site/left-site/devices":
			readsA.Add(1)
			site, token, ip = left, "left.fixture", "10.2.0.1"
			if r.URL.RawQuery == "" {
				next = "?page=1&max=250"
				switch variant.Load() {
				case 1:
					next = "/api/v2/site/right-site/devices?page=1"
				case 2:
					site = right
				case 3:
					http.Redirect(w, r, "/api/v2/site/right-site/devices", http.StatusTemporaryRedirect)
					return
				}
			}
		case "/api/v2/site/right-site/devices":
			readsB.Add(1)
			site, token, ip = right, "right.fixture", "10.3.0.1"
		default:
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if r.Header.Get("Authorization") != "Bearer "+token {
			t.Error("a request used another site's credential")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		record := map[string]string{"uid": "one", "siteUid": site.ID, "hostname": "fixture", "intIpAddress": ip,
			"operatingSystem": "Linux", "extIpAddress": "192.0.2.2"}
		if r.URL.Query().Get("page") == "1" {
			record["uid"] = "two"
			record["intIpAddress"] = "127.0.0.1"
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"pageDetails": map[string]any{"nextPageUrl": next},
			"devices": []map[string]string{record}})
	}))
	t.Cleanup(server.Close)

	sourceA, err := NewDattoInventory(left, server.URL, "left.fixture", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	sourceB, err := NewDattoInventory(right, server.URL, "right.fixture", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	for _, attempt := range []struct {
		ctx    context.Context
		source InventorySource
	}{{ownerB, sourceA}, {ownerA, sourceB}} {
		got, err := mappings.Discover(attempt.ctx, attempt.source)
		if !errors.Is(err, ErrSiteUnavailable) || len(got.Devices) != 0 || readsA.Load()+readsB.Load() != 0 {
			t.Fatal("a foreign mapping reached the vendor", err)
		}
	}
	alpha, err := mappings.Discover(ownerA, sourceA)
	if err != nil || alpha.TenantID != tenantAlpha || alpha.ContextID != contextAlpha ||
		alpha.Source != left || len(alpha.Devices) != 2 || readsA.Load() != 2 ||
		alpha.Devices[0].Address != "10.2.0.1" || alpha.Devices[1].Address != "" {
		t.Fatal("the two owned inventory pages were not converted correctly", err)
	}
	beta, err := mappings.Discover(ownerB, sourceB)
	if err != nil || beta.TenantID != tenantBeta || beta.ContextID != contextBeta || beta.Source != right ||
		len(beta.Devices) != 1 || beta.Devices[0].Address != "10.3.0.1" || readsB.Load() != 1 {
		t.Fatal("the sibling inventory crossed the configured routing context", err)
	}
	for _, batch := range []DiscoveryCandidates{alpha, beta} {
		for _, row := range batch.Devices {
			if row.ActivationState != device.ActivationPendingReview || row.OS != "Linux" {
				t.Fatal("vendor inventory was converted into an active device")
			}
		}
	}
	for _, n := range []int32{1, 2, 3} {
		variant.Store(n)
		batch, err := mappings.Discover(ownerA, sourceA)
		if err == nil || readsB.Load() != 1 || len(batch.Devices) != 0 || strings.Contains(err.Error(), "left.fixture") {
			t.Fatal("foreign row, continuation or redirect escaped the site boundary", err)
		}
	}
}
