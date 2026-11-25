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
	"sync/atomic"
	"testing"

	"github.com/ctlplne/probectl/internal/device"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestNinjaOneInventoryPaginatesWithSiteFilter(t *testing.T) {
	site := Site{Vendor: NinjaOne, Account: "shared", ID: "42:7"}
	var calls, variant atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		q := r.URL.Query()
		if r.Method != http.MethodGet || r.URL.Path != "/v2/devices" || q.Get("df") != "org=42 AND loc=7" ||
			q.Get("pageSize") != "250" || r.Header.Get("Authorization") != "Bearer ninja.fixture" {
			t.Error("request left the HTTPS inventory endpoint, site filter, or read credential")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		page := []ninjaOneDevice{}
		switch q.Get("after") {
		case "":
			page = append(page,
				ninjaOneDevice{ID: 14, Organization: 42, Location: 7, DNSName: "other.example"},
				ninjaOneDevice{ID: 12, Organization: 42, Location: 7, DNSName: "first.example"},
			)
		case "12":
			row := ninjaOneDevice{ID: 20, Organization: 42, Location: 7, SystemName: "second"}
			switch variant.Load() {
			case 1:
				row.ID = 12
			case 2:
				_, _ = w.Write([]byte("null"))
				return
			case 3:
				http.Redirect(w, r, "/v2/unexpected", http.StatusTemporaryRedirect)
				return
			}
			page = append(page, row)
		case "20":
		default:
			t.Error("request used an unexpected cursor")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(page)
	}))
	t.Cleanup(server.Close)
	source, err := NewNinjaOneInventory(site, server.URL, "ninja.fixture", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	mappings := fixtureSiteMappings(t, fixtureSite(tenantAlpha, contextAlpha, site))
	owner := tenancy.WithTenant(t.Context(), tenantAlpha)
	got, err := mappings.Discover(owner, source)
	if err != nil || calls.Load() != 3 || len(got.Devices) != 3 ||
		got.Devices[0].ExternalID != "12" || got.Devices[0].Hostname != "first.example" ||
		got.Devices[2].ExternalID != "20" || got.Devices[2].Hostname != "second" ||
		got.Devices[2].ActivationState != device.ActivationPendingReview {
		t.Fatal("inventory failed to read both short pages through the explicit end", err)
	}
	for _, state := range []int32{1, 2, 3} {
		variant.Store(state)
		calls.Store(0)
		invalid, err := mappings.Discover(owner, source)
		if err == nil || len(invalid.Devices) != 0 || calls.Load() != 2 {
			t.Fatal("invalid page exposed partial results or made a continuation request", err)
		}
	}
}

func TestNinjaOneInventoryKeepsTwoTenantsSeparate(t *testing.T) {
	first := Site{Vendor: NinjaOne, Account: "shared", ID: "42:7"}
	second := Site{Vendor: NinjaOne, Account: "shared", ID: "42:8"}
	mappings := fixtureSiteMappings(t, fixtureSite(tenantAlpha, contextAlpha, first), fixtureSite(tenantBeta, contextBeta, second))
	ownerA := tenancy.WithTenant(t.Context(), tenantAlpha)
	ownerB := tenancy.WithTenant(t.Context(), tenantBeta)

	var requests, injection atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		q := r.URL.Query()
		var row ninjaOneDevice
		switch q.Get("df") {
		case "org=42 AND loc=7":
			row = ninjaOneDevice{ID: 12, Organization: 42, Location: 7, SystemName: "alpha"}
			switch injection.Load() {
			case 1:
				row.Location = 8
			case 2:
				row.Organization = 43
			}
		case "org=42 AND loc=8":
			row = ninjaOneDevice{ID: 18, Organization: 42, Location: 8, SystemName: "beta"}
		default:
			t.Error("request omitted its exact provider-side location filter")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		page := []ninjaOneDevice{}
		if q.Get("after") == "" {
			page = append(page, row)
		}
		_ = json.NewEncoder(w).Encode(page)
	}))
	t.Cleanup(server.Close)
	sourceA, err := NewNinjaOneInventory(first, server.URL, "ninja.fixture", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	sourceB, err := NewNinjaOneInventory(second, server.URL, "ninja.fixture", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	for _, attempt := range []struct {
		ctx    context.Context
		source InventorySource
	}{{ownerA, sourceB}, {ownerB, sourceA}} {
		batch, err := mappings.Discover(attempt.ctx, attempt.source)
		if !errors.Is(err, ErrSiteUnavailable) || len(batch.Devices) != 0 || requests.Load() != 0 {
			t.Fatal("a sibling tenant's mapping reached NinjaOne", err)
		}
	}
	alpha, err := mappings.Discover(ownerA, sourceA)
	if err != nil || alpha.TenantID != tenantAlpha || alpha.ContextID != contextAlpha ||
		len(alpha.Devices) != 1 || alpha.Devices[0].Hostname != "alpha" {
		t.Fatal("the first site failed to preserve its tenant and routing context", err)
	}
	beta, err := mappings.Discover(ownerB, sourceB)
	if err != nil || beta.TenantID != tenantBeta || beta.ContextID != contextBeta ||
		len(beta.Devices) != 1 || beta.Devices[0].Hostname != "beta" {
		t.Fatal("the second site failed to preserve its tenant and routing context", err)
	}
	for _, foreign := range []int32{1, 2} {
		injection.Store(foreign)
		batch, err := mappings.Discover(ownerA, sourceA)
		if err == nil || len(batch.Devices) != 0 {
			t.Fatal("a foreign location or organization escaped the site filter", err)
		}
	}
}
