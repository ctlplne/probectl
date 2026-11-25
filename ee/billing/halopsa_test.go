// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.
// Production use requires a valid commercial agreement; resale additionally
// requires an MSP entitlement and reseller agreement.

package billing

import (
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/ctlplne/probectl/internal/notify"
)

func TestHaloBillingRetriesAbsoluteQuantities(t *testing.T) {
	var mu sync.Mutex
	counts := map[int32]int64{12: 8, 13: 1}
	customer := int32(7)
	var reads, writes int
	halo := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.URL.Path == "/auth/token" {
			if r.Method != http.MethodPost || r.ParseForm() != nil ||
				r.PostForm.Get("client_id") != "billing-fixture" || r.PostForm.Get("client_secret") != "fixture-value" {
				t.Error("the OAuth grant did not use the billing credentials")
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"token_type": "Bearer", "access_token": "billing.fixture", "expires_in": 3600})
			return
		}
		if r.Header.Get("Authorization") != "Bearer billing.fixture" {
			t.Error("billing request had the wrong bearer token")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch r.Method + " " + r.URL.Path {
		case "GET /api/SoftwareLicence/12", "GET /api/SoftwareLicence/13":
			reads++
			id, owner := int32(12), int32(7)
			if r.URL.Path == "/api/SoftwareLicence/13" {
				id, owner = 13, customer
			}
			value := counts[id]
			_ = json.NewEncoder(w).Encode(haloSubscription{ID: id, Customer: owner, Type: 1, Count: &value})
		case "POST /api/SoftwareLicence":
			writes++
			var updates []haloQuantityWrite
			decode := json.NewDecoder(r.Body)
			decode.DisallowUnknownFields()
			if decode.Decode(&updates) != nil {
				t.Error("billing write carried fields beyond id and count")
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			switch {
			case writes == 1 && len(updates) == 2 && updates[0] == (haloQuantityWrite{ID: 12, Count: 0}) &&
				updates[1] == (haloQuantityWrite{ID: 13, Count: 3}):
				counts[12] = 0 // First row was applied before an ambiguous failure.
				w.WriteHeader(http.StatusServiceUnavailable)
			case writes == 2 && len(updates) == 1 && updates[0] == (haloQuantityWrite{ID: 13, Count: 3}):
				counts[13] = 3
				w.WriteHeader(http.StatusOK)
			default:
				t.Errorf("unexpected quantity update: %+v", updates)
				w.WriteHeader(http.StatusBadRequest)
			}
		default:
			t.Errorf("unexpected billing route %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(halo.Close)
	credentials := notify.HaloCredentials{ClientID: "billing-fixture", ClientSecret: "fixture-value"}
	writer, err := NewHaloBillingWriter("left", halo.URL, credentials,
		HaloSubscriptions{CustomerID: 7, DevicesSubscription: 12, AgentsSubscription: 13}, halo.Client())
	if err != nil {
		t.Fatal(err)
	}
	desired := PSAQuantities{Devices: 0, Agents: 3}
	for _, attempt := range []struct {
		tenant string
		count  PSAQuantities
	}{{"right", desired}, {"left", PSAQuantities{Devices: math.MaxInt64}}} {
		if changed, err := writer.sync(t.Context(), attempt.tenant, attempt.count, nil); err == nil || changed {
			t.Fatal("invalid tenant or quantity reached Halo", err)
		}
	}
	mu.Lock()
	if reads != 0 {
		t.Error("invalid snapshots went over the network")
	}
	customer = 99
	mu.Unlock()
	if changed, err := writer.sync(t.Context(), "left", desired, nil); err == nil || changed {
		t.Fatal("a foreign subscription passed the ownership check", err)
	}
	mu.Lock()
	customer = 7
	mu.Unlock()
	if changed, err := writer.sync(t.Context(), "left", desired, nil); err == nil || changed {
		t.Fatal("partial remote failure was reported as a confirmed sync", err)
	}
	if changed, err := writer.sync(t.Context(), "left", desired, nil); err != nil || !changed {
		t.Fatal("repair of the partial write did not converge", err)
	}
	if changed, err := writer.sync(t.Context(), "left", desired, nil); err != nil || changed {
		t.Fatal("unchanged quantities triggered a redundant write", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if writes != 2 || counts[12] != 0 || counts[13] != 3 {
		t.Fatal("the adjustment was duplicated or wrong")
	}
}

func TestHaloBillingWritersKeepTwoTenantsSeparate(t *testing.T) {
	type workspace struct {
		company int32
		counts  map[int32]int64
		writes  int
	}
	accounts := map[string]*workspace{
		"alpha": {company: 7, counts: map[int32]int64{12: 1, 13: 1}},
		"beta":  {company: 8, counts: map[int32]int64{22: 1, 23: 1}},
	}
	var mu sync.Mutex
	halo := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.URL.Path == "/auth/token" {
			name := ""
			if r.Method == http.MethodPost && r.ParseForm() == nil {
				name = r.PostForm.Get("client_id")
			}
			if accounts[name] == nil || r.PostForm.Get("client_secret") != name+"-fixture" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"token_type": "Bearer", "access_token": name, "expires_in": 3600})
			return
		}
		name, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		account := accounts[name]
		if !ok || account == nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch r.Method {
		case http.MethodGet:
			idText, hasPrefix := strings.CutPrefix(r.URL.Path, "/api/SoftwareLicence/")
			id, err := strconv.ParseInt(idText, 10, 32)
			if !hasPrefix || err != nil || id < 1 {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			// Halo may return a record across an upstream credential's client
			// assignments. The writer still has to verify the billed company.
			for _, owner := range accounts {
				if count, exists := owner.counts[int32(id)]; exists {
					_ = json.NewEncoder(w).Encode(haloSubscription{ID: int32(id), Customer: owner.company, Type: 1, Count: &count})
					return
				}
			}
			w.WriteHeader(http.StatusNotFound)
		case http.MethodPost:
			var updates []haloQuantityWrite
			if r.URL.Path != "/api/SoftwareLicence" || json.NewDecoder(r.Body).Decode(&updates) != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			account.writes++
			for _, update := range updates {
				if _, owns := account.counts[update.ID]; !owns {
					t.Error("a tenant attempted to bill a sibling subscription")
					w.WriteHeader(http.StatusForbidden)
					return
				}
				account.counts[update.ID] = update.Count
			}
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	t.Cleanup(halo.Close)
	newWriter := func(tenant string, mapping HaloSubscriptions) *HaloBillingWriter {
		t.Helper()
		api, err := NewHaloBillingWriter(tenant, halo.URL, notify.HaloCredentials{ClientID: tenant, ClientSecret: tenant + "-fixture"},
			mapping, halo.Client())
		if err != nil {
			t.Fatal(err)
		}
		return api
	}
	alpha := newWriter("alpha", HaloSubscriptions{CustomerID: 7, DevicesSubscription: 12, AgentsSubscription: 13})
	beta := newWriter("beta", HaloSubscriptions{CustomerID: 8, DevicesSubscription: 22, AgentsSubscription: 23})
	corrupt := newWriter("beta", HaloSubscriptions{CustomerID: 8, DevicesSubscription: 22, AgentsSubscription: 13})
	if _, err := alpha.sync(t.Context(), "beta", PSAQuantities{Devices: 99, Agents: 99}, nil); err == nil {
		t.Fatal("a writer accepted the sibling tenant's snapshot")
	}
	if _, err := corrupt.sync(t.Context(), "beta", PSAQuantities{Devices: 99, Agents: 99}, nil); err == nil {
		t.Fatal("the vendor's foreign subscription was writable")
	}
	if changed, err := alpha.sync(t.Context(), "alpha", PSAQuantities{Devices: 2, Agents: 3}, nil); err != nil || !changed {
		t.Fatal("alpha's own usage did not sync", err)
	}
	if changed, err := beta.sync(t.Context(), "beta", PSAQuantities{Devices: 4, Agents: 5}, nil); err != nil || !changed {
		t.Fatal("beta's own usage did not sync", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if accounts["alpha"].writes != 1 || accounts["alpha"].counts[12] != 2 || accounts["alpha"].counts[13] != 3 ||
		accounts["beta"].writes != 1 || accounts["beta"].counts[22] != 4 || accounts["beta"].counts[23] != 5 {
		t.Fatal("credentials or billing quantities crossed tenants")
	}
}
