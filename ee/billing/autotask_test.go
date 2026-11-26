// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.
// Production use requires a valid commercial agreement; resale additionally
// requires an MSP entitlement and reseller agreement.

package billing

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/notify"
	"github.com/ctlplne/probectl/internal/tenancy"
)

var autotaskBillingInstant = time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)

const autotaskFixtureZone = "/atservicesrest/v1.0"

type autotaskBillingFixture struct {
	mapping            AutotaskContractMapping
	counts             PSAQuantities
	calendarEnd        string
	shape              atomic.Int32
	unavailableService atomic.Int64
	adjustmentCalls    atomic.Int32
	appliedDeviceUnit  atomic.Bool
}

func autotaskBillingServer(t *testing.T, accounts map[string]*autotaskBillingFixture) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var requests atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		name := r.Header.Get("UserName")
		account := accounts[name]
		if account == nil || r.Header.Get("Secret") != name+"-fixture" || r.Header.Get("ApiIntegrationCode") != "fixture-integration" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		m := account.mapping
		path := strings.TrimPrefix(r.URL.Path, autotaskFixtureZone)
		switch {
		case r.Method == http.MethodGet && path == "/Contracts/"+strconv.FormatInt(m.ContractID, 10):
			end := "2026-12-01T00:00:00Z"
			if account.calendarEnd != "" {
				end = account.calendarEnd
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"item": map[string]any{
				"id": m.ContractID, "companyID": m.CompanyID, "billToCompanyID": m.CompanyID,
				"contractType": m.RecurringType, "startDate": "2026-11-01T00:00:00.000",
				"endDate": end,
			}})
		case r.Method == http.MethodGet && strings.HasPrefix(path, "/ContractServices/"):
			id, err := strconv.ParseInt(strings.TrimPrefix(path, "/ContractServices/"), 10, 64)
			if err != nil || id == account.unavailableService.Load() || (id != m.DevicesServiceID && id != m.AgentsServiceID) {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			contract := m.ContractID
			if account.shape.Load() == 3 {
				contract++
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"item": map[string]int64{"id": id, "contractID": contract, "serviceID": id + 100}})
		case r.Method == http.MethodPost && path == "/ContractServiceUnits/query":
			var filter struct {
				Fields []string                `json:"IncludeFields"`
				Where  []notify.AutotaskFilter `json:"filter"`
			}
			if err := json.NewDecoder(r.Body).Decode(&filter); err != nil ||
				!reflect.DeepEqual(filter.Fields, []string{"contractID", "contractServiceID", "serviceID", "units", "startDate", "endDate"}) ||
				len(filter.Where) != 4 {
				t.Error("billing query omitted the narrow fields or required filters")
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			selected := filter.Where[1].Value
			var id, count int64
			switch {
			case reflect.DeepEqual(selected, []any{float64(m.DevicesServiceID)}):
				id, count = m.DevicesServiceID, account.counts.Devices
				if account.appliedDeviceUnit.Load() {
					count++
				}
			case reflect.DeepEqual(selected, []any{float64(m.AgentsServiceID)}):
				id, count = m.AgentsServiceID, account.counts.Agents
			default:
				t.Error("billing query must request one registered service")
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			if !reflect.DeepEqual(filter.Where, []notify.AutotaskFilter{
				{Operator: "eq", Field: "contractID", Value: float64(m.ContractID)},
				{Operator: "in", Field: "contractServiceID", Value: selected},
				{Operator: "lte", Field: "startDate", Value: autotaskBillingInstant.Format(time.RFC3339)},
				{Operator: "gte", Field: "endDate", Value: "2026-11-25T00:00:00Z"},
			}) {
				t.Error("billing query omitted the registered scope, effective instant, or narrow fields")
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			items := []map[string]any{}
			start, end := "2026-11-01", "2026-11-30T23:59:59Z"
			if account.calendarEnd != "" {
				// An earlier timestamped row is in the widened query but
				// has already ended. Its quantity must not be billed.
				items = append(items, map[string]any{
					"contractID": m.ContractID, "contractServiceID": id, "serviceID": id + 100, "units": 9,
					"startDate": start, "endDate": "2026-11-25T01:59:59Z",
				})
				start, end = "2026-11-25T02:00:00Z", account.calendarEnd
			}
			if count != 0 {
				items = append(items, map[string]any{
					"contractID": m.ContractID, "contractServiceID": id, "serviceID": id + 100, "units": count,
					"startDate": start, "endDate": end,
				})
			}
			page := map[string]any{"nextPageUrl": nil}
			switch account.shape.Load() {
			case 1:
				page["nextPageUrl"] = "https://untrusted.example.invalid/page"
			case 2:
				items = append(items, items[len(items)-1])
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"items": items, "pageDetails": page})
		case r.Method == http.MethodPost && path == "/ContractServiceAdjustments":
			account.adjustmentCalls.Add(1)
			var adjust struct {
				ServiceID int64     `json:"contractServiceID"`
				Time      time.Time `json:"effectiveDate"`
				Delta     int64     `json:"unitChange"`
			}
			if json.NewDecoder(r.Body).Decode(&adjust) != nil || adjust.ServiceID != m.DevicesServiceID ||
				!adjust.Time.Equal(autotaskBillingInstant) || adjust.Delta != 1 {
				t.Error("an adjustment escaped its service, effective date or expected delta")
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusServiceUnavailable)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)
	return server, &requests
}

func newAutotaskBillingFixtureReader(t *testing.T, server *httptest.Server, tenant string, mapping AutotaskContractMapping) *AutotaskBillingReader {
	t.Helper()
	reader, err := NewAutotaskBillingReader(tenant, server.URL+autotaskFixtureZone, mapping, notify.AutotaskCredentials{
		UserName: tenant, Secret: tenant + "-fixture", IntegrationCode: "fixture-integration",
	}, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	return reader
}

func TestAutotaskBillingReadsOneEffectivePeriod(t *testing.T) {
	account := &autotaskBillingFixture{
		mapping:     AutotaskContractMapping{CompanyID: 7, ContractID: 9, RecurringType: 6, DevicesServiceID: 12, AgentsServiceID: 13},
		counts:      PSAQuantities{Devices: 4},
		calendarEnd: "2026-11-25T00:00:00.000",
	}
	server, _ := autotaskBillingServer(t, map[string]*autotaskBillingFixture{"alpha": account})
	reader := newAutotaskBillingFixtureReader(t, server, "alpha", account.mapping)
	if got, err := reader.readServiceUnits(t.Context(), "alpha", account.mapping.DevicesServiceID, autotaskBillingInstant); got != account.counts.Devices || err != nil {
		t.Fatalf("device units = %d, %v, want %d", got, err, account.counts.Devices)
	}
	if got, err := reader.readServiceUnits(t.Context(), "alpha", account.mapping.AgentsServiceID, autotaskBillingInstant); got != 0 || err != nil {
		t.Fatalf("agent units = %d, %v, want zero for the documented zero-unit omission", got, err)
	}
	for _, invalid := range []struct {
		shape int32
		name  string
	}{{1, "incomplete page"}, {2, "overlapping periods"}, {3, "different contract"}} {
		t.Run(invalid.name, func(t *testing.T) {
			account.shape.Store(invalid.shape)
			if got, err := reader.readServiceUnits(t.Context(), "alpha", account.mapping.DevicesServiceID, autotaskBillingInstant); err == nil || got != 0 {
				t.Fatal("ambiguous or foreign data supplied a payable quantity")
			}
		})
	}
	t.Run("healthy service with unavailable sibling", func(t *testing.T) {
		account.shape.Store(0)
		account.unavailableService.Store(account.mapping.AgentsServiceID)
		got, err := reader.readServiceUnits(t.Context(), "alpha", account.mapping.DevicesServiceID, autotaskBillingInstant)
		if err != nil || got != account.counts.Devices {
			t.Fatalf("healthy service read depended on the unavailable sibling: units %d, error %v", got, err)
		}
		if got, err := reader.readServiceUnits(t.Context(), "alpha", account.mapping.AgentsServiceID, autotaskBillingInstant); err == nil || got != 0 {
			t.Fatal("the unavailable service supplied a payable quantity")
		}
	})
}

func TestAutotaskBillingReadbackKeepsTwoTenantsSeparate(t *testing.T) {
	accounts := map[string]*autotaskBillingFixture{
		"alpha": {mapping: AutotaskContractMapping{CompanyID: 7, ContractID: 9, RecurringType: 6, DevicesServiceID: 12, AgentsServiceID: 13},
			counts: PSAQuantities{Devices: 2, Agents: 3}},
		"beta": {mapping: AutotaskContractMapping{CompanyID: 8, ContractID: 9, RecurringType: 6, DevicesServiceID: 12, AgentsServiceID: 13},
			counts: PSAQuantities{Devices: 4, Agents: 5}},
	}
	server, requests := autotaskBillingServer(t, accounts)
	alpha := newAutotaskBillingFixtureReader(t, server, "alpha", accounts["alpha"].mapping)
	beta := newAutotaskBillingFixtureReader(t, server, "beta", accounts["beta"].mapping)
	if _, err := alpha.readServiceUnits(t.Context(), "beta", alpha.mapping.DevicesServiceID, autotaskBillingInstant); err == nil || requests.Load() != 0 {
		t.Fatal("a sibling tenant used the reader before ownership was verified")
	}
	if _, err := alpha.readServiceUnits(t.Context(), "alpha", 99, autotaskBillingInstant); err == nil || requests.Load() != 0 {
		t.Fatal("a service outside the mapping reached the vendor API")
	}
	for tenant, client := range map[string]*AutotaskBillingReader{"alpha": alpha, "beta": beta} {
		want := accounts[tenant].counts
		for id, quantity := range map[int64]int64{client.mapping.DevicesServiceID: want.Devices, client.mapping.AgentsServiceID: want.Agents} {
			if got, err := client.readServiceUnits(t.Context(), tenant, id, autotaskBillingInstant); err != nil || got != quantity {
				t.Fatalf("tenant %s service %d received incorrect billing units %d, %v", tenant, id, got, err)
			}
		}
	}
	mismatched := newAutotaskBillingFixtureReader(t, server, "beta", accounts["alpha"].mapping)
	if got, err := mismatched.readServiceUnits(t.Context(), "beta", mismatched.mapping.DevicesServiceID, autotaskBillingInstant); err == nil || got != 0 {
		t.Fatal("a matching contract ID bypassed the company's ownership check")
	}
	claim := pendingAutotaskAdjustment{Tenant: tenancy.ID(alpha.tenant), Sequence: 1,
		autotaskAdjustment: autotaskAdjustment{
			Key:         autotaskAdjustmentKey{alpha.mapping.CompanyID, alpha.mapping.ContractID, alpha.mapping.DevicesServiceID},
			EffectiveAt: autotaskBillingInstant,
			Previous:    2,
			Desired:     3,
		}}
	before := requests.Load()
	invalid := claim
	invalid.Desired = invalid.Previous
	for _, err := range []error{beta.createAdjustment(t.Context(), claim), alpha.createAdjustment(t.Context(), invalid)} {
		if !errors.Is(err, errInvalidAutotaskAdjustment) {
			t.Fatalf("the connector accepted a foreign or malformed claim: %v", err)
		}
	}
	if requests.Load() != before {
		t.Fatal("a rejected claim reached the vendor")
	}
	if err := alpha.createAdjustment(t.Context(), claim); err == nil ||
		accounts["alpha"].adjustmentCalls.Load() != 1 || accounts["beta"].adjustmentCalls.Load() != 0 {
		t.Fatalf("an owned send must make one request and expose the vendor error: %v", err)
	}
}
