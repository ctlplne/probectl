// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.
// Production use requires a valid commercial agreement; resale additionally
// requires an MSP entitlement and reseller agreement.

package billing

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/notify"
)

func TestPSASyncRejectsAmbiguousRoutes(t *testing.T) {
	base := haloBillingRoute{
		Tenant: "00000000-0000-4000-8000-000000000001", Origin: "https://halo.example.invalid",
		HaloSubscriptions: HaloSubscriptions{CustomerID: 7, DevicesSubscription: 12, AgentsSubscription: 13},
		HaloCredentials:   notify.HaloCredentials{ClientID: "fixture-client", ClientSecret: "fixture-value"},
	}
	sibling := base
	sibling.Tenant = "00000000-0000-4000-8000-000000000002"
	sibling.Origin = "https://HALO.EXAMPLE.INVALID.:0443/"
	sibling.DevicesSubscription = 22
	for _, tc := range []struct {
		name   string
		routes []haloBillingRoute
		want   string
	}{
		{"shared subscription", []haloBillingRoute{base, sibling}, "reuses a subscription"},
		{"repeated tenant", []haloBillingRoute{base, base}, "repeats a tenant"},
		{"distinct tenants and subscriptions", []haloBillingRoute{base, {
			Tenant: sibling.Tenant, Origin: sibling.Origin,
			HaloSubscriptions: HaloSubscriptions{CustomerID: 8, DevicesSubscription: 22, AgentsSubscription: 23},
			HaloCredentials:   sibling.HaloCredentials,
		}}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := json.Marshal(tc.routes)
			if err != nil {
				t.Fatal(err)
			}
			// Construction only validates configuration and creates clients.
			s, err := NewPSASync(PSAConfigurations{Halo: raw}, &pgxpool.Pool{}, func() bool { return true }, nil, nil)
			if tc.want == "" {
				if err != nil || len(s.routes) != len(tc.routes) {
					t.Fatal("could not construct independent tenant routes", err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tc.want) || strings.Contains(err.Error(), "fixture-value") {
				t.Fatal("overlapping routes were accepted or credentials were shown", err)
			}
		})
	}
	halo, err := json.Marshal([]haloBillingRoute{base})
	if err != nil {
		t.Fatal(err)
	}
	autotask := autotaskBillingRoute{
		Tenant: base.Tenant, Zone: "https://autotask.example.invalid/atservicesrest/v1.0",
		AutotaskContractMapping: AutotaskContractMapping{CompanyID: 7, ContractID: 8, RecurringType: 6, DevicesServiceID: 9, AgentsServiceID: 10},
		AutotaskCredentials:     notify.AutotaskCredentials{UserName: "fixture-client", Secret: "fixture-value", IntegrationCode: "fixture-code"},
	}
	other := autotask
	other.Tenant = sibling.Tenant
	other.Zone = "https://AUTOTASK.EXAMPLE.INVALID.:0443/atservicesrest/v1.0/"
	for _, tc := range []struct {
		name     string
		halo     []byte
		autotask []autotaskBillingRoute
		want     string
	}{
		{"shared service", nil, []autotaskBillingRoute{autotask, other}, "reuses a contract service"},
		{"cross-vendor repeat", halo, []autotaskBillingRoute{autotask}, "repeats a tenant"},
		{"distinct vendor routes", halo, []autotaskBillingRoute{other}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := json.Marshal(tc.autotask)
			if err != nil {
				t.Fatal(err)
			}
			worker, err := NewPSASync(PSAConfigurations{Halo: tc.halo, Autotask: raw}, &pgxpool.Pool{}, func() bool { return true }, nil, nil)
			if tc.want == "" {
				if err != nil || len(worker.routes) != 2 || worker.routes[1].vendor != "autotask" || worker.routes[1].tenant != other.Tenant {
					t.Fatal("the licensed worker did not register both scoped routes", err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tc.want) || strings.Contains(err.Error(), "fixture-value") {
				t.Fatal("ambiguous registration was accepted or credentials were shown", err)
			}
		})
	}
}
