// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.
// Production use requires a valid commercial agreement; resale additionally
// requires an MSP entitlement and reseller agreement.

package billing

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"strconv"
	"time"

	"github.com/ctlplne/probectl/internal/notify"
)

// AutotaskContractMapping names two existing recurring services in the same
// customer's contract. The IDs identify contract services, not catalog items.
type AutotaskContractMapping struct {
	CompanyID        int64 `json:"company_id"`
	ContractID       int64 `json:"contract_id"`
	RecurringType    int64 `json:"recurring_contract_type"`
	DevicesServiceID int64 `json:"devices_contract_service_id"`
	AgentsServiceID  int64 `json:"agents_contract_service_id"`
}

// AutotaskBillingReader verifies and reads the vendor state used to reconcile
// an additive adjustment. Each connection is bound to a single tenant.
type AutotaskBillingReader struct {
	tenant  string
	mapping AutotaskContractMapping
	api     *notify.AutotaskAPI
}

func NewAutotaskBillingReader(tenant, zone string, mapping AutotaskContractMapping, credentials notify.AutotaskCredentials, client notify.Doer) (*AutotaskBillingReader, error) {
	if tenant == "" || mapping.DevicesServiceID == mapping.AgentsServiceID {
		return nil, errors.New("billing: Autotask needs a tenant and two distinct contract services")
	}
	for _, id := range []int64{mapping.CompanyID, mapping.ContractID, mapping.RecurringType, mapping.DevicesServiceID, mapping.AgentsServiceID} {
		if id <= 0 || id > math.MaxInt32 {
			return nil, errors.New("billing: invalid Autotask company, contract, type or contract service")
		}
	}
	api, err := notify.NewAutotaskAPI(zone, credentials, client)
	if err != nil {
		return nil, err
	}
	return &AutotaskBillingReader{tenant: tenant, mapping: mapping, api: api}, nil
}

type autotaskBillingDate struct {
	time.Time
}

func (d *autotaskBillingDate) UnmarshalJSON(raw []byte) error {
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return err
	}
	// Autotask reports time data as UTC and also serializes UTC without
	// an offset. Keep explicit offsets when the API includes them.
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04:05", time.DateOnly} {
		parsed, err := time.Parse(layout, value)
		if err == nil {
			d.Time = parsed.UTC()
			return nil
		}
	}
	return errors.New("billing: invalid Autotask UTC date")
}

func autotaskDateContains(start, end autotaskBillingDate, asOf time.Time) bool {
	return !start.IsZero() && !end.IsZero() && !asOf.Before(start.Time) && !asOf.After(end.lastInstant())
}

func (d autotaskBillingDate) lastInstant() time.Time {
	// Autotask includes the last calendar day of a billing period. The
	// REST API can serialize a calendar date as a midnight UTC datetime.
	if d.Equal(d.Truncate(24 * time.Hour)) {
		return d.AddDate(0, 0, 1).Add(-time.Nanosecond)
	}
	return d.Time
}

type autotaskBillingContract struct {
	ID              int64               `json:"id"`
	CompanyID       int64               `json:"companyID"`
	BillToCompanyID int64               `json:"billToCompanyID"`
	Type            int64               `json:"contractType"`
	Start           autotaskBillingDate `json:"startDate"`
	End             autotaskBillingDate `json:"endDate"`
}

type autotaskContractService struct {
	ID         int64 `json:"id"`
	ContractID int64 `json:"contractID"`
	ProductID  int64 `json:"serviceID"`
}

type autotaskServiceUnits struct {
	ContractID        int64               `json:"contractID"`
	ContractServiceID int64               `json:"contractServiceID"`
	ProductID         int64               `json:"serviceID"`
	Units             *int64              `json:"units"`
	Start             autotaskBillingDate `json:"startDate"`
	End               autotaskBillingDate `json:"endDate"`
}

// readServiceUnits verifies the company, contract, and selected service for a
// fixed effective instant. Autotask omits zero-unit periods, so only a complete
// scoped query may treat an absent service row as zero.
func (r *AutotaskBillingReader) readServiceUnits(ctx context.Context, tenant string, serviceID int64, asOf time.Time) (int64, error) {
	if tenant != r.tenant || asOf.IsZero() {
		return 0, errors.New("billing: Autotask read requires the registered tenant and an effective instant")
	}
	m := r.mapping
	if serviceID != m.DevicesServiceID && serviceID != m.AgentsServiceID {
		return 0, errors.New("billing: Autotask service is outside the registered mapping")
	}
	var contract autotaskBillingContract
	if err := r.api.Get(ctx, &contract, "Contracts", strconv.FormatInt(m.ContractID, 10)); err != nil {
		return 0, err
	}
	if contract.ID != m.ContractID || contract.CompanyID != m.CompanyID || contract.Type != m.RecurringType ||
		(contract.BillToCompanyID != 0 && contract.BillToCompanyID != m.CompanyID) ||
		!autotaskDateContains(contract.Start, contract.End, asOf) {
		return 0, errors.New("billing: Autotask contract does not match the registered customer or billing period")
	}
	var service autotaskContractService
	if err := r.api.Get(ctx, &service, "ContractServices", strconv.FormatInt(serviceID, 10)); err != nil {
		return 0, err
	}
	if service.ID != serviceID || service.ContractID != m.ContractID || service.ProductID <= 0 {
		return 0, errors.New("billing: Autotask service is outside the registered contract")
	}

	at := asOf.UTC().Format(time.RFC3339Nano)
	dayStart := asOf.UTC().Truncate(24 * time.Hour)
	var items []autotaskServiceUnits
	err := r.api.Query(ctx, "ContractServiceUnits",
		[]string{"contractID", "contractServiceID", "serviceID", "units", "startDate", "endDate"},
		[]notify.AutotaskFilter{
			{Operator: "eq", Field: "contractID", Value: m.ContractID},
			{Operator: "in", Field: "contractServiceID", Value: []int64{serviceID}},
			{Operator: "lte", Field: "startDate", Value: at},
			// A calendar end date can arrive as midnight on the last billing
			// day. Keep these rows and check the actual end after decoding.
			{Operator: "gte", Field: "endDate", Value: dayStart.Format(time.RFC3339)},
		}, &items)
	if err != nil {
		return 0, err
	}
	return effectiveAutotaskUnits(items, service, dayStart, asOf)
}

func effectiveAutotaskUnits(items []autotaskServiceUnits, service autotaskContractService, dayStart, asOf time.Time) (int64, error) {
	var units *int64
	for _, item := range items {
		end := item.End.lastInstant()
		if item.ContractServiceID != service.ID || item.ContractID != service.ContractID ||
			item.ProductID != service.ProductID || item.Units == nil || *item.Units < 0 || *item.Units > math.MaxInt32 ||
			item.Start.IsZero() || item.Start.After(asOf) || item.End.IsZero() ||
			item.End.Before(dayStart) || end.Before(item.Start.Time) {
			return 0, errors.New("billing: unexpected Autotask contract service unit")
		}
		if asOf.After(end) {
			continue
		}
		if units != nil {
			return 0, errors.New("billing: overlapping Autotask contract service periods")
		}
		units = item.Units
	}
	if units == nil {
		return 0, nil
	}
	return *units, nil
}
