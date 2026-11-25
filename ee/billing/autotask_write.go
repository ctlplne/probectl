// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.
// Production use requires a valid commercial agreement; resale additionally
// requires an MSP entitlement and reseller agreement.

package billing

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/ctlplne/probectl/internal/notify"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type autotaskBillingRoute struct {
	Tenant string `json:"tenant_id"`
	Zone   string `json:"zone_url"`
	AutotaskContractMapping
	notify.AutotaskCredentials
}

func (s *PSASync) addAutotaskRoutes(mappings []autotaskBillingRoute, tenants map[string]bool, client notify.Doer) error {
	type service struct {
		instance string
		key      autotaskAdjustmentKey
	}
	used := map[service]bool{}
	for i, mapping := range mappings {
		if err := validateBillingTenant(mapping.Tenant, tenants); err != nil {
			return fmt.Errorf("billing: Autotask route %d: %w", i+1, err)
		}
		reader, err := NewAutotaskBillingReader(mapping.Tenant, mapping.Zone, mapping.AutotaskContractMapping, mapping.AutotaskCredentials, client)
		if err != nil {
			return fmt.Errorf("billing: Autotask route %d: %w", i+1, err)
		}
		instance, err := psaOriginKey(mapping.Zone)
		if err != nil {
			return fmt.Errorf("billing: Autotask route %d: %w", i+1, err)
		}
		for _, id := range []int64{mapping.DevicesServiceID, mapping.AgentsServiceID} {
			target := service{instance, autotaskAdjustmentKey{mapping.CompanyID, mapping.ContractID, id}}
			if used[target] {
				return fmt.Errorf("billing: Autotask route %d reuses a contract service", i+1)
			}
			used[target] = true
		}
		tenants[mapping.Tenant] = true
		s.routes = append(s.routes, psaBillingRoute{tenant: mapping.Tenant, vendor: "autotask", run: func(ctx context.Context) error {
			return s.syncAutotask(ctx, reader)
		}})
	}
	return nil
}

var errAutotaskAdjustmentUnconfirmed = errors.New("billing: Autotask adjustment is pending service-unit confirmation")

// syncAutotask reconciles the two independent, existing contract service
// lines. An unresolved adjustment on one cannot authorize another send on
// that line or suppress reconciliation of the sibling line.
func (s *PSASync) syncAutotask(ctx context.Context, r *AutotaskBillingReader) error {
	if err := s.checkWrite(ctx); err != nil {
		return err
	}
	ctx = tenancy.WithTenant(ctx, tenancy.ID(r.tenant))
	devicesErr := s.syncAutotaskService(ctx, r, r.mapping.DevicesServiceID)
	agentsErr := s.syncAutotaskService(ctx, r, r.mapping.AgentsServiceID)
	return errors.Join(devicesErr, agentsErr)
}

func (s *PSASync) syncAutotaskService(ctx context.Context, r *AutotaskBillingReader, serviceID int64) error {
	key := autotaskAdjustmentKey{r.mapping.CompanyID, r.mapping.ContractID, serviceID}
	journal := autotaskAdjustmentJournal{pool: s.pool}
	fresh := autotaskAdjustment{Key: key, EffectiveAt: time.Now().UTC().Truncate(time.Second)}
	var pending *pendingAutotaskAdjustment
	err := s.withEgress(ctx, func(ctx context.Context, scope tenancy.Scope) error {
		var err error
		pending, err = readAutotaskAdjustment(ctx, scope, key)
		if err != nil {
			return err
		}
		if pending != nil {
			actual, err := r.readServiceUnits(ctx, scope.Tenant.String(), serviceID, pending.EffectiveAt)
			if err != nil {
				return err
			}
			if actual != pending.Desired {
				return errAutotaskAdjustmentUnconfirmed
			}
			return nil
		}
		counts, err := psaInventory(ctx, scope)
		if err != nil {
			return err
		}
		fresh.Desired = r.serviceQuantity(serviceID, counts)
		fresh.Previous, err = r.readServiceUnits(ctx, scope.Tenant.String(), serviceID, fresh.EffectiveAt)
		return err
	})
	if err != nil {
		return err
	}
	if pending != nil {
		_, err := journal.resolve(ctx, *pending, autotaskQuantityObserved)
		return err
	}
	if fresh.Previous == fresh.Desired {
		return nil
	}
	claim, err := journal.reserve(ctx, fresh)
	if errors.Is(err, errAutotaskAdjustmentPending) {
		return errAutotaskAdjustmentUnconfirmed
	}
	if err != nil {
		return err
	}
	return s.sendAutotaskAdjustment(ctx, r, journal, *claim)
}

func (s *PSASync) sendAutotaskAdjustment(ctx context.Context, r *AutotaskBillingReader, journal autotaskAdjustmentJournal, claim pendingAutotaskAdjustment) error {
	// Only a claim freshly persisted by this operation enters this function.
	// After any possible send, a restart or retry goes through readback instead.
	resolution := autotaskAdjustmentUnsent
	serviceID := claim.Key.ContractServiceID
	err := s.withEgress(ctx, func(ctx context.Context, scope tenancy.Scope) error {
		pending, err := readAutotaskAdjustment(ctx, scope, claim.Key)
		if err != nil || pending == nil || pending.Sequence != claim.Sequence {
			return err
		}
		counts, err := psaInventory(ctx, scope)
		if err != nil {
			return err
		}
		if r.serviceQuantity(serviceID, counts) != claim.Desired {
			return errPSAInventoryChanged
		}
		actual, err := r.readServiceUnits(ctx, scope.Tenant.String(), serviceID, claim.EffectiveAt)
		if err != nil {
			return err
		}
		if actual == claim.Desired {
			resolution = autotaskQuantityObserved
			return nil
		}
		if actual != claim.Previous {
			return errors.New("billing: Autotask units changed before the adjustment")
		}
		if err := tenancy.RequireTenantCollection(ctx, scope); err != nil {
			return err
		}
		if err := s.checkWrite(ctx); err != nil {
			return err
		}
		resolution = ""
		if err := r.createAdjustment(ctx, claim); err != nil {
			return err
		}
		actual, err = r.readServiceUnits(ctx, scope.Tenant.String(), serviceID, claim.EffectiveAt)
		if err != nil {
			return err
		}
		if actual != claim.Desired {
			return errAutotaskAdjustmentUnconfirmed
		}
		resolution = autotaskQuantityObserved
		return nil
	})
	if resolution == "" {
		return err
	}
	_, closeErr := journal.resolve(ctx, claim, resolution)
	return errors.Join(err, closeErr)
}

func (r *AutotaskBillingReader) serviceQuantity(serviceID int64, counts PSAQuantities) int64 {
	if serviceID == r.mapping.DevicesServiceID {
		return counts.Devices
	}
	return counts.Agents
}

func (r *AutotaskBillingReader) createAdjustment(ctx context.Context, claim pendingAutotaskAdjustment) error {
	key := claim.Key
	if claim.Tenant.String() != r.tenant || claim.Sequence <= 0 ||
		key.CompanyID != r.mapping.CompanyID || key.ContractID != r.mapping.ContractID ||
		(key.ContractServiceID != r.mapping.DevicesServiceID && key.ContractServiceID != r.mapping.AgentsServiceID) {
		return errInvalidAutotaskAdjustment
	}
	delta, err := claim.delta()
	if err != nil {
		return err
	}
	payload := struct {
		ServiceID   int64     `json:"contractServiceID"`
		EffectiveAt time.Time `json:"effectiveDate"`
		UnitChange  int64     `json:"unitChange"`
	}{ServiceID: key.ContractServiceID, EffectiveAt: claim.EffectiveAt, UnitChange: delta}
	_, err = r.api.Create(ctx, "ContractServiceAdjustments", payload)
	return err
}
