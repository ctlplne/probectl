// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"strconv"
	"strings"
	"time"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/reporting"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func cleanCarrierSLAReportDefinition(d *dashboardDefinition) error {
	if d.CarrierClaim == nil {
		return nil
	}
	if d.ClientReport != nil || len(d.FlowSources) != 0 || !d.AbsoluteFrom.IsZero() || !d.AbsoluteTo.IsZero() || len(d.Metrics) != 0 {
		return apierror.Validation("carrier_claim derives recorded financial periods and original measurements; omit other report source modes, absolute bounds and metrics")
	}
	if len(d.CarrierClaim.Selections) == 0 {
		return apierror.Validation("carrier_claim requires explicit recorded agreement selections")
	}
	seen := map[reporting.CarrierSLAReportSelection]bool{}
	for _, selection := range d.CarrierClaim.Selections {
		revision, err := strconv.ParseInt(selection.Version, 10, 64)
		if !reportRequirementUUID(selection.AgreementID) || err != nil || revision <= 0 || strconv.FormatInt(revision, 10) != selection.Version || seen[selection] {
			return apierror.Validation("carrier_claim requires distinct canonical agreements and exact recorded revisions")
		}
		if selection.At != "" {
			if _, err := time.Parse(time.RFC3339Nano, selection.At); err != nil {
				return apierror.Validation("a selected financial period must use RFC3339 with timezone; omit it for the previous complete billing period")
			}
		}
		seen[selection] = true
	}
	return nil
}

func portableCarrierSLAReportDefinition(input *reporting.CarrierSLAReportDefinition) *reporting.CarrierSLAReportManifestDefinition {
	if input == nil {
		return nil
	}
	output := &reporting.CarrierSLAReportManifestDefinition{Selections: make([]reporting.CarrierSLAReportManifestSelection, 0, len(input.Selections))}
	slots := map[reporting.CarrierSLAReportAgreementBinding]string{}
	for _, selection := range input.Selections {
		binding := reporting.CarrierSLAReportAgreementBinding{AgreementID: selection.AgreementID, Version: selection.Version}
		slot, exists := slots[binding]
		if !exists {
			slot = "agreement-" + strconv.Itoa(len(slots)+1)
			slots[binding] = slot
		}
		output.Selections = append(output.Selections, reporting.CarrierSLAReportManifestSelection{Slot: slot, At: selection.At})
	}
	return output
}

func bindCarrierSLAReportManifest(input *reporting.CarrierSLAReportManifestDefinition, supplied []map[string]reporting.CarrierSLAReportAgreementBinding) (*reporting.CarrierSLAReportDefinition, error) {
	if len(supplied) > 1 {
		return nil, apierror.Validation("one complete agreement binding map is required")
	}
	bindings := map[string]reporting.CarrierSLAReportAgreementBinding{}
	if len(supplied) == 1 && supplied[0] != nil {
		bindings = supplied[0]
	}
	if input == nil {
		if len(bindings) != 0 {
			return nil, apierror.Validation("agreement_bindings requires a carrier_claim template")
		}
		return nil, nil
	}
	output := &reporting.CarrierSLAReportDefinition{Selections: make([]reporting.CarrierSLAReportSelection, 0, len(input.Selections))}
	used := map[string]bool{}
	for _, selection := range input.Selections {
		binding, exists := bindings[selection.Slot]
		if !exists || selection.Slot == "" || strings.TrimSpace(selection.Slot) != selection.Slot {
			return nil, apierror.Validation("every carrier_claim slot needs an explicit current-tenant agreement binding")
		}
		output.Selections = append(output.Selections, reporting.CarrierSLAReportSelection{AgreementID: binding.AgreementID, Version: binding.Version, At: selection.At})
		used[selection.Slot] = true
	}
	if len(used) != len(bindings) {
		return nil, apierror.Validation("agreement_bindings contains an unused financial slot")
	}
	return output, nil
}

// Selectors must be readable in this physical tenant before they become saved
// configuration. Actual measurements require independent source authorization.
func (s *Server) validateDashboardCarrierClaimRefs(ctx context.Context, sc tenancy.Scope, actor *auth.Principal, definition *reporting.CarrierSLAReportDefinition) error {
	if definition == nil {
		return nil
	}
	if actor == nil || s.cfg == nil || s.cfg.FlowQueryLibraryBytes <= 0 || actor.TenantID != sc.Tenant.String() {
		return errReportSourceRequirements
	}
	if err := s.authorizeCapacityAgreement(ctx, sc, actor, false); err != nil {
		return err
	}
	repository := s.capacityAgreementRepository(actor, flowstore.ExplorerQueryBudget(s.flowStore))
	for _, selection := range definition.Selections {
		if _, err := repository.CapacityAgreementInScope(ctx, sc, actor.UserID, selection.AgreementID, selection.Version, nil); err != nil {
			return err
		}
	}
	return ctx.Err()
}
