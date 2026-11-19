// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.
// Production use requires a valid commercial agreement; resale additionally
// requires an MSP entitlement and reseller agreement.

package provider

import (
	"net/http"

	"github.com/ctlplne/probectl/internal/reporting"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func (h *Handler) WithProspectReports(queue reporting.ProspectProviderQueue) *Handler {
	h.prospectReports = queue
	return h
}

func (h *Handler) handleProspectReportStatus(w http.ResponseWriter, r *http.Request, op Operator) error {
	tenant := r.PathValue("id")
	if h.prospectReports == nil || !canonicalReportID(tenant) {
		return ErrNotFound
	}
	data := h.providerAccessContext(r, "requested")
	if err := h.svc.RecordOperatorAccess(r.Context(), op.Email, "provider.prospect_status", tenant, data); err != nil {
		return err
	}
	result, err := h.prospectReports.Status(tenancy.WithTenant(r.Context(), tenancy.ID(tenant)), tenant)
	if err != nil {
		return ErrNotFound
	}
	return h.writeJSON(w, http.StatusOK, result)
}

func (h *Handler) handleRequestProspectReport(w http.ResponseWriter, r *http.Request, op Operator) error {
	tenant := r.PathValue("id")
	if h.prospectReports == nil || !canonicalReportID(tenant) {
		return ErrNotFound
	}
	if err := h.svc.CheckWritable(); err != nil {
		return err
	}
	var input reporting.ProspectProviderRequest
	if err := decode(r, &input); err != nil {
		return err
	}
	if !canonicalReportID(input.ID) || input.EngagementRevision < 1 || input.AccessRevision < 1 {
		return errValidation{"a canonical request UUID and both current revisions are required"}
	}
	data := h.providerAccessContext(r, "requested")
	data["prospect_request_id"] = input.ID
	if err := h.svc.RecordOperatorAccess(r.Context(), op.Email, "provider.prospect_assessment_requested", tenant, data); err != nil {
		return err
	}
	result, err := h.prospectReports.RequestAssessment(tenancy.WithTenant(r.Context(), tenancy.ID(tenant)), tenant, op.ID, input)
	if err != nil {
		return ErrNotFound
	}
	return h.writeJSON(w, http.StatusAccepted, result)
}
