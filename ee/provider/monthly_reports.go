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

// WithMonthlyReports attaches only the core's tenant-consented metadata queue.
// It has no report reader, download or source-query method.
func (h *Handler) WithMonthlyReports(queue reporting.MonthlyReportQueue) *Handler {
	h.monthlyReports = queue
	return h
}

func (h *Handler) handleMonthlyReports(w http.ResponseWriter, r *http.Request, op Operator) error {
	if h.monthlyReports == nil {
		return ErrNotFound
	}
	if err := h.svc.CheckWritable(); err != nil {
		return err
	}
	var input struct {
		RequestID string `json:"request_id"`
	}
	if err := decode(r, &input); err != nil {
		return err
	}
	tenant := r.PathValue("id")
	if !canonicalReportID(tenant) || !canonicalReportID(input.RequestID) {
		return errValidation{"canonical tenant and request UUIDs are required"}
	}
	if err := h.svc.RecordOperatorAccess(r.Context(), op.Email, "provider.monthly_reports_requested", tenant, map[string]any{"request_id": input.RequestID}); err != nil {
		return err
	}
	result, err := h.monthlyReports.QueueMonthlyReports(tenancy.WithTenant(r.Context(), tenancy.ID(tenant)), tenant, op.ID, input.RequestID)
	if err != nil {
		// Operational failure only; never echo a core/source exception or payload.
		h.log.Warn("provider monthly report queue unavailable", "tenant_id", tenant, "request_id", input.RequestID)
		return h.writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": map[string]string{"code": "report_queue_unavailable", "message": "tenant report queue is unavailable; retry the same request ID"}})
	}
	return h.writeJSON(w, http.StatusAccepted, result)
}

func canonicalReportID(value string) bool {
	if len(value) != 36 {
		return false
	}
	nonzero := false
	for i, ch := range value {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if ch != '-' {
				return false
			}
			continue
		}
		if ch >= '1' && ch <= '9' || ch >= 'a' && ch <= 'f' {
			nonzero = true
		}
		if (ch < '0' || ch > '9') && (ch < 'a' || ch > 'f') {
			return false
		}
	}
	return nonzero
}

func (h *Handler) handleMonthlyReportProgress(w http.ResponseWriter, r *http.Request, op Operator) error {
	if h.monthlyReports == nil {
		return ErrNotFound
	}
	tenant, requestID := r.PathValue("id"), r.PathValue("request_id")
	if !canonicalReportID(tenant) || !canonicalReportID(requestID) {
		return errValidation{"canonical tenant and request UUIDs are required"}
	}
	if err := h.svc.RecordOperatorAccess(r.Context(), op.Email, "provider.monthly_reports_progress", tenant, map[string]any{"request_id": requestID}); err != nil {
		return err
	}
	result, err := h.monthlyReports.MonthlyReportProgress(tenancy.WithTenant(r.Context(), tenancy.ID(tenant)), tenant, op.ID, requestID)
	if err != nil {
		return ErrNotFound
	}
	return h.writeJSON(w, http.StatusOK, result)
}
