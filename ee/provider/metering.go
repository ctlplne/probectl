// probectl Commercial License — PLACEHOLDER (legal text TBD with counsel).

package provider

import (
	"net/http"
	"time"

	"github.com/imfeelingtheagi/probectl/ee/billing"
)

// The S-T3 metering surface on the provider plane: per-tenant usage/showback,
// the billing-export feed (generic CSV / JSON Lines — the ratified first
// target), and per-tenant quotas. Attached only when the license grants the
// metering feature; absent, these routes answer not_found (hidden).

// Metering bundles the billing capability for the handler.
type Metering struct {
	Store  billing.Store
	Quotas *billing.QuotaChecker // Invalidate on quota writes; nil OK
}

// usageWindow parses from/to with month-to-date defaults.
func usageWindow(r *http.Request, now time.Time) (time.Time, time.Time, error) {
	from := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	to := billing.PeriodStart(now).Add(billing.Period)
	if v := r.URL.Query().Get("from"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			return from, to, errBadJSON{err}
		}
		from = t.UTC()
	}
	if v := r.URL.Query().Get("to"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			return from, to, errBadJSON{err}
		}
		to = t.UTC()
	}
	return from, to, nil
}

func (h *Handler) usageRecords(r *http.Request) ([]billing.UsageRecord, error) {
	if h.metering == nil || h.metering.Store == nil {
		return nil, ErrNotFound // hidden-unlicensed: indistinguishable from an unknown route
	}
	from, to, err := usageWindow(r, h.svc.now())
	if err != nil {
		return nil, err
	}
	records, err := h.metering.Store.Query(r.Context(), from, to, r.URL.Query().Get("tenant_id"))
	if err != nil {
		return nil, err
	}
	rollup := r.URL.Query().Get("rollup")
	if rollup == "" {
		rollup = billing.RollupDay
	}
	if rollup != billing.RollupHour && rollup != billing.RollupDay {
		return nil, errBadJSON{strErr("rollup must be hour or day")}
	}
	return billing.Rollup(records, rollup), nil
}

func (h *Handler) handleUsage(w http.ResponseWriter, r *http.Request, _ Operator) error {
	records, err := h.usageRecords(r)
	if err != nil {
		return err
	}
	return h.writeJSON(w, http.StatusOK, map[string]any{
		"items":  records,
		"meters": billing.Meters(),
	})
}

func (h *Handler) handleUsageExport(w http.ResponseWriter, r *http.Request, _ Operator) error {
	records, err := h.usageRecords(r)
	if err != nil {
		return err
	}
	format := r.URL.Query().Get("format")
	switch format {
	case "", "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="probectl-usage.csv"`)
		return billing.WriteCSV(w, records)
	case "jsonl":
		w.Header().Set("Content-Type", "application/x-ndjson")
		w.Header().Set("Content-Disposition", `attachment; filename="probectl-usage.jsonl"`)
		return billing.WriteJSONL(w, records)
	default:
		return errBadJSON{strErr("format must be csv or jsonl")}
	}
}

func (h *Handler) handleGetQuotas(w http.ResponseWriter, r *http.Request, _ Operator) error {
	if h.metering == nil || h.metering.Store == nil {
		return ErrNotFound
	}
	q, err := h.metering.Store.QuotaFor(r.Context(), r.PathValue("id"))
	if err != nil {
		return err
	}
	return h.writeJSON(w, http.StatusOK, q)
}

func (h *Handler) handlePutQuotas(w http.ResponseWriter, r *http.Request, op Operator) error {
	if h.metering == nil || h.metering.Store == nil {
		return ErrNotFound
	}
	if err := h.svc.CheckWritable(); err != nil {
		return err // read-only license degrade blocks quota writes too
	}
	var in struct {
		MaxAgents *int `json:"max_agents"`
		MaxTests  *int `json:"max_tests"`
	}
	if err := decode(r, &in); err != nil {
		return err
	}
	if (in.MaxAgents != nil && *in.MaxAgents < 0) || (in.MaxTests != nil && *in.MaxTests < 0) {
		return errBadJSON{errNegativeQuota}
	}
	tenantID := r.PathValue("id")
	q := billing.Quota{TenantID: tenantID, MaxAgents: in.MaxAgents, MaxTests: in.MaxTests, UpdatedBy: op.Email}
	if err := h.metering.Store.SetQuota(r.Context(), q); err != nil {
		return err
	}
	if h.metering.Quotas != nil {
		h.metering.Quotas.Invalidate(tenantID) // visible immediately
	}
	if err := h.svc.RecordQuotaChange(r.Context(), op.Email, tenantID, in.MaxAgents, in.MaxTests); err != nil {
		return err
	}
	return h.writeJSON(w, http.StatusOK, q)
}

var errNegativeQuota = strErr("quotas must be >= 0 (null = unlimited)")

type strErr string

func (e strErr) Error() string { return string(e) }

// meteringRoutes are appended to Routes() — kept here so the S-T3 surface
// stays in one file (the openapi parity test covers the union).
func meteringRoutes() []RouteDecl {
	return []RouteDecl{
		{http.MethodGet, "/provider/v1/usage"},
		{http.MethodGet, "/provider/v1/usage/export"},
		{http.MethodGet, "/provider/v1/tenants/{id}/quotas"},
		{http.MethodPut, "/provider/v1/tenants/{id}/quotas"},
	}
}
