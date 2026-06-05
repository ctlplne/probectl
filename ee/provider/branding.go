// probectl Commercial License — PLACEHOLDER (legal text TBD with counsel).

package provider

import (
	"net/http"

	"github.com/imfeelingtheagi/probectl/ee/whitelabel"
)

// The S-T4 white-label surface on the provider plane: per-tenant brands and
// the provider master, configured by ADMINS (SoD: brand changes are
// commercial decisions), audited, blocked by the read-only license ladder,
// and hidden (not_found) when the white_label feature is unattached.

// WhiteLabel bundles the branding capability for the handler.
type WhiteLabel struct {
	Store      whitelabel.Store
	Invalidate func() // resolver cache drop on writes; nil OK
}

func (h *Handler) brandingStore() (whitelabel.Store, error) {
	if h.whitelabel == nil || h.whitelabel.Store == nil {
		return nil, ErrNotFound // hidden-unlicensed
	}
	return h.whitelabel.Store, nil
}

func (h *Handler) handleGetTenantBranding(w http.ResponseWriter, r *http.Request, _ Operator) error {
	st, err := h.brandingStore()
	if err != nil {
		return err
	}
	rec, err := st.TenantBrand(r.Context(), r.PathValue("id"))
	if err != nil {
		return err
	}
	if rec == nil {
		rec = &whitelabel.Record{TenantID: r.PathValue("id")}
	}
	return h.writeJSON(w, http.StatusOK, rec)
}

func (h *Handler) handlePutTenantBranding(w http.ResponseWriter, r *http.Request, op Operator) error {
	st, err := h.brandingStore()
	if err != nil {
		return err
	}
	if err := h.svc.CheckWritable(); err != nil {
		return err
	}
	var rec whitelabel.Record
	if err := decode(r, &rec); err != nil {
		return err
	}
	rec.TenantID = r.PathValue("id")
	rec.UpdatedBy = op.Email
	if err := rec.Validate(); err != nil {
		return errBadJSON{err}
	}
	if err := st.SetTenantBrand(r.Context(), rec); err != nil {
		return err
	}
	if h.whitelabel.Invalidate != nil {
		h.whitelabel.Invalidate()
	}
	if err := h.svc.RecordBrandingChange(r.Context(), op.Email, rec.TenantID, rec.CustomDomain); err != nil {
		return err
	}
	return h.writeJSON(w, http.StatusOK, rec)
}

func (h *Handler) handleGetProviderBranding(w http.ResponseWriter, r *http.Request, _ Operator) error {
	st, err := h.brandingStore()
	if err != nil {
		return err
	}
	rec, err := st.ProviderBrand(r.Context())
	if err != nil {
		return err
	}
	if rec == nil {
		rec = &whitelabel.Record{}
	}
	return h.writeJSON(w, http.StatusOK, rec)
}

func (h *Handler) handlePutProviderBranding(w http.ResponseWriter, r *http.Request, op Operator) error {
	st, err := h.brandingStore()
	if err != nil {
		return err
	}
	if err := h.svc.CheckWritable(); err != nil {
		return err
	}
	var rec whitelabel.Record
	if err := decode(r, &rec); err != nil {
		return err
	}
	rec.TenantID, rec.CustomDomain = "", "" // the master has no tenant/domain
	rec.UpdatedBy = op.Email
	if err := rec.Validate(); err != nil {
		return errBadJSON{err}
	}
	if err := st.SetProviderBrand(r.Context(), rec); err != nil {
		return err
	}
	if h.whitelabel.Invalidate != nil {
		h.whitelabel.Invalidate()
	}
	if err := h.svc.RecordBrandingChange(r.Context(), op.Email, "provider-master", ""); err != nil {
		return err
	}
	return h.writeJSON(w, http.StatusOK, rec)
}

// brandingRoutes are appended to Routes().
func brandingRoutes() []RouteDecl {
	return []RouteDecl{
		{http.MethodGet, "/provider/v1/tenants/{id}/branding"},
		{http.MethodPut, "/provider/v1/tenants/{id}/branding"},
		{http.MethodGet, "/provider/v1/branding"},
		{http.MethodPut, "/provider/v1/branding"},
	}
}
