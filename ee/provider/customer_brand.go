// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.
// Production use requires a valid commercial agreement; resale additionally
// requires an MSP entitlement and reseller agreement.

package provider

import (
	"context"
	"errors"
	"net/http"
	"strconv"

	"github.com/ctlplne/probectl/ee/whitelabel"
)

var errBrandPreconditionRequired = errors.New("brand If-Match revision is required")

type brandMutationStore interface {
	replaceBrand(context.Context, string, string, int64, whitelabel.Brand) (int64, error)
}

func (h *Handler) withCustomerBrands(store *whitelabel.Store) *Handler {
	h.brands = store
	return h
}

func (s *PGStore) replaceBrand(ctx context.Context, tenantID, actor string, expected int64,
	brand whitelabel.Brand) (int64, error) {
	if s.q == nil {
		return 0, errors.New("branding write requires the provider audit transaction")
	}
	return whitelabel.Replace(ctx, s.q, tenantID, actor, expected, brand)
}

func (h *Handler) handleReadBrand(w http.ResponseWriter, r *http.Request, op Operator) error {
	if h.brands == nil {
		return ErrNotFound
	}
	tenantID := r.PathValue("id")
	brand, revision, err := h.brands.ReadAdmin(r.Context(), tenantID)
	if err != nil {
		return err
	}
	if err := h.svc.RecordOperatorAccess(r.Context(), op.Email, "provider.tenant_brand_read", tenantID,
		map[string]any{"revision": revision}); err != nil {
		return err
	}
	return h.writeBrand(w, brand, revision)
}

func (h *Handler) handleReplaceBrand(w http.ResponseWriter, r *http.Request, op Operator) error {
	if h.brands == nil {
		return ErrNotFound
	}
	if err := h.svc.writable(); err != nil {
		return err
	}
	match := r.Header.Get("If-Match")
	if match == "" {
		return errBrandPreconditionRequired
	}
	if len(match) < 3 || match[0] != '"' || match[len(match)-1] != '"' {
		return validationError("If-Match must contain a quoted brand revision")
	}
	expected, err := strconv.ParseInt(match[1:len(match)-1], 10, 64)
	if err != nil || expected < 0 || revisionTag(expected) != match {
		return validationError("If-Match must contain a quoted brand revision")
	}
	var requested whitelabel.Brand
	if err := decode(r, &requested); err != nil {
		return err
	}
	brand, err := h.brands.Validate(requested)
	if err != nil {
		return validationError(err.Error())
	}
	tenantID := r.PathValue("id")
	var revision int64
	err = h.svc.store.WithAuditedMutation(r.Context(), h.svc.audit,
		func(ctx context.Context, store MutationStore, audit AuditSink) error {
			writer, ok := store.(brandMutationStore)
			if !ok {
				return errors.New("branding requires transactional provider storage")
			}
			var err error
			revision, err = writer.replaceBrand(ctx, tenantID, op.Email, expected, brand)
			if err != nil {
				return err
			}
			return audit.Append(ctx, op.Email, "provider.tenant_brand_replaced", tenantID, map[string]any{
				"revision": revision, "has_logo": brand.LogoDataURI != "", "has_domain": brand.Domain != "",
			})
		})
	if err != nil {
		return err
	}
	return h.writeBrand(w, brand, revision)
}

func (h *Handler) writeBrand(w http.ResponseWriter, brand whitelabel.Brand, revision int64) error {
	w.Header().Set("Cache-Control", "private, no-store")
	w.Header().Set("ETag", revisionTag(revision))
	return h.writeJSON(w, http.StatusOK, brand)
}

func revisionTag(revision int64) string {
	return `"` + strconv.FormatInt(revision, 10) + `"`
}
