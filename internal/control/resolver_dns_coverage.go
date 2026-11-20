// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/ctlplne/probectl/internal/ai"
	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/threat/dnstap"
)

func (s *Server) handleResolverDNSCoverage(w http.ResponseWriter, r *http.Request) error {
	tenant, err := s.principalTenant(r)
	if err != nil {
		return err
	}
	query := r.URL.Query()
	minutes := 10
	if value := query.Get("minutes"); value != "" {
		minutes, err = strconv.Atoi(value)
	}
	source, agent := query.Get("source_ref"), query.Get("agent_id")
	if err != nil || minutes < 1 || minutes > 120 || !reportRequirementUUID(agent) || !dnstap.ValidSourceRef(source) {
		return apierror.BadRequest("select an exact resolver source and from 1 to 120 completed minutes")
	}
	scope := entity.Scope{TenantID: tenant, ContextID: query.Get("context_id")}
	ctx := tenancy.WithTenant(r.Context(), tenancy.ID(tenant))
	registry := store.NewEntityRegistry(s.pool)
	record, err := registry.GetEntity(ctx, scope, r.PathValue("id"))
	if err != nil {
		return entityAPIError(err)
	}
	resource, err := s.entityResource(ctx, record.Scope)
	if err != nil {
		return err
	}
	principal := auth.PrincipalFrom(r.Context())
	for _, permission := range []string{ai.PermEntitiesRead, permMetricsRead} {
		if err := s.authorize(ctx, principal, permission, auth.RBACGlobal, resource); err != nil {
			return err
		}
	}
	coverage, err := registry.ReadResolverDNSCoverage(ctx, record.Scope, record.ID, agent, source, minutes)
	if errors.Is(err, store.ErrResolverDNSUnavailable) {
		return apierror.NotFound("current resolver source was not found")
	}
	if err != nil {
		return entityAPIError(err)
	}
	if err := s.pathAlertRequestCredential(r, principal)(ctx); err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, coverage)
	return nil
}
