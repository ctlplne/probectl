// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"errors"
	"net/http"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// Administrative writes require agent.write at the route. The
// authenticated principal selects the tenant before any SQL; FORCE RLS and
// compound FKs are the outer boundary. Each audit append shares the write
// transaction so a failed audit rolls the registry mutation back.
func (s *Server) handleCreateEntityContext(w http.ResponseWriter, r *http.Request) error {
	var req struct {
		SiteLabel string `json:"site_label"`
		VRFLabel  string `json:"vrf_label"`
	}
	if err := decodeJSONLimit(r, 8<<10, &req); err != nil {
		return err
	}
	tid, err := s.principalTenant(r)
	if err != nil {
		return err
	}
	attributes, err := store.EntityContextAttributes(tid, req.SiteLabel, req.VRFLabel)
	if err != nil {
		return entityAdminError(err)
	}
	if err := s.authorize(r.Context(), auth.PrincipalFrom(r.Context()), permAgentWrite,
		auth.RBACGlobal, entityContextResource(attributes)); err != nil {
		return err
	}
	var out entity.ContextRecord
	err = s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
		var err error
		out, err = store.NewEntityRegistry(s.pool).CreateEntityContext(ctx, sc,
			req.SiteLabel, req.VRFLabel)
		if err != nil {
			return err
		}
		return s.recordAudit(ctx, sc, r, "entity.context.created", out.ContextID,
			map[string]any{"site_id": out.SiteID, "vrf_id": out.VRFID,
				"site_label": out.SiteLabel, "vrf_label": out.VRFLabel})
	})
	if err != nil {
		return entityAdminError(err)
	}
	writeJSON(w, http.StatusCreated, out)
	return nil
}

func (s *Server) handleCreateCanonicalEntity(w http.ResponseWriter, r *http.Request) error {
	var req struct {
		ContextID     string      `json:"context_id"`
		Kind          entity.Kind `json:"kind"`
		Label         string      `json:"label"`
		NetworkPrefix string      `json:"network_prefix,omitempty"`
	}
	if err := decodeJSONLimit(r, 8<<10, &req); err != nil {
		return err
	}
	if err := s.authorizeEntityWriteContext(r, req.ContextID); err != nil {
		return err
	}
	var record entity.Record
	err := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
		var err error
		record, err = store.NewEntityRegistry(s.pool).CreateCanonicalEntityWithNetwork(ctx, sc,
			req.ContextID, req.Kind, req.Label, req.NetworkPrefix)
		if err != nil {
			return err
		}
		return s.recordAudit(ctx, sc, r, "entity.created", record.ID,
			map[string]any{"context_id": record.Scope.ContextID, "kind": record.Kind})
	})
	if err != nil {
		return entityAdminError(err)
	}
	writeJSON(w, http.StatusCreated, record)
	return nil
}

func (s *Server) handleSetEntityNetworkPrefix(w http.ResponseWriter, r *http.Request) error {
	var req struct {
		ContextID     string  `json:"context_id"`
		NetworkPrefix *string `json:"network_prefix"`
	}
	if err := decodeJSONLimit(r, 8<<10, &req); err != nil {
		return err
	}
	if req.NetworkPrefix == nil {
		return apierror.BadRequest("network_prefix is required; an empty string clears it")
	}
	if err := s.authorizeEntityWriteContext(r, req.ContextID); err != nil {
		return err
	}
	var record entity.Record
	err := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
		var err error
		record, err = store.NewEntityRegistry(s.pool).SetEntityNetworkPrefix(ctx, sc, req.ContextID, r.PathValue("id"), *req.NetworkPrefix)
		if err != nil {
			return err
		}
		return s.recordAudit(ctx, sc, r, "entity.network_prefix.updated", record.ID,
			map[string]any{"context_id": record.Scope.ContextID, "network_configured": record.NetworkPrefix != ""})
	})
	if err != nil {
		return entityAdminError(err)
	}
	writeJSON(w, http.StatusOK, record)
	return nil
}

func (s *Server) handleAssignEntitySource(w http.ResponseWriter, r *http.Request) error {
	var req struct {
		AgentID        string            `json:"agent_id"`
		SourceKind     entity.SourceKind `json:"source_kind"`
		SourceRef      string            `json:"source_ref"`
		ContextID      string            `json:"context_id"`
		AnchorEntityID string            `json:"anchor_entity_id,omitempty"`
	}
	if err := decodeJSONLimit(r, 8<<10, &req); err != nil {
		return err
	}
	if err := s.authorizeEntityWriteContext(r, req.ContextID); err != nil {
		return err
	}
	err := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
		if err := store.NewEntityRegistry(s.pool).AssignEntitySource(ctx, sc,
			entity.SourceKey{AgentID: req.AgentID, Kind: req.SourceKind,
				SourceRef: req.SourceRef}, req.ContextID, req.AnchorEntityID); err != nil {
			return err
		}
		return s.recordAudit(ctx, sc, r, "entity.source.assigned", req.AgentID,
			map[string]any{"source_kind": req.SourceKind, "source_ref": req.SourceRef,
				"context_id": req.ContextID, "anchor_entity_id": req.AnchorEntityID})
	})
	if err != nil {
		return entityAdminError(err)
	}
	writeJSON(w, http.StatusOK, req)
	return nil
}

// The current path engine runs in the control plane. An operator assigns the
// test's routing context; a hop's untrusted IP never selects one.
func (s *Server) handleAssignPathTestContext(w http.ResponseWriter, r *http.Request) error {
	var req struct {
		ContextID string `json:"context_id"`
	}
	if err := decodeJSONLimit(r, 8<<10, &req); err != nil {
		return err
	}
	if err := s.authorizeEntityWriteContext(r, req.ContextID); err != nil {
		return err
	}
	testID := r.PathValue("id")
	err := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
		if err := store.NewEntityRegistry(s.pool).AssignPathTestContext(ctx, sc, testID, req.ContextID); err != nil {
			return err
		}
		return s.recordAudit(ctx, sc, r, "entity.path_context.assigned", testID,
			map[string]any{"context_id": req.ContextID})
	})
	if err != nil {
		return entityAdminError(err)
	}
	writeJSON(w, http.StatusOK, map[string]string{"test_id": testID, "context_id": req.ContextID})
	return nil
}

func (s *Server) authorizeEntityWriteContext(r *http.Request, contextID string) error {
	tid, err := s.principalTenant(r)
	if err != nil {
		return err
	}
	scope, err := (entity.Scope{TenantID: tid, ContextID: contextID}).Normalize()
	if err != nil {
		return entityAPIError(err)
	}
	resource, err := s.entityResource(tenancy.WithTenant(r.Context(), tenancy.ID(tid)), scope)
	if err != nil {
		return err
	}
	return s.authorize(r.Context(), auth.PrincipalFrom(r.Context()), permAgentWrite,
		auth.RBACGlobal, resource)
}

func entityAdminError(err error) error {
	var pgErr *pgconn.PgError
	switch {
	case errors.Is(err, entity.ErrInvalidScope), errors.Is(err, entity.ErrInvalidClaim),
		errors.Is(err, entity.ErrInvalidSource):
		return apierror.BadRequest("invalid entity registry input")
	case errors.Is(err, store.ErrEntityAgentNotRegistered):
		return apierror.NotFound("source agent is not registered in this tenant")
	case errors.Is(err, entity.ErrScopeMismatch):
		return apierror.Conflict("entity source, anchor or context is not assignable")
	case errors.Is(err, store.ErrEntityRegistryUnavailable):
		return apierror.Unavailable("entity registry is not configured")
	case errors.Is(err, pgx.ErrNoRows):
		return apierror.NotFound("entity does not exist in this tenant and context")
	case errors.As(err, &pgErr) && pgErr.Code == "23505":
		if pgErr.ConstraintName == "entity_path_target_one_context" {
			return apierror.Conflict("path destination is already bound to a routing context in this tenant")
		}
		return apierror.Conflict("entity context already exists")
	case errors.As(err, &pgErr) && pgErr.Code == "23503":
		return apierror.BadRequest("entity context or anchor does not exist in this tenant")
	default:
		return err
	}
}
