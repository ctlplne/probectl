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
	"strconv"

	"github.com/jackc/pgx/v5"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tags"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type tagRuleInput struct {
	TagID       string `json:"tag_id"`
	TargetKind  string `json:"target_kind"`
	Match       string `json:"match_kind"`
	AddressSide string `json:"address_side"`
	CIDR        string `json:"cidr"`
	NamePattern string `json:"name_pattern"`
	SNMPField   string `json:"snmp_field"`
	SNMPValue   string `json:"snmp_value"`
	Value       string `json:"value"`
	Priority    int    `json:"priority"`
}

func (input tagRuleInput) rule(tenantID, contextID, id string) tags.Rule {
	return tags.Rule{Scope: tags.Scope{TenantID: tenantID, ContextID: contextID},
		ID: id, TagID: input.TagID, TargetKind: input.TargetKind, Match: input.Match,
		AddressSide: input.AddressSide, CIDR: input.CIDR, NamePattern: input.NamePattern,
		SNMPField: input.SNMPField, SNMPValue: input.SNMPValue,
		Value: input.Value, Priority: input.Priority}
}

// A context-qualified read/write does a second resource-aware authorization
// after the route-level permission check. This keeps context ABAC effective.
func (s *Server) authorizeTagContext(r *http.Request, contextID, permission string) (string, error) {
	tenantID, err := s.principalTenant(r)
	if err != nil {
		return "", err
	}
	scope, err := (entity.Scope{TenantID: tenantID, ContextID: contextID}).Normalize()
	if err != nil {
		return "", entityAPIError(err)
	}
	resource, err := s.entityResource(tenancy.WithTenant(r.Context(), tenancy.ID(tenantID)), scope)
	if err != nil {
		return "", err
	}
	if err := s.authorize(r.Context(), auth.PrincipalFrom(r.Context()), permission,
		auth.RBACGlobal, resource); err != nil {
		return "", err
	}
	return tenantID, nil
}

func (s *Server) handleListTagRules(w http.ResponseWriter, r *http.Request) error {
	contextID := r.PathValue("context_id")
	if _, err := s.authorizeTagContext(r, contextID, permTagsRead); err != nil {
		return err
	}
	limit := 50
	if raw := r.URL.Query().Get("limit"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > 100 {
			return apierror.BadRequest("tag rule limit must be between 1 and 100")
		}
		limit = parsed
	}
	cursor := r.URL.Query().Get("cursor")
	var items []tags.Rule
	var next string
	err := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
		var err error
		items, next, err = (store.TagRules{}).List(ctx, sc, contextID, cursor, limit)
		return err
	})
	if err != nil {
		return tagRuleAPIError(err)
	}
	page := map[string]any{"items": items}
	if next != "" {
		page["next_cursor"] = next
	}
	writeJSON(w, http.StatusOK, page)
	return nil
}

func (s *Server) handleCreateTagRule(w http.ResponseWriter, r *http.Request) error {
	contextID := r.PathValue("context_id")
	if _, err := s.authorizeTagContext(r, contextID, permTagsWrite); err != nil {
		return err
	}
	var input tagRuleInput
	if err := decodeJSONLimit(r, tags.MaxValueInputBytes, &input); err != nil {
		return err
	}
	item, err := s.mutateTagRule(r, tagCreate, contextID, "", input)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusCreated, item)
	return nil
}

func (s *Server) handleUpdateTagRule(w http.ResponseWriter, r *http.Request) error {
	contextID := r.PathValue("context_id")
	if _, err := s.authorizeTagContext(r, contextID, permTagsWrite); err != nil {
		return err
	}
	var input tagRuleInput
	if err := decodeJSONLimit(r, tags.MaxValueInputBytes, &input); err != nil {
		return err
	}
	item, err := s.mutateTagRule(r, tagUpdate, contextID, r.PathValue("id"), input)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, item)
	return nil
}

func (s *Server) handleDeleteTagRule(w http.ResponseWriter, r *http.Request) error {
	if _, err := s.mutateTagRule(r, tagDelete, r.PathValue("context_id"), r.PathValue("id"), tagRuleInput{}); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func tagRuleAPIError(err error) error {
	switch {
	case errors.Is(err, tags.ErrInvalid):
		return apierror.BadRequest("invalid tag rule or tenant rule quota reached")
	case errors.Is(err, tags.ErrScopeMismatch):
		return apierror.BadRequest("invalid tenant routing context")
	case errors.Is(err, store.ErrTagReference), errors.Is(err, pgx.ErrNoRows):
		return apierror.NotFound("tag rule, key or routing context does not exist in this tenant")
	case errors.Is(err, tags.ErrConflict):
		return apierror.Conflict("tag rule conflicts with an existing rule")
	default:
		return err
	}
}
