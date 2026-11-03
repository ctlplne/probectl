// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"net/http"

	"github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tags"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type tagMutationAction string

const (
	tagCreate tagMutationAction = "create"
	tagUpdate tagMutationAction = "update"
	tagDelete tagMutationAction = "delete"
)

func validateTagMutation(action tagMutationAction, id string) error {
	switch action {
	case tagCreate:
		if id == "" {
			return nil
		}
	case tagUpdate, tagDelete:
		if parsed, err := uuid.Parse(id); err == nil && parsed != uuid.Nil {
			return nil
		}
	}
	return apierror.BadRequest("invalid tag mutation action or identifier")
}

// REST and user-only MCP share this authorization and write/audit path.
// The principal selects the tenant; no command carries a tenant selector.
func (s *Server) authorizeTagMutation(r *http.Request, contextID string) (string, error) {
	tenantID, err := s.principalTenant(r)
	if err != nil || tenantID == "" {
		return "", apierror.Unauthorized("tenant identity is required")
	}
	p := auth.PrincipalFrom(r.Context())
	if err := s.checkTenantLifecycle(r, tenantID); err != nil {
		return "", err
	}
	if s.requireMFA && !p.MFASatisfied {
		return "", apierror.Forbidden("multi-factor authentication required")
	}
	if err := s.authorize(r.Context(), p, permTagsWrite, auth.RBACGlobal, nil); err != nil {
		return "", err
	}
	if s.pool == nil {
		return "", apierror.Unavailable("tag metadata store is unavailable")
	}
	if contextID != "" {
		return s.authorizeTagContext(r, contextID, permTagsWrite)
	}
	return tenantID, nil
}

func (s *Server) mutateTagDefinition(r *http.Request, action tagMutationAction, id, key string) (tags.Definition, error) {
	if err := validateTagMutation(action, id); err != nil {
		return tags.Definition{}, err
	}
	if _, err := s.authorizeTagMutation(r, ""); err != nil {
		return tags.Definition{}, err
	}
	var item tags.Definition
	err := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
		var err error
		event := ""
		var data map[string]any
		switch action {
		case tagCreate:
			item, err = (store.TagDefinitions{}).Create(ctx, sc, key)
			event = "tag.definition.created"
		case tagUpdate:
			item, err = (store.TagDefinitions{}).Rename(ctx, sc, id, key)
			event = "tag.definition.renamed"
		case tagDelete:
			err = (store.TagDefinitions{}).Delete(ctx, sc, id)
			item = tags.Definition{TenantID: sc.Tenant.String(), ID: id}
			event = "tag.definition.deleted"
		}
		if err != nil {
			return err
		}
		if action != tagDelete {
			data = map[string]any{"key": item.Key}
		}
		return s.recordAudit(ctx, sc, r, event, item.ID, data)
	})
	if err != nil {
		return tags.Definition{}, tagDefinitionAPIError(err)
	}
	return item, nil
}

func (s *Server) mutateTagRule(r *http.Request, action tagMutationAction, contextID, id string, input tagRuleInput) (tags.Rule, error) {
	if err := validateTagMutation(action, id); err != nil {
		return tags.Rule{}, err
	}
	if contextID == "" {
		return tags.Rule{}, tagRuleAPIError(tags.ErrScopeMismatch)
	}
	tenantID, err := s.authorizeTagMutation(r, contextID)
	if err != nil {
		return tags.Rule{}, err
	}
	var item tags.Rule
	err = s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
		var err error
		event := ""
		data := map[string]any{"context_id": contextID}
		switch action {
		case tagCreate:
			item, err = (store.TagRules{}).Create(ctx, sc, input.rule(tenantID, contextID, ""))
			event = "tag.rule.created"
		case tagUpdate:
			item, err = (store.TagRules{}).Update(ctx, sc, input.rule(tenantID, contextID, id))
			event = "tag.rule.updated"
		case tagDelete:
			err = (store.TagRules{}).Delete(ctx, sc, contextID, id)
			item = tags.Rule{Scope: tags.Scope{TenantID: tenantID, ContextID: contextID}, ID: id}
			event = "tag.rule.deleted"
		}
		if err != nil {
			return err
		}
		if action != tagDelete {
			data["tag_id"], data["match_kind"] = item.TagID, item.Match
		}
		return s.recordAudit(ctx, sc, r, event, item.ID, data)
	})
	if err != nil {
		return tags.Rule{}, tagRuleAPIError(err)
	}
	return item, nil
}

func (s *Server) mutateManualTagAssignment(r *http.Request, action tagMutationAction, contextID, id string, input manualTagAssignmentRequest) (store.TagAssignmentRecord, error) {
	if err := validateTagMutation(action, id); err != nil {
		return store.TagAssignmentRecord{}, err
	}
	if contextID == "" {
		return store.TagAssignmentRecord{}, tagAssignmentAPIError(tags.ErrScopeMismatch)
	}
	tenantID, err := s.authorizeTagMutation(r, contextID)
	if err != nil {
		return store.TagAssignmentRecord{}, err
	}
	var item store.TagAssignmentRecord
	err = s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
		var err error
		event := ""
		data := map[string]any{"context_id": contextID}
		switch action {
		case tagCreate:
			item, err = (store.TagAssignments{}).CreateManual(ctx, sc, input.storeInput(tenantID, contextID))
			event = "tag.assignment.created"
		case tagUpdate:
			item, err = (store.TagAssignments{}).UpdateManual(ctx, sc, id, input.storeInput(tenantID, contextID))
			event = "tag.assignment.updated"
		case tagDelete:
			err = (store.TagAssignments{}).DeleteManual(ctx, sc, contextID, id)
			item.ID = id
			event = "tag.assignment.deleted"
		}
		if err != nil {
			return err
		}
		if action != tagDelete {
			data["tag_id"], data["target_kind"], data["target_id"] = item.TagID, item.TargetKind, item.TargetID
		}
		return s.recordAudit(ctx, sc, r, event, item.ID, data)
	})
	if err != nil {
		return store.TagAssignmentRecord{}, tagAssignmentAPIError(err)
	}
	return item, nil
}
