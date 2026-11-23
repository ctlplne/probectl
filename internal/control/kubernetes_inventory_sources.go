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

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

const (
	kubernetesSourcePath   = "/v1/entity-contexts/{context_id}/kubernetes-inventory-sources"
	kubernetesSourceIDPath = kubernetesSourcePath + "/{id}"
)

func (s *Server) handleCreateKubernetesInventorySource(w http.ResponseWriter, r *http.Request) error {
	var input store.KubernetesInventorySourceInput
	if err := decodeJSONLimit(r, 8<<10, &input); err != nil {
		return err
	}
	contextID := r.PathValue("context_id")
	out, err := s.changeKubernetesInventorySource(r, input.AgentID, "kubernetes.inventory_source.assigned",
		func(ctx context.Context, sc tenancy.Scope) (store.KubernetesInventorySource, error) {
			return store.CreateKubernetesInventorySourceInScope(ctx, sc, contextID, input)
		})
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusCreated, out)
	return nil
}

func (s *Server) handleRevokeKubernetesInventorySource(w http.ResponseWriter, r *http.Request) error {
	out, err := s.changeKubernetesInventorySource(r, "", "kubernetes.inventory_source.revoked",
		func(ctx context.Context, sc tenancy.Scope) (store.KubernetesInventorySource, error) {
			return store.RevokeKubernetesInventorySourceInScope(ctx, sc, r.PathValue("context_id"), r.PathValue("id"))
		})
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, out)
	return nil
}

func (s *Server) changeKubernetesInventorySource(r *http.Request, agentID, auditAction string,
	change func(context.Context, tenancy.Scope) (store.KubernetesInventorySource, error)) (store.KubernetesInventorySource, error) {
	ctx, flush := scopedABACDenial(r.Context())
	defer flush(s)
	r = r.WithContext(tenancy.WithSiloTableLock(ctx))
	actor := auth.PrincipalFrom(ctx)
	contextID := r.PathValue("context_id")
	var out store.KubernetesInventorySource
	err := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
		if _, err := s.authorizeKubernetesSourceChange(ctx, sc, actor, contextID, agentID); err != nil {
			return err
		}
		var err error
		out, err = change(ctx, sc)
		if err != nil {
			return err
		}
		// The source mutation can wait on a collector or epoch lock. Repeat
		// the current permission and policy checks with the stored collector.
		ctx, err = s.authorizeKubernetesSourceChange(ctx, sc, actor, contextID, out.AgentID)
		if err != nil {
			return err
		}
		return s.recordAudit(ctx, sc, r.WithContext(ctx), auditAction, out.ID, map[string]any{
			"context_id": contextID, "cluster_id": out.ClusterID, "namespace": out.Namespace, "agent_id": out.AgentID,
			"flow_clock_error_ms": out.FlowClockErrorMS,
		})
	})
	switch {
	case errors.Is(err, store.ErrKubernetesInventoryInput):
		err = apierror.BadRequest("invalid Kubernetes inventory source")
	case errors.Is(err, store.ErrKubernetesInventorySourceInUse):
		err = apierror.Conflict("cluster namespace already has an active inventory source in this context")
	case errors.Is(err, store.ErrKubernetesInventoryAuthority):
		err = apierror.NotFound("current Kubernetes inventory source or collector routing assignment is unavailable")
	default:
		err = entityAdminError(err)
	}
	return out, err
}

func (s *Server) authorizeKubernetesSourceChange(ctx context.Context, sc tenancy.Scope, actor *auth.Principal, contextID, agentID string) (context.Context, error) {
	ctx, principal, err := s.currentRoutingAuthority(ctx, sc, actor, permAgentWrite)
	if err != nil {
		return nil, err
	}
	record, err := store.NewEntityRegistry(s.pool).GetEntityContextInScope(ctx, sc, contextID)
	if err != nil {
		return nil, err
	}
	resource := entityContextResource(record)
	if agentID != "" {
		resource["agent_id"] = agentID
	}
	return ctx, s.authorize(ctx, principal, permAgentWrite, auth.RBACGlobal, resource)
}
