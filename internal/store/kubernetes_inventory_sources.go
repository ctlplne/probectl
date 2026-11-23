// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"context"
	"errors"
	"math"
	"regexp"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/ctlplne/probectl/internal/tenancy"
)

var (
	kubernetesInventoryNamespace      = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	ErrKubernetesInventorySourceInUse = errors.New("kubernetes namespace already has an active inventory source")
)

type KubernetesInventorySource struct {
	ID               string     `json:"id"`
	ContextID        string     `json:"context_id"`
	ClusterID        string     `json:"cluster_id"`
	Namespace        string     `json:"namespace"`
	AgentID          string     `json:"agent_id"`
	FlowClockErrorMS *int64     `json:"flow_clock_error_ms,omitempty"`
	AssignedAt       time.Time  `json:"assigned_at"`
	ClosedAt         *time.Time `json:"closed_at,omitempty"`
}

type KubernetesInventorySourceInput struct {
	ClusterID        string `json:"cluster_id"`
	Namespace        string `json:"namespace"`
	AgentID          string `json:"agent_id"`
	FlowClockErrorMS *int64 `json:"flow_clock_error_ms,omitempty"`
}

// CreateKubernetesInventorySourceInScope pins one collector to a specific
// cluster and namespace in its current tenant-owned routing context.
func CreateKubernetesInventorySourceInScope(ctx context.Context, sc tenancy.Scope, contextID string,
	input KubernetesInventorySourceInput) (KubernetesInventorySource, error) {
	if !canonicalKubernetesUploadID(contextID) || !canonicalKubernetesUploadID(input.ClusterID) ||
		!canonicalKubernetesUploadID(input.AgentID) || !kubernetesInventoryNamespace.MatchString(input.Namespace) ||
		!validKubernetesFlowClockError(input.FlowClockErrorMS) {
		return KubernetesInventorySource{}, ErrKubernetesInventoryInput
	}
	if err := admitKubernetesSourceChange(ctx, sc); err != nil {
		return KubernetesInventorySource{}, err
	}
	var registeredAgent string
	if err := sc.Q.QueryRow(ctx, `
SELECT binding.agent_id FROM entity_agent_contexts binding
JOIN agents agent ON agent.tenant_id=binding.tenant_id AND agent.id=$3::text::uuid
WHERE binding.tenant_id=$1 AND binding.context_id=$2 AND binding.agent_id=$3 AND agent.status<>'revoked'
  AND binding.assigned_at<=clock_timestamp() AND (binding.expires_at IS NULL OR binding.expires_at>clock_timestamp())
FOR SHARE OF binding,agent`, sc.Tenant.String(), contextID, input.AgentID).Scan(&registeredAgent); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return KubernetesInventorySource{}, ErrKubernetesInventoryAuthority
		}
		return KubernetesInventorySource{}, err
	}
	id, err := newRegistryID()
	if err != nil {
		return KubernetesInventorySource{}, err
	}
	source := KubernetesInventorySource{ID: id, ContextID: contextID, ClusterID: input.ClusterID,
		Namespace: input.Namespace, AgentID: registeredAgent, FlowClockErrorMS: input.FlowClockErrorMS}
	err = sc.Q.QueryRow(ctx, `
INSERT INTO kubernetes_inventory_sources(tenant_id,context_id,id,cluster_id,namespace,agent_id,flow_clock_error_ms)
VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING assigned_at`,
		sc.Tenant.String(), contextID, id, input.ClusterID, input.Namespace, input.AgentID, input.FlowClockErrorMS).Scan(&source.AssignedAt)
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" && pgErr.ConstraintName == "kubernetes_inventory_live_namespace_idx" {
		return KubernetesInventorySource{}, ErrKubernetesInventorySourceInUse
	}
	return source, err
}

// RevokeKubernetesInventorySourceInScope closes the exact immutable source
// epoch. Later enrollment receives a different ID, with fresh evidence only.
func RevokeKubernetesInventorySourceInScope(ctx context.Context, sc tenancy.Scope, contextID, id string) (KubernetesInventorySource, error) {
	if !canonicalKubernetesUploadID(contextID) || !canonicalKubernetesUploadID(id) {
		return KubernetesInventorySource{}, ErrKubernetesInventoryInput
	}
	if err := admitKubernetesSourceChange(ctx, sc); err != nil {
		return KubernetesInventorySource{}, err
	}
	source := KubernetesInventorySource{ID: id, ContextID: contextID}
	err := sc.Q.QueryRow(ctx, `
UPDATE kubernetes_inventory_sources
SET closed_at=coalesce(closed_at,greatest(assigned_at,clock_timestamp()))
WHERE tenant_id=$1 AND context_id=$2 AND id=$3
RETURNING cluster_id::text,namespace,agent_id,flow_clock_error_ms,assigned_at,closed_at`, sc.Tenant.String(), contextID, id).
		Scan(&source.ClusterID, &source.Namespace, &source.AgentID, &source.FlowClockErrorMS, &source.AssignedAt, &source.ClosedAt)
	if err != nil {
		return KubernetesInventorySource{}, err
	}
	_, err = sc.Q.Exec(ctx, `DELETE FROM kubernetes_inventory_staging
WHERE tenant_id=$1 AND context_id=$2 AND source_id=$3`, sc.Tenant.String(), contextID, id)
	return source, err
}

func validKubernetesFlowClockError(millis *int64) bool {
	const maxMillis = (math.MaxInt64 - int64(time.Millisecond)) / int64(time.Millisecond)
	return millis == nil || *millis >= 0 && *millis <= maxMillis
}

func admitKubernetesSourceChange(ctx context.Context, sc tenancy.Scope) error {
	tenant, bound := tenancy.FromContext(ctx)
	if !bound || tenant != sc.Tenant || sc.Q == nil {
		return ErrKubernetesInventoryAuthority
	}
	invalidating, _, err := entityEvidenceLifecycleScope(ctx, sc)
	if err != nil {
		return err
	}
	if invalidating {
		return ErrKubernetesInventoryAuthority
	}
	return nil
}
