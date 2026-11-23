// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package agenttransport

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5/pgconn"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/entity"
	agentv1 "github.com/ctlplne/probectl/internal/gen/probectl/agent/v1"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func (svc *service) submitKubernetesInventory(ctx context.Context, id crypto.SPIFFEID, serial string,
	request *agentv1.SubmitEntityEvidenceRequest) (*agentv1.SubmitEntityEvidenceResponse, error) {
	size := proto.Size(request)
	if size > entity.KubernetesInventoryRequestBytes {
		return nil, status.Error(codes.ResourceExhausted, "Kubernetes inventory request exceeds evidence admission")
	}
	upload := request.GetKubernetesInventory()
	count, err := store.KubernetesInventoryAdmission(upload)
	if err != nil {
		return nil, kubernetesInventoryWriteError(err)
	}
	if svc.pool == nil {
		return nil, status.Error(codes.Unavailable, "Kubernetes inventory persistence is unavailable")
	}
	if !svc.admitEntityEvidence(ctx, id.TenantID, count, size) {
		return nil, status.Error(codes.ResourceExhausted, "tenant Kubernetes inventory evidence rate exceeded")
	}
	ctx = tenancy.WithSiloTableLock(tenancy.WithTenant(ctx, tenancy.ID(id.TenantID)))
	var receipt *agentv1.KubernetesInventoryReceipt
	err = tenancy.FencedTenantWrite(ctx, svc.fence, id.TenantID, entity.ErrScopeMismatch, func(ctx context.Context) error {
		return tenancy.InTenant(ctx, svc.pool, func(ctx context.Context, sc tenancy.Scope) error {
			var err error
			receipt, err = store.WriteKubernetesInventoryInScope(ctx, sc, id.AgentID, serial, upload)
			return err
		})
	})
	if err != nil {
		return nil, kubernetesInventoryWriteError(err)
	}
	return &agentv1.SubmitEntityEvidenceResponse{KubernetesInventory: receipt}, nil
}

func kubernetesInventoryWriteError(err error) error {
	switch {
	case errors.Is(err, store.ErrKubernetesInventoryAuthority), errors.Is(err, entity.ErrScopeMismatch):
		return status.Error(codes.PermissionDenied, "current Kubernetes inventory source assignment is unavailable")
	case errors.Is(err, store.ErrKubernetesInventoryConflict):
		return status.Error(codes.AlreadyExists, "Kubernetes inventory upload conflicts with retained evidence")
	case errors.Is(err, store.ErrKubernetesInventoryOrder):
		return status.Error(codes.FailedPrecondition, "Kubernetes inventory upload is incomplete, out of order or expired")
	case errors.Is(err, store.ErrKubernetesInventoryBudget):
		return status.Error(codes.ResourceExhausted, "Kubernetes inventory upload exceeds evidence admission")
	case errors.Is(err, store.ErrKubernetesInventoryInput):
		return status.Error(codes.InvalidArgument, "invalid original Kubernetes inventory evidence")
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return status.FromContextError(err).Err()
	}
	var constraint *pgconn.PgError
	if errors.As(err, &constraint) {
		switch constraint.Code {
		case "23503", "23505", "23514":
			return status.Error(codes.InvalidArgument, "Kubernetes inventory records have inconsistent references")
		}
	}
	return status.Error(codes.Unavailable, "Kubernetes inventory persistence failed")
}
