// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/device"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/remediation"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func (s *Server) recheckRoutingTransferPublicationInScope(ctx context.Context, sc tenancy.Scope, op capacityAgreementOperation,
	scope entity.Scope, input routingTransferBillingInput, before routingTransferBillPlans, ports routingTransferPorts, route routingTransferRoute,
	sources routingTransferExporterPlan, originals routingTransferFlowEvidence, rows []flowstore.CounterRow,
	performance *routingTransferPerformanceEvidence) error {
	return s.withTopologyFailureAuthority(ctx, sc, op.actor, scope, func(ctx context.Context, sc tenancy.Scope, record entity.ContextRecord, authorize topologyFailureAuthorize) error {
		if _, err := s.routingTransferBillPlansInScope(ctx, sc, record, authorize, op, scope, input, &before, rows); err != nil {
			return err
		}
		currentRoute, err := s.routingTransferRouteInScope(ctx, sc, scope, record, authorize, ports, route.prefix, op.budget)
		if err != nil {
			return err
		}
		if !route.matchesCurrent(currentRoute) {
			return apierror.Conflict("owned routing choices changed during review publication")
		}
		currentSources, err := s.routingTransferExporterSourcesInScope(ctx, sc, scope, record, authorize, ports.source, op.budget)
		if err != nil {
			return err
		}
		if !sources.matchesCurrent(currentSources) {
			return apierror.Conflict("owned exporter assignments or leases changed during review publication")
		}
		currentOriginals, err := s.readRoutingTransferOriginalsInScope(ctx, sc, scope, record, authorize, ports.source.Source.DeviceID, originals, op.budget)
		if err != nil {
			return err
		}
		if !originals.matchesCurrent(currentOriginals) {
			return apierror.Conflict("original flow authority or selected prefixes changed during review publication")
		}
		if performance != nil {
			selection := performance.selection
			tests := [2]store.RoutingProbeTest{selection.request.Source, selection.request.Candidate}
			if err := store.NewEntityRegistry(s.pool).LockRoutingProbeSourcesForPublication(ctx, sc, scope, ports.source.Source.DeviceID, tests); err != nil {
				return err
			}
			now, err := s.routingTransferPerformanceInScope(ctx, sc, op, scope, record, authorize, ports, currentRoute, selection)
			if err != nil {
				return err
			}
			if !performance.matchesCurrent(now) {
				return apierror.Conflict("upstream probe evidence changed during review publication")
			}
		}
		return ctx.Err()
	})
}

func (s *Server) routingTransferReviewPublication(op capacityAgreementOperation, scope entity.Scope,
	estimate routingTransferResponse, archive device.RoutingPolicyArchive, digest string, validUntil time.Time) remediation.RTBHImpactPublication {
	// Retain the archive identity and assignment epochs for locking. The raw
	// configuration was already consumed by the read-only compiler.
	archive.Content = ""
	return remediation.RTBHImpactPublication{Scope: digest,
		Publish: func(ctx context.Context, sc tenancy.Scope, permission string, mutate func(context.Context, tenancy.Scope) error) error {
			if scope.TenantID != sc.Tenant.String() || op.actor == nil || scope.TenantID != op.actor.TenantID ||
				archive.Binding == nil || estimate.checkInScope == nil || mutate == nil ||
				(permission != permRemediationPropose && permission != permRemediationApprove) {
				return entity.ErrScopeMismatch
			}
			if err := s.lockRoutingReviewApprovalSession(ctx, sc, op.actor); err != nil {
				return err
			}
			return (store.BGPRouting{}).WithRoutingTransferPublication(ctx, sc,
				func(ctx context.Context, sc tenancy.Scope) error {
					err := device.LockRoutingPolicyArchiveInScope(ctx, sc, archive.ConfigVersion, func(ctx context.Context, binding device.ConfigArchiveBinding) error {
						return s.authorizeRoutingTransferPublicationArchive(ctx, sc, op.actor, scope, binding, permission)
					})
					return routingTransferArchivePublicationError(err)
				},
				func(ctx context.Context, sc tenancy.Scope) error {
					if err := estimate.checkInScope(ctx, sc); err != nil {
						return routingTransferAPIError(err)
					}
					// Refresh archive and credential authority after any lock wait.
					if err := s.authorizeRoutingTransferPublicationArchive(ctx, sc, op.actor, scope, *archive.Binding, permission); err != nil {
						return err
					}
					if err := s.lockRoutingReviewApprovalSession(ctx, sc, op.actor); err != nil {
						return err
					}
					if err := device.CheckLockedRoutingPolicyArchiveExpiryInScope(ctx, sc, archive.ConfigVersion, validUntil); err != nil {
						return routingTransferArchivePublicationError(err)
					}
					return mutate(ctx, sc)
				})
		}}
}

func (s *Server) authorizeRoutingTransferPublicationArchive(ctx context.Context, sc tenancy.Scope, actor *auth.Principal,
	scope entity.Scope, binding device.ConfigArchiveBinding, permission string) error {
	return s.withTopologyFailureAuthority(ctx, sc, actor, scope, func(ctx context.Context, sc tenancy.Scope, record entity.ContextRecord, authorize topologyFailureAuthorize) error {
		if binding.ContextID != scope.ContextID || binding.DeviceEntityID == "" || binding.AgentID == "" || binding.SourceRef == "" {
			return entity.ErrScopeMismatch
		}
		if err := authorize(ctx, record, binding.DeviceEntityID); err != nil {
			return err
		}
		current, err := readCurrentUserAuthorityScope(ctx, sc, actor.UserID)
		if err != nil {
			return err
		}
		ctx, principal, err := current.requestContext(ctx, actor)
		if err != nil {
			return err
		}
		resource := entityContextResource(record)
		resource["entity_id"] = binding.DeviceEntityID
		if err := s.authorize(ctx, principal, permission, auth.RBACGlobal, resource); err != nil {
			return err
		}
		resource["agent_id"], resource["source_kind"], resource["source_ref"] = binding.AgentID, string(entity.DeviceTarget), binding.SourceRef
		return s.authorize(ctx, principal, "metrics.read", auth.RBACGlobal, resource)
	})
}

func routingTransferArchivePublicationError(err error) error {
	if errors.Is(err, device.ErrConfigBinding) || errors.Is(err, pgx.ErrNoRows) {
		return apierror.Conflict("the owned router archive or its lease changed during review publication").Wrap(err)
	}
	return err
}
