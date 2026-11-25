// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"reflect"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/device"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/remediation"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type routingTransferDryRunInput struct {
	ArchiveID string                 `json:"archive_id"`
	Estimate  routingTransferRequest `json:"estimate"`
}

type routingTransferPreparedPreview struct {
	preview     remediation.RoutingTransferDryRun
	publication remediation.RTBHImpactPublication
}

func (s *Server) handleRoutingTransferDryRun(w http.ResponseWriter, r *http.Request) error {
	service, err := s.remediationSvc()
	if err != nil {
		return err
	}
	dryRun, ok := service.(remediation.RoutingTransferDryRunner)
	if !ok {
		return apierror.NotFound("routing transfer dry run is unavailable")
	}
	op, err := s.beginCapacityAgreementMode(r, false)
	if err != nil {
		return capacityAgreementAPIError(err)
	}
	defer op.done()
	ctx := op.request.Context()
	var input routingTransferDryRunInput
	if err := decodeJSONLimit(op.request, op.budget.MemoryBytes/64, &input); err != nil {
		return err
	}
	prepared, err := s.prepareRoutingTransferPreview(ctx, op, input, dryRun, permRemediationPropose)
	if err != nil {
		return err
	}
	result := prepared.preview
	body, err := json.Marshal(result)
	if err != nil || int64(len(body)) >= op.budget.ResponseBytes {
		return apierror.Unavailable("complete routing dry run exceeds output admission")
	}
	return s.writeRoutingTransferReviewRead(w, op, body, result.SourceValidUntil)
}

func (s *Server) writeRoutingTransferReviewRead(w http.ResponseWriter, op capacityAgreementOperation,
	body json.RawMessage, validUntil time.Time) error {
	if err := s.pathAlertRequestCredential(op.request, op.actor)(op.request.Context()); err != nil {
		return err
	}
	if !time.Now().Before(validUntil) {
		return apierror.Conflict("the source validity changed; run a fresh preview")
	}
	writeJSON(w, http.StatusOK, body)
	return nil
}

func (s *Server) prepareRoutingTransferPreview(ctx context.Context, op capacityAgreementOperation, input routingTransferDryRunInput,
	dryRun remediation.RoutingTransferDryRunner, permission string) (routingTransferPreparedPreview, error) {
	none := routingTransferPreparedPreview{}
	estimate, err := s.runRoutingTransferEstimate(ctx, op, input.Estimate)
	if err != nil {
		return none, routingTransferAPIError(err)
	}
	if estimate.Policy == nil || estimate.Estimate.Status != "estimated" {
		return none, apierror.Validation("a current feasible routing transfer is required")
	}
	policy := estimate.Policy
	scope := entity.Scope{TenantID: op.actor.TenantID, ContextID: estimate.ContextID}
	archive, err := s.readRoutingTransferPolicyArchive(ctx, op, scope, policy.RouterID, input.ArchiveID, permission)
	if err != nil {
		return none, err
	}
	if archive.Binding == nil {
		return none, apierror.NotFound("current owned router archive is unavailable")
	}
	peer, err := netip.ParseAddr(policy.CandidatePeer)
	if err != nil {
		return none, apierror.Unavailable("current candidate peer is unavailable")
	}
	prefix, err := netip.ParsePrefix(policy.ExactPrefix)
	if err != nil {
		return none, apierror.Unavailable("current destination prefix is unavailable")
	}
	estimateDigest, err := routingTransferDryRunEstimateDigest(ctx, scope, input.Estimate, estimate)
	if err != nil {
		return none, routingTransferAPIError(err)
	}
	validUntil := estimate.ValidUntil
	if archive.ValidUntil != nil && archive.ValidUntil.Before(validUntil) {
		validUntil = archive.ValidUntil.UTC()
	}
	result, err := dryRun.PreviewRoutingTransfer(ctx, scope.TenantID, remediation.RoutingTransferDryRunEvidence{
		TenantID: scope.TenantID, ContextID: scope.ContextID, RouterID: policy.RouterID, ArchiveID: archive.ID, ArchiveDigest: archive.ContentHash,
		ArchiveAgentID: archive.Binding.AgentID, ArchiveSourceRef: archive.Binding.SourceRef,
		ArchiveContent: archive.Content, ArchiveObservedAt: archive.ObservedAt, CandidatePeer: peer, CandidateASN: policy.CandidateASN, ExactPrefix: prefix,
		LocalPreference: policy.LocalPreference, MaxConfigBytes: op.budget.MemoryBytes / 16,
		EstimateDigest: estimateDigest, SourceValidUntil: validUntil,
		MovedPeakBPS: estimate.Estimate.MovedPeakBPS, CandidatePeakBPS: estimate.Estimate.CandidatePeakBPS,
		CandidateLimitBPS: estimate.Estimate.CandidateEgressLimitBPS,
	})
	if err != nil {
		return none, mapRemediationErr(err)
	}
	if !result.SourceValidUntil.Equal(validUntil) {
		return none, apierror.Unavailable("the routing transfer preview did not preserve the source deadline")
	}
	if err := estimate.check(ctx); err != nil {
		return none, routingTransferAPIError(err)
	}
	currentArchive, err := s.readRoutingTransferPolicyArchive(ctx, op, scope, policy.RouterID, archive.ID, permission)
	if err != nil {
		return none, err
	}
	if currentArchive.ContentHash != archive.ContentHash || currentArchive.Version != archive.Version || !reflect.DeepEqual(currentArchive.Binding, archive.Binding) {
		return none, apierror.Conflict("the router archive changed; run a fresh preview")
	}
	if !time.Now().Before(validUntil) || currentArchive.ValidUntil != nil && currentArchive.ValidUntil.Before(validUntil) {
		return none, apierror.Conflict("the source validity changed; run a fresh preview")
	}
	if err := ctx.Err(); err != nil {
		return none, err
	}
	return routingTransferPreparedPreview{preview: result, publication: s.routingTransferReviewPublication(op, scope, estimate, archive, estimateDigest, validUntil)}, nil
}

func routingTransferDryRunEstimateDigest(ctx context.Context, scope entity.Scope, requested routingTransferRequest, estimate routingTransferResponse) (string, error) {
	if estimate.proofDigest == nil {
		return "", apierror.Unavailable("current estimate evidence cannot be bound to this preview")
	}
	proof, err := estimate.proofDigest(ctx)
	if err != nil {
		return "", err
	}
	// The advancing source-validity bound does not change the evidence itself.
	estimate.ValidUntil = time.Time{}
	body, err := json.Marshal(struct {
		Version int                     `json:"version"`
		Scope   entity.Scope            `json:"scope"`
		Input   routingTransferRequest  `json:"input"`
		Result  routingTransferResponse `json:"result"`
		Proof   [32]byte                `json:"proof"`
	}{1, scope, requested, estimate, proof})
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(crypto.Hash(body)), nil
}

func (s *Server) readRoutingTransferPolicyArchive(ctx context.Context, op capacityAgreementOperation, scope entity.Scope, router, archive, permission string) (device.RoutingPolicyArchive, error) {
	var selected device.RoutingPolicyArchive
	err := s.withTopologyFailureSnapshot(ctx, op.actor, scope, op.budget, func(ctx context.Context, sc tenancy.Scope, record entity.ContextRecord, authorize topologyFailureAuthorize) error {
		if err := authorize(ctx, record, router); err != nil {
			return err
		}
		out, err := device.RoutingPolicyArchiveInScope(ctx, sc, scope, router, archive, op.budget.MemoryBytes/16, func(ctx context.Context, binding device.ConfigArchiveBinding) error {
			return s.authorizeRoutingTransferPublicationArchive(ctx, sc, op.actor, scope, binding, permission)
		})
		if err != nil {
			return err
		}
		selected = out
		return nil
	})
	switch {
	case errors.Is(err, pgx.ErrNoRows), errors.Is(err, device.ErrConfigBinding):
		return device.RoutingPolicyArchive{}, apierror.NotFound("current owned router archive is unavailable")
	case errors.Is(err, device.ErrConfigReferenceBudget):
		return device.RoutingPolicyArchive{}, apierror.TooLarge("complete router archive exceeds resource admission")
	case err != nil:
		return device.RoutingPolicyArchive{}, err
	}
	return selected, ctx.Err()
}
