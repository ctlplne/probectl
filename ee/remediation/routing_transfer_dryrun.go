// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
// Licensed under the probectl Commercial Source License. See ee/LICENSE.
// Production use requires a valid commercial agreement. Resale additionally
// requires an MSP entitlement and reseller agreement.

package remediation

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"strconv"
	"strings"
	"time"

	"github.com/ctlplne/probectl/internal/crypto"
	rem "github.com/ctlplne/probectl/internal/remediation"
)

func (s *Service) PreviewRoutingTransfer(ctx context.Context, tenantID string, evidence rem.RoutingTransferDryRunEvidence) (rem.RoutingTransferDryRun, error) {
	none := rem.RoutingTransferDryRun{}
	if _, err := remediationActor(ctx, tenantID, false); err != nil {
		return none, err
	}
	now := s.now()
	if tenantID != evidence.TenantID || evidence.RouterID == "" || evidence.ArchiveID == "" || evidence.ArchiveObservedAt.IsZero() ||
		evidence.ArchiveObservedAt.After(now) || !validRTBHDigest(evidence.ArchiveDigest) ||
		!validRTBHDigest(evidence.EstimateDigest) || !evidence.SourceValidUntil.After(now) ||
		evidence.MaxConfigBytes <= 0 || int64(len(evidence.ArchiveContent)) > evidence.MaxConfigBytes {
		return none, rem.ErrUnknownBlastRadius
	}
	if hex.EncodeToString(crypto.Hash([]byte(evidence.ArchiveContent))) != evidence.ArchiveDigest {
		return none, rem.ErrUnknownBlastRadius
	}
	policy, err := draftFRRTransfer(ctx, evidence.ArchiveContent, evidence.CandidatePeer, evidence.CandidateASN, evidence.ExactPrefix,
		evidence.LocalPreference, evidence.MaxConfigBytes)
	if err != nil {
		return none, err
	}
	if err := validateRoutingTransferPeak(evidence.MovedPeakBPS, evidence.CandidatePeakBPS, evidence.CandidateLimitBPS, evidence.MaxConfigBytes); err != nil {
		return none, err
	}
	// Exact binary prefix cardinality remains representable for IPv6 even
	// when the prefix exceeds the configured integer approval limit.
	hostBits := evidence.ExactPrefix.Addr().BitLen() - evidence.ExactPrefix.Bits()
	if hostBits < 0 || hostBits > 127 {
		return none, rem.ErrUnknownBlastRadius
	}
	affected := new(big.Int).Lsh(big.NewInt(1), uint(hostBits)).String()
	result := rem.RoutingTransferDryRun{
		ContextID: evidence.ContextID, RouterID: evidence.RouterID, ArchiveID: evidence.ArchiveID, ArchiveDigest: evidence.ArchiveDigest,
		ArchiveAgentID: evidence.ArchiveAgentID, ArchiveSourceRef: evidence.ArchiveSourceRef,
		ArchiveObservedAt: evidence.ArchiveObservedAt.UTC(), CandidatePeer: policy.CandidatePeer, CandidateASN: policy.CandidateASN, ExactPrefix: policy.ExactPrefix,
		CurrentInboundPolicy: policy.BeforeMap, ProposedInboundPolicy: policy.AfterMap,
		DefaultLocalPreference: policy.DefaultLocalPreference, WeightVerification: policy.WeightVerification,
		EstimateDigest: evidence.EstimateDigest, SourceValidUntil: evidence.SourceValidUntil.UTC(),
		AddressCountUpperBound: affected, AddressLimit: strconv.Itoa(s.maxBlastRadius),
		MovedPeakBPS: evidence.MovedPeakBPS, CandidatePeakBPS: evidence.CandidatePeakBPS, CandidateLimitBPS: evidence.CandidateLimitBPS,
		Configure: policy.Configure, Withdraw: policy.Withdraw,
	}
	// A review can compare this exact scoped change after re-evaluating the
	// estimate and archive. The validity clock is evidence for display and
	// admission. A heartbeat may extend it without changing the policy.
	result.PreviewFingerprint, err = routingTransferPreviewFingerprint(tenantID, result)
	if err != nil {
		return none, err
	}
	return result, ctx.Err()
}

func validateRoutingTransferPeak(movedText, projectedText, capacityText string, budget int64) error {
	moved, validMoved := positiveRoutingTransferBPS(movedText, budget/3)
	projected, validProjected := positiveRoutingTransferBPS(projectedText, budget/3)
	capacity, validCapacity := positiveRoutingTransferBPS(capacityText, budget/3)
	if !validMoved || !validProjected || !validCapacity || projected.Cmp(moved) < 0 {
		return rem.ErrUnknownBlastRadius
	}
	if projected.Cmp(capacity) > 0 {
		return rem.ErrBlastRadiusExceeded
	}
	return nil
}

func positiveRoutingTransferBPS(text string, maxBytes int64) (*big.Rat, bool) {
	if text == "" || int64(len(text)) > maxBytes || strings.IndexFunc(text, func(c rune) bool {
		return (c < '0' || c > '9') && c != '/'
	}) != -1 {
		return nil, false
	}
	value, ok := new(big.Rat).SetString(text)
	return value, ok && value.Sign() > 0 && value.RatString() == text
}

func routingTransferPreviewFingerprint(tenantID string, result rem.RoutingTransferDryRun) (string, error) {
	result.PreviewFingerprint = ""
	result.SourceValidUntil = time.Time{}
	identity, err := json.Marshal(struct {
		Version int                       `json:"version"`
		Tenant  string                    `json:"tenant_id"`
		Preview rem.RoutingTransferDryRun `json:"preview"`
	}{1, tenantID, result})
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(crypto.Hash(identity)), nil
}
