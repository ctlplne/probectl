// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
// Licensed under the probectl Commercial Source License. See ee/LICENSE.
// Production use requires a valid commercial agreement. Resale additionally
// requires an MSP entitlement and reseller agreement.

package remediation

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"time"

	"github.com/ctlplne/probectl/internal/crypto"
	rem "github.com/ctlplne/probectl/internal/remediation"
)

func (s *Service) PreviewFlowSpec(ctx context.Context, tenant string, input rem.FlowSpecPreviewInput, credential func(context.Context) error) (rem.FlowSpecPreview, error) {
	if _, err := remediationActor(ctx, tenant, false); err != nil {
		return rem.FlowSpecPreview{}, err
	}
	preview, _, err := s.prepareFlowSpec(ctx, tenant, input, time.Time{}, credential)
	return preview, err
}

func (s *Service) prepareFlowSpec(ctx context.Context, tenant string, input rem.FlowSpecPreviewInput, observedTo time.Time,
	credential func(context.Context) error,
) (rem.FlowSpecPreview, rem.RTBHImpactPublication, error) {
	var empty rem.FlowSpecPreview
	source, enabled := s.prefixImpact.(rem.FlowSpecReviewSource)
	if !enabled || credential == nil {
		return empty, rem.RTBHImpactPublication{}, unavailableRTBHReview()
	}
	if !input.RoutingPolicyAgreed {
		return empty, rem.RTBHImpactPublication{}, rem.Error{Code: "validation", Message: "confirm the configured routing policy"}
	}
	if err := input.Transport.Validate(); err != nil {
		return empty, rem.RTBHImpactPublication{}, err
	}
	prepared, err := source.PrepareFlowSpecImpact(ctx, tenant, input.PrefixImpactInput, input.Transport, observedTo, credential)
	if err != nil {
		return empty, prepared, err
	}
	now := s.now().UTC()
	if !validRTBHDigest(prepared.Scope) || prepared.Publish == nil || prepared.WholeScope == nil || prepared.Impact.To.IsZero() ||
		prepared.Impact.To.After(now) || (!observedTo.IsZero() && !observedTo.Equal(prepared.Impact.To)) ||
		!now.Before(prepared.Impact.To.Add(rtbhReviewLifetime)) {
		return empty, prepared, changedRTBHReview()
	}
	preview, err := composeFlowSpecPreview(input.Transport, prepared.Impact, *prepared.WholeScope)
	if err != nil {
		return empty, prepared, err
	}
	raw, err := json.Marshal(struct {
		Version int                      `json:"version"`
		Tenant  string                   `json:"tenant_id"`
		Input   rem.FlowSpecPreviewInput `json:"input"`
		Preview rem.FlowSpecPreview      `json:"preview"`
		Scope   string                   `json:"source_scope"`
	}{1, tenant, input, preview, prepared.Scope})
	if err != nil {
		return empty, prepared, err
	}
	preview.Fingerprint = hex.EncodeToString(crypto.Hash(raw))
	return preview, prepared, ctx.Err()
}

func composeFlowSpecPreview(transport rem.FlowSpecTransport, matching, whole rem.PrefixImpact) (rem.FlowSpecPreview, error) {
	prefix, err := netip.ParsePrefix(matching.Prefix)
	if err != nil || prefix.Bits() < 1 || prefix != prefix.Masked() || prefix.Addr().Is4In6() ||
		whole.Prefix != matching.Prefix || !matching.From.Equal(whole.From) || !matching.To.Equal(whole.To) ||
		!matching.From.Before(matching.To) || whole.ObservedRecords < 1 || whole.ObservedAddresses < 1 ||
		whole.ObservedAddresses > whole.ObservedRecords || matching.ObservedRecords < 0 || matching.ObservedAddresses < 0 ||
		matching.ObservedRecords > whole.ObservedRecords || matching.ObservedAddresses > whole.ObservedAddresses ||
		matching.ObservedAddresses > matching.ObservedRecords || (matching.Sampled && !whole.Sampled) ||
		!flowSpecTotalsCovered(matching.Matched, whole.Matched) || !flowSpecTotalsCovered(matching.KnownBenign, whole.KnownBenign) ||
		!flowSpecTotalsCovered(matching.Unclassified, whole.Unclassified) {
		return rem.FlowSpecPreview{}, rem.ErrUnknownBlastRadius
	}
	family := "ipv6"
	if prefix.Addr().Is4() {
		family = "ipv4"
	}
	matching.From, matching.To = matching.From.UTC(), matching.To.UTC()
	whole.From, whole.To = whole.From.UTC(), whole.To.UTC()
	return rem.FlowSpecPreview{
		Candidate: rem.FlowSpecCandidate{Family: family, Destination: prefix.String(), Transport: transport, Action: "discard"},
		Matching:  matching, WholeScope: whole,
	}, nil
}

func flowSpecTotalsCovered(partition, whole rem.PrefixTraffic) bool {
	partBytes, partBytesOK := rtbhDecimal(partition.Bytes)
	wholeBytes, wholeBytesOK := rtbhDecimal(whole.Bytes)
	partPackets, partPacketsOK := rtbhDecimal(partition.Packets)
	wholePackets, wholePacketsOK := rtbhDecimal(whole.Packets)
	return partBytesOK && wholeBytesOK && partPacketsOK && wholePacketsOK &&
		partBytes.Cmp(wholeBytes) <= 0 && partPackets.Cmp(wholePackets) <= 0
}
