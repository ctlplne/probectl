// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
// Licensed under the probectl Commercial Source License. See ee/LICENSE.
// Production use requires a valid commercial agreement. Resale additionally
// requires an MSP entitlement and reseller agreement.

package remediation

import (
	"context"
	"net/netip"
	"strconv"
	"strings"
	"time"

	rem "github.com/ctlplne/probectl/internal/remediation"
)

func (s *Service) PreviewRTBH(ctx context.Context, tenantID string, input rem.RTBHPreviewInput, check func(context.Context) error) (rem.RTBHPreview, error) {
	if s.prefixImpact == nil {
		return rem.RTBHPreview{}, rem.Error{Code: "not_found", Message: "traffic review is unavailable"}
	}
	if _, err := remediationActor(ctx, tenantID, false); err != nil {
		return rem.RTBHPreview{}, err
	}
	if !input.RoutingPolicyAgreed || !canonicalRTBHCommunity(input.Community) {
		return rem.RTBHPreview{}, rem.Error{Code: "validation", Message: "confirm the routing policy and enter its canonical community"}
	}
	if _, ok := s.prefixImpact.(rem.RTBHReviewSource); ok {
		preview, _, err := s.prepareRTBH(ctx, tenantID, input, time.Time{}, check)
		return preview, err
	}
	impact, err := s.prefixImpact.ObservePrefixImpact(ctx, tenantID, input.PrefixImpactInput, check)
	if err != nil {
		return rem.RTBHPreview{}, err
	}
	return composeRTBHPreview(ctx, input, impact)
}

func composeRTBHPreview(ctx context.Context, input rem.RTBHPreviewInput, impact rem.PrefixImpact) (rem.RTBHPreview, error) {
	prefix, err := netip.ParsePrefix(impact.Prefix)
	if err != nil || prefix.Bits() < 1 || prefix != prefix.Masked() || prefix.Addr().Is4In6() {
		return rem.RTBHPreview{}, rem.Error{Code: "validation", Message: "the protected network prefix is unavailable"}
	}
	family := "ipv6"
	if prefix.Addr().Is4() {
		family = "ipv4"
	}
	return rem.RTBHPreview{Announcement: rem.RTBHAnnouncement{Family: family, Prefix: prefix.String(), Community: input.Community}, Impact: impact}, ctx.Err()
}

func canonicalRTBHCommunity(value string) bool {
	left, right, found := strings.Cut(value, ":")
	if !found || len(left) < 1 || len(left) > 5 || len(right) < 1 || len(right) > 5 {
		return false
	}
	first, leftErr := strconv.ParseUint(left, 10, 16)
	second, rightErr := strconv.ParseUint(right, 10, 16)
	return leftErr == nil && rightErr == nil && left == strconv.FormatUint(first, 10) && right == strconv.FormatUint(second, 10)
}
