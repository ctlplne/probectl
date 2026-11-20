// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
// Licensed under the probectl Commercial Source License. See ee/LICENSE.
// Production use requires a valid commercial agreement. Resale additionally
// requires an MSP entitlement and reseller agreement.

package remediation

import (
	"math/big"
	"net/netip"
	"strconv"
	"strings"

	rem "github.com/ctlplne/probectl/internal/remediation"
)

// The existing blast limit is an upper bound on the address space of the
// announcement. The observed address count is separate collateral evidence.
func rtbhBlastRadius(preview rem.RTBHPreview, limit int) (int, error) {
	return routingReviewBlastRadius(preview.Announcement.Prefix, preview.Impact.Prefix, limit)
}

func routingReviewBlastRadius(destination, observedPrefix string, limit int) (int, error) {
	prefix, err := netip.ParsePrefix(destination)
	if err != nil || prefix.Bits() < 1 || prefix != prefix.Masked() || prefix.Addr().Is4In6() ||
		observedPrefix != prefix.String() || limit < 1 {
		return 0, rem.ErrUnknownBlastRadius
	}
	hostBits := prefix.Addr().BitLen() - prefix.Bits()
	if hostBits >= strconv.IntSize-1 {
		return 0, rem.ErrBlastRadiusExceeded
	}
	addresses := 1 << hostBits
	if addresses > limit {
		return 0, rem.ErrBlastRadiusExceeded
	}
	return addresses, nil
}

func rtbhCollateralWithinLimit(preview rem.RTBHPreview, maxBenignPackets string) error {
	return routingReviewCollateralWithinLimit(preview.Impact.KnownBenign.Packets, maxBenignPackets)
}

func routingReviewCollateralWithinLimit(benignPackets, maxBenignPackets string) error {
	limit, ok := rtbhDecimal(maxBenignPackets)
	if !ok {
		return rem.Error{Code: "validation", Message: "set the exact approved benign packet limit"}
	}
	measured, ok := rtbhDecimal(benignPackets)
	if !ok {
		return rem.ErrUnknownBlastRadius
	}
	if measured.Cmp(limit) > 0 {
		return rem.ErrBlastRadiusExceeded
	}
	return nil
}

func rtbhDecimal(value string) (*big.Int, bool) {
	if value == "" || len(value) > 64 || strings.IndexFunc(value, func(r rune) bool { return r < '0' || r > '9' }) >= 0 {
		return nil, false
	}
	return new(big.Int).SetString(value, 10)
}
