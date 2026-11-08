// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package opendata

import (
	"context"
	"net/netip"
	"time"
)

// UsableAt distinguishes a fully loaded original generation from caller-filled
// public metadata. It grants no tenant or routing-source authority.
func (s RPKISnapshot) UsableAt(at time.Time) bool {
	return s.Enabled && s.Current && s.complete && !s.ObservedAt.IsZero() && !s.ObservedAt.After(at) && s.ValidUntil.After(at)
}

// RPKICoveringVerdict checks a complete retained covering set. Its caller must
// independently establish the original complete source and route provenance;
// an arbitrary list, even an empty one, proves no source completeness or grant.
func RPKICoveringVerdict(ctx context.Context, prefix netip.Prefix, origin *uint32, covering []RPKIVRP, memoryBytes, workUnits int64) (string, error) {
	if !prefix.IsValid() || prefix != prefix.Masked() {
		return "unknown", errRPKIJSON
	}
	if memoryBytes < 4096 || workUnits < 4096 || int64(len(covering)) > (memoryBytes-4096)/256 || int64(len(covering)) > (workUnits-4096)/256 {
		return "unknown", ErrRPKIVRPBudget
	}
	seen := make(map[RPKIVRP]bool, len(covering))
	valid := false
	for _, vrp := range covering {
		if err := ctx.Err(); err != nil {
			return "unknown", err
		}
		if !vrp.Prefix.IsValid() || vrp.Prefix != vrp.Prefix.Masked() || vrp.Prefix.Addr().BitLen() != prefix.Addr().BitLen() || vrp.Prefix.Bits() > prefix.Bits() || !vrp.Prefix.Contains(prefix.Addr()) || vrp.MaxLength < vrp.Prefix.Bits() || vrp.MaxLength > vrp.Prefix.Addr().BitLen() || seen[vrp] {
			return "unknown", errRPKIJSON
		}
		seen[vrp] = true
		valid = valid || origin != nil && vrp.ASN != 0 && vrp.ASN == *origin && prefix.Bits() <= vrp.MaxLength
	}
	if err := ctx.Err(); err != nil {
		return "unknown", err
	}
	if origin == nil || *origin == 0 || *origin == 23456 {
		return "unknown", nil
	}
	if len(covering) == 0 {
		return "not_found", nil
	}
	if valid {
		return "valid", nil
	}
	return "invalid", nil
}
