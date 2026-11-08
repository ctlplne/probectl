// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package opendata

import (
	"context"
	"errors"
	"net/netip"
	"time"
)

func (p *RPKIVRPs) Descriptor() Descriptor {
	return Descriptor{Name: "rpki-vrp-file", Kind: KindRPKI, Cadence: p.maxAge, AUP: AUP{License: "Operator-supplied validator export; underlying TAL/repository terms apply", URL: "https://www.rfc-editor.org/rfc/rfc6811", CommercialUse: CommercialUnknown, Redistribution: "Operator remains responsible for applicable source terms; no dataset is distributed by this reader"}}
}

func (p *RPKIVRPs) snapshotAt(at time.Time) RPKISnapshot {
	s := p.snapshot
	s.Current = s.Enabled && s.complete && !s.ObservedAt.IsZero() && !s.ObservedAt.After(at) && s.ValidUntil.After(at)
	return s
}

func (p *RPKIVRPs) availability(at time.Time) error {
	if !p.snapshotAt(at).Current {
		return errors.New("complete current RPKI validator export with original generation time is unavailable")
	}
	return nil
}

func (p *RPKIVRPs) Enrich(ctx context.Context, _ netip.Addr, _ *Enrichment) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	// An IP alone has neither a route prefix nor an origin. This source never
	// fabricates a validation status through ordinary address enrichment.
	return p.availability(time.Now())
}

// RPKI bypasses IP-cache TTL, as a disabled or stale validator source cannot
// establish current validation. A duplicate configured source is ambiguous.
func (en *Enricher) RPKI(at time.Time) RPKISnapshot {
	if en == nil {
		return RPKISnapshot{}
	}
	en.mu.Lock()
	defer en.mu.Unlock()
	var out RPKISnapshot
	found := false
	for _, source := range en.sources {
		p, ok := source.src.(*RPKIVRPs)
		if !ok {
			continue
		}
		if found {
			return RPKISnapshot{Version: "ambiguous"}
		}
		found = true
		out = p.snapshotAt(at)
		out.Enabled = source.health.Enabled && out.Enabled
		out.Current = out.Enabled && out.Current
	}
	return out
}

var _ Source = (*RPKIVRPs)(nil)
