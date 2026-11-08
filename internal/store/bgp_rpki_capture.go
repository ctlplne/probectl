// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"context"
	"encoding/hex"
	"net/netip"
	"time"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/opendata"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// BGPRoutingRPKICapture is original ingestion-time validator evidence. Its
// source generation proves no tenant, exporter, route or current read grant.
// Store it in the existing immutable tenant-isolated routing facts, never
// substitute today's VRPs for an original accepted flow capture.
type BGPRoutingRPKICapture struct {
	Version                string
	Records                int64
	ObservedAt, ValidUntil time.Time
	Prefix                 netip.Prefix
	Covering               []opendata.RPKIVRP
	Verdicts               []string
}

// WithRPKIEnrichment attaches only the deployment's complete local public
// validator source. Authenticated tenant/exporter resolution still runs first.
func (service *BGPRoutingFlowCaptures) WithRPKIEnrichment(source *opendata.Enricher) *BGPRoutingFlowCaptures {
	service.rpki = source
	return service
}

func captureRoutingRPKI(ctx context.Context, lookup *BGPRoutingFlowLookup, snapshot opendata.RPKISnapshot, budget BGPRoutingBudget) error {
	tenant, ok := tenancy.FromContext(ctx)
	if !ok || tenant.String() != lookup.Owner.TenantID {
		return entity.ErrScopeMismatch
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	candidate := *lookup
	candidate.Source.RPKI, candidate.Destination.RPKI = nil, nil
	if !snapshot.UsableAt(lookup.CapturedAt) {
		*lookup = candidate
		return nil
	}
	for _, side := range []*BGPRoutingFlowSide{&candidate.Source, &candidate.Destination} {
		prefix := routingRPKIPrefix(side)
		if !prefix.IsValid() {
			continue
		}
		if err := routingCaptureCountCharge(ctx, &budget, len(side.Fields), 512); err != nil {
			return err
		}
		// The covering set depends on the prefix, not the origin. Keep it once
		// for every path, including an ambiguous origin, without duplication.
		probe := uint32(1)
		_, covering, err := snapshot.Validate(ctx, prefix, &probe, budget.MemoryBytes, budget.WorkUnits)
		if err != nil {
			return err
		}
		capture := &BGPRoutingRPKICapture{Version: snapshot.Version, Records: snapshot.Records, ObservedAt: snapshot.ObservedAt, ValidUntil: snapshot.ValidUntil, Prefix: prefix, Covering: covering, Verdicts: make([]string, len(side.Fields))}
		if err := chargeRoutingRPKICapture(ctx, capture, &budget); err != nil {
			return err
		}
		for i, field := range side.Fields {
			capture.Verdicts[i], err = routingRPKIVerdict(ctx, prefix, field.OriginAS, covering, &budget)
			if err != nil {
				return err
			}
		}
		side.RPKI = capture
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	*lookup = candidate
	return nil
}

func routingRPKIPrefix(side *BGPRoutingFlowSide) netip.Prefix {
	if side.State == "router_selected" && side.Public == nil {
		return side.Route.Prefix
	}
	if side.State == "public_fallback" && side.Public != nil {
		return side.Public.Prefix
	}
	return netip.Prefix{}
}

func routingRPKIVerdict(ctx context.Context, prefix netip.Prefix, origin *uint32, covering []opendata.RPKIVRP, budget *BGPRoutingBudget) (string, error) {
	verdict, err := opendata.RPKICoveringVerdict(ctx, prefix, origin, covering, budget.MemoryBytes, budget.WorkUnits)
	if err != nil {
		return "unknown", err
	}
	if err := routingCaptureCountCharge(ctx, budget, len(covering), 256); err != nil {
		return "unknown", err
	}
	return verdict, routingBatchCharge(budget, 4096, 4096)
}

func chargeRoutingRPKICapture(ctx context.Context, capture *BGPRoutingRPKICapture, budget *BGPRoutingBudget) error {
	if capture == nil {
		return ctx.Err()
	}
	if err := routingCaptureStringCharge(ctx, budget, capture.Version); err != nil {
		return err
	}
	if err := routingCaptureCountCharge(ctx, budget, len(capture.Covering), 512); err != nil {
		return err
	}
	if err := routingCaptureCountCharge(ctx, budget, len(capture.Verdicts), 256); err != nil {
		return err
	}
	return routingBatchCharge(budget, 4096, 4096)
}

func validateRoutingRPKICapture(ctx context.Context, side *BGPRoutingFlowSide, at time.Time, budget BGPRoutingBudget) error {
	if side.RPKI == nil {
		return ctx.Err()
	}
	capture := side.RPKI
	version, err := hex.DecodeString(capture.Version)
	if err != nil || len(version) != 32 || hex.EncodeToString(version) != capture.Version || capture.Records < 0 || capture.Records < int64(len(capture.Covering)) || capture.Prefix != routingRPKIPrefix(side) || !capture.Prefix.IsValid() || capture.ObservedAt.IsZero() || capture.ObservedAt.After(at) || !capture.ValidUntil.After(at) || len(capture.Verdicts) == 0 || len(capture.Verdicts) != len(side.Fields) {
		return errRoutingCaptureFormat
	}
	if err := chargeRoutingRPKICapture(ctx, capture, &budget); err != nil {
		return err
	}
	for i, field := range side.Fields {
		verdict, err := routingRPKIVerdict(ctx, capture.Prefix, field.OriginAS, capture.Covering, &budget)
		if err != nil {
			return err
		}
		if verdict != capture.Verdicts[i] {
			return errRoutingCaptureFormat
		}
	}
	return ctx.Err()
}

func routingCaptureRPKIQueryFields(ctx context.Context, side BGPRoutingFlowSide, prefix string, out *flowstore.RoutingProjection, budget *BGPRoutingBudget) error {
	if side.RPKI == nil {
		return ctx.Err()
	}
	if err := validateRoutingRPKICapture(ctx, &side, time.Unix(0, out.Clock), *budget); err != nil {
		return err
	}
	if err := chargeRoutingRPKICapture(ctx, side.RPKI, budget); err != nil {
		return err
	}
	status := side.RPKI.Verdicts[0]
	for _, verdict := range side.RPKI.Verdicts {
		if verdict != status {
			status = "unknown"
			break
		}
	}
	out.Fields[prefix+"bgp_rpki"] = status
	out.SourceIDs = append(out.SourceIDs, "rpki-vrps/"+side.RPKI.Version)
	return ctx.Err()
}
