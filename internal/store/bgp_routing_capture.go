// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strings"
	"time"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/tenancy"
)

var errRoutingCaptureFormat = errors.New("complete routing capture metadata is unavailable")

// Immutable content values are deliberately separate from observation clocks.
// The same full route/path content can be shared by many observed flows. These
// hashes identify data; they never grant context, source or reader authority.
// Persistence and reader authorization still require tenant-scoped storage and
// current actor/context/source checks; this codec performs no database writes.
type routingCaptureObject struct {
	payload string
	digest  [32]byte
}

type routingCaptureObjects struct {
	facts, clocks routingCaptureObject
	capturedAt    time.Time
}

type routingCaptureFacts struct {
	Version    int                        `json:"version"`
	Kind       string                     `json:"kind"`
	TenantID   string                     `json:"tenant_id"`
	Data       BGPRoutingFlowLookup       `json:"data"`
	Selections [2]*routingSourceSelection `json:"selections"`
}

type routingCaptureViewClock struct {
	AsOf, ValidUntil, LastObservedAt time.Time
	LastSequence                     int64
	NextHopExpiry                    []time.Time
}

type routingCaptureClocks struct {
	Version             int      `json:"version"`
	Kind                string   `json:"kind"`
	TenantID            string   `json:"tenant_id"`
	FactsDigest         [32]byte `json:"facts_digest"`
	OwnerClock          InterfaceRoleEvidenceClock
	OwnerSourceID       string
	Source, Destination routingCaptureViewClock
}

func freezeRoutingCapture(ctx context.Context, lookup BGPRoutingFlowLookup, budget BGPRoutingBudget) (routingCaptureObjects, error) {
	if err := ctx.Err(); err != nil {
		return routingCaptureObjects{}, err
	}
	if tenant, ok := tenancy.FromContext(ctx); !ok || tenant.String() != lookup.Owner.TenantID {
		return routingCaptureObjects{}, entity.ErrScopeMismatch
	}
	if err := admitRoutingCapture(ctx, lookup, budget); err != nil {
		return routingCaptureObjects{}, err
	}
	if err := validateRoutingCapture(ctx, lookup, budget); err != nil {
		return routingCaptureObjects{}, err
	}
	facts := routingCaptureFacts{Version: 1, Kind: "routing_facts", TenantID: lookup.Owner.TenantID, Data: lookup}
	clocks := routingCaptureClocks{Version: 1, Kind: "routing_clocks", TenantID: lookup.Owner.TenantID, OwnerClock: lookup.Owner.InterfaceRoleEvidenceClock, OwnerSourceID: lookup.Owner.SourceID}
	facts.Data.CapturedAt = time.Time{}
	facts.Data.Owner.InterfaceRoleEvidenceClock = InterfaceRoleEvidenceClock{}
	facts.Data.Owner.SourceID = ""
	for lane, side := range []*BGPRoutingFlowSide{&facts.Data.Source, &facts.Data.Destination} {
		facts.Selections[lane] = side.Route.Source.routingSelection
		clock := splitRoutingCaptureClock(side)
		if lane == 0 {
			clocks.Source = clock
		} else {
			clocks.Destination = clock
		}
	}
	result := routingCaptureObjects{capturedAt: lookup.CapturedAt}
	var err error
	result.facts, err = marshalRoutingCaptureObject(facts)
	if err != nil {
		return routingCaptureObjects{}, err
	}
	clocks.FactsDigest = result.facts.digest
	result.clocks, err = marshalRoutingCaptureObject(clocks)
	if err != nil {
		return routingCaptureObjects{}, err
	}
	if err := ctx.Err(); err != nil {
		return routingCaptureObjects{}, err
	}
	return result, nil
}

func splitRoutingCaptureClock(side *BGPRoutingFlowSide) routingCaptureViewClock {
	clock := routingCaptureViewClock{AsOf: side.Route.AsOf, ValidUntil: side.Route.ValidUntil, LastObservedAt: side.Route.LastObservedAt, LastSequence: side.Route.LastSequence}
	side.Route.AsOf, side.Route.ValidUntil, side.Route.LastObservedAt = time.Time{}, time.Time{}, time.Time{}
	side.Route.LastSequence = 0
	side.NextHops = append([]BGPRoutingNextHopAS(nil), side.NextHops...)
	for i := range side.NextHops {
		clock.NextHopExpiry = append(clock.NextHopExpiry, side.NextHops[i].ValidUntil)
		side.NextHops[i].ValidUntil = time.Time{}
	}
	return clock
}

func marshalRoutingCaptureObject(value any) (routingCaptureObject, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return routingCaptureObject{}, err
	}
	return routingCaptureObject{payload: string(raw), digest: routingCaptureHash(raw)}, nil
}

func decodeRoutingCapture(ctx context.Context, objects routingCaptureObjects, budget BGPRoutingBudget) (BGPRoutingFlowLookup, error) {
	if err := ctx.Err(); err != nil {
		return BGPRoutingFlowLookup{}, err
	}
	tenant, ok := tenancy.FromContext(ctx)
	if !ok {
		return BGPRoutingFlowLookup{}, entity.ErrScopeMismatch
	}
	if canonical, err := validRegistryUUID(tenant.String()); err != nil || canonical != tenant.String() {
		return BGPRoutingFlowLookup{}, entity.ErrScopeMismatch
	}
	if budget.MemoryBytes < 4096 || budget.WorkUnits < 1 {
		return BGPRoutingFlowLookup{}, ErrBGPRoutingBudget
	}
	for _, object := range []routingCaptureObject{objects.facts, objects.clocks} {
		if int64(len(object.payload)) > budget.MemoryBytes/16 || int64(len(object.payload)) > budget.WorkUnits/8 {
			return BGPRoutingFlowLookup{}, ErrBGPRoutingBudget
		}
		if err := routingBatchCharge(&budget, int64(len(object.payload))*16, int64(len(object.payload))*8); err != nil {
			return BGPRoutingFlowLookup{}, err
		}
		if err := admitRoutingCaptureJSON(ctx, object, &budget); err != nil {
			return BGPRoutingFlowLookup{}, err
		}
	}
	var facts routingCaptureFacts
	var clocks routingCaptureClocks
	if err := readRoutingCaptureObject(objects.facts, &facts); err != nil {
		return BGPRoutingFlowLookup{}, err
	}
	if err := readRoutingCaptureObject(objects.clocks, &clocks); err != nil {
		return BGPRoutingFlowLookup{}, err
	}
	if facts.Version != 1 || clocks.Version != 1 || facts.Kind != "routing_facts" || clocks.Kind != "routing_clocks" || facts.TenantID != tenant.String() || clocks.TenantID != tenant.String() || clocks.FactsDigest != objects.facts.digest {
		return BGPRoutingFlowLookup{}, errRoutingCaptureFormat
	}
	result := facts.Data
	result.CapturedAt = objects.capturedAt
	result.Owner.InterfaceRoleEvidenceClock = clocks.OwnerClock
	result.Owner.SourceID = clocks.OwnerSourceID
	for lane, side := range []*BGPRoutingFlowSide{&result.Source, &result.Destination} {
		clock := clocks.Source
		if lane != 0 {
			clock = clocks.Destination
		}
		if len(side.NextHops) != len(clock.NextHopExpiry) {
			return BGPRoutingFlowLookup{}, errRoutingCaptureFormat
		}
		side.Route.AsOf, side.Route.ValidUntil, side.Route.LastObservedAt = clock.AsOf, clock.ValidUntil, clock.LastObservedAt
		side.Route.LastSequence = clock.LastSequence
		side.Route.Source.routingSelection = facts.Selections[lane]
		for i := range side.NextHops {
			side.NextHops[i].ValidUntil = clock.NextHopExpiry[i]
		}
	}
	if err := validateRoutingCapture(ctx, result, budget); err != nil {
		return BGPRoutingFlowLookup{}, err
	}
	return result, nil
}

func readRoutingCaptureObject(object routingCaptureObject, value any) error {
	raw := []byte(object.payload)
	if routingCaptureHash(raw) != object.digest {
		return errRoutingCaptureFormat
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return errRoutingCaptureFormat
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return errRoutingCaptureFormat
	}
	// Only the exact canonical writer representation is accepted. Duplicate,
	// omitted or reordered keys cannot silently replace retained provenance.
	canonical, err := json.Marshal(value)
	if err != nil || !bytes.Equal(raw, canonical) {
		return errRoutingCaptureFormat
	}
	return nil
}

func validateRoutingCapture(ctx context.Context, lookup BGPRoutingFlowLookup, budget BGPRoutingBudget) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	tenant, ok := tenancy.FromContext(ctx)
	owner := lookup.Owner
	if !ok || tenant.String() != owner.TenantID {
		return entity.ErrScopeMismatch
	}
	if normalized, err := owner.Scope.Normalize(); err != nil || normalized != owner.Scope {
		return entity.ErrScopeMismatch
	}
	if router, err := validRegistryUUID(owner.RouterID); err != nil || router != owner.RouterID {
		return errRoutingCaptureFormat
	}
	id, hasID := strings.CutPrefix(owner.SourceID, "evidence/")
	if canonical, err := validRegistryUUID(id); !hasID || err != nil || canonical != id {
		return errRoutingCaptureFormat
	}
	if owner.AgentID == "" || owner.SourceID == "" || owner.ObservedAt.IsZero() || owner.Exporter.IsUnspecified() || owner.Exporter.IsMulticast() || !owner.Exporter.IsValid() || owner.Exporter.Zone() != "" || owner.Exporter.Is4In6() || !routingFlowProtocol(owner.Protocol) || lookup.CapturedAt.IsZero() || owner.ObservedAt.After(lookup.CapturedAt) || !owner.ValidUntil.After(lookup.CapturedAt) {
		return errRoutingCaptureFormat
	}
	for _, side := range []*BGPRoutingFlowSide{&lookup.Source, &lookup.Destination} {
		if err := validateRoutingCaptureSide(ctx, owner, side, lookup.CapturedAt, budget); err != nil {
			return err
		}
	}
	return nil
}

func validateRoutingCaptureSide(ctx context.Context, owner InterfaceRoleFlowBinding, side *BGPRoutingFlowSide, at time.Time, budget BGPRoutingBudget) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if side.State != "router_selected" {
		if (side.State != "no_prefix" && side.State != "source_unavailable") || side.Route.Source != (BGPRoutingSource{}) || side.Route.View != (BGPRoutingViewRef{}) || side.Route.Prefix.IsValid() || !side.Route.AsOf.IsZero() || !side.Route.ValidUntil.IsZero() || !side.Route.LastObservedAt.IsZero() || side.Route.LastSequence != 0 || side.Route.Paths != nil || side.Fields != nil || side.NextHops != nil {
			return errRoutingCaptureFormat
		}
		return nil
	}
	source := side.Route.Source
	if source.Scope != owner.Scope || source.RouterID != owner.RouterID {
		return entity.ErrScopeMismatch
	}
	if source.CollectorAgentID == "" || source.SourceRef == "" || source.SenderSerial == "" || source.OriginSerial == "" || source.ObservedAt.IsZero() || source.ObservedAt.After(at) {
		return errRoutingCaptureFormat
	}
	if source.routingSelection != nil && !validRoutingSelection(source, source.routingSelection) {
		return errRoutingCaptureFormat
	}
	for _, id := range []string{side.Route.View.ID, side.Route.View.Generation} {
		if canonical, err := validRegistryUUID(id); err != nil || canonical != id {
			return errRoutingCaptureFormat
		}
	}
	if !side.Route.Prefix.IsValid() || side.Route.Prefix.Masked() != side.Route.Prefix || len(side.Route.Paths) == 0 || len(side.Fields) != len(side.Route.Paths) || len(side.NextHops) != len(side.Route.Paths) || side.Route.AsOf.IsZero() || side.Route.AsOf.After(at) || !side.Route.ValidUntil.After(at) || side.Route.LastSequence <= 0 || side.Route.LastObservedAt.Before(source.ObservedAt) || side.Route.LastObservedAt.After(side.Route.AsOf) {
		return errRoutingCaptureFormat
	}
	return validateRoutingCapturePaths(ctx, side, at, budget)
}

func validateRoutingCapturePaths(ctx context.Context, side *BGPRoutingFlowSide, at time.Time, budget BGPRoutingBudget) error {
	fields, err := routingFlowPathFields(ctx, side.Route.Paths, budget)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(fields, side.Fields) {
		return errRoutingCaptureFormat
	}
	afi := uint16(2)
	if side.Route.Prefix.Addr().Is4() {
		afi = 1
	}
	for i, path := range side.Route.Paths {
		if err := ctx.Err(); err != nil {
			return err
		}
		if validateRoutingChange(path, afi) != nil || path.Prefix != side.Route.Prefix || path.Withdraw {
			return errRoutingCaptureFormat
		}
		if !validRoutingCaptureNextHop(side.NextHops[i], at) {
			return errRoutingCaptureFormat
		}
	}
	return nil
}

func validRoutingCaptureNextHop(field BGPRoutingNextHopAS, at time.Time) bool {
	if field.ASN == nil {
		return field.Sources == nil && field.ValidUntil.IsZero() && (field.Reason == "unresolved_next_hop" || field.Reason == "next_hop_as_conflict" || field.Reason == "expired_neighbor_observation")
	}
	if *field.ASN == 0 || *field.ASN == 23456 || field.Reason != "current_neighbor_observation" || !field.ValidUntil.After(at) || len(field.Sources) == 0 {
		return false
	}
	for i, source := range field.Sources {
		id, found := strings.CutPrefix(source, "evidence/")
		if canonical, err := validRegistryUUID(id); !found || err != nil || canonical != id || (i > 0 && source <= field.Sources[i-1]) {
			return false
		}
	}
	return true
}

func routingCaptureHash(raw []byte) (digest [32]byte) {
	copy(digest[:], crypto.Hash(raw))
	return digest
}
