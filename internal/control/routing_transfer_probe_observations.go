// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"errors"
	"math/big"
	"slices"
	"strconv"
	"time"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testspec"
)

const maxRoutingProbeSlots = 10000

type routingTransferProbeObservations struct {
	Target       string                     `json:"target"`
	From         time.Time                  `json:"from"`
	To           time.Time                  `json:"to"`
	Status       string                     `json:"status"`
	Reason       string                     `json:"reason,omitempty"`
	PairedRounds uint32                     `json:"paired_rounds"`
	Source       *routingTransferProbeStats `json:"source,omitempty"`
	Candidate    *routingTransferProbeStats `json:"candidate,omitempty"`
	proof        [32]byte
}

type routingTransferProbeStats struct {
	TestID      string  `json:"test_id"`
	AgentID     string  `json:"agent_id"`
	Transmitted uint32  `json:"transmitted"`
	Replies     uint32  `json:"replies"`
	Reachable   bool    `json:"reachable"`
	LossRatio   string  `json:"loss_ratio"`
	P95RTTNanos *string `json:"p95_rtt_nanos,omitempty"`
}

type routingTransferProbeSlot struct {
	ObservationID string
	Digest        [32]byte
	StartedAt     time.Time
	Transmitted   uint32
	Replies       uint32
	RTTs          []uint64
}

type routingProbeScan struct {
	plan     routingTransferProbePlan
	from, to time.Time
	interval time.Duration
	slots    [][2]routingTransferProbeSlot
	unknown  bool
}

func readRoutingTransferProbeObservationsInScope(ctx context.Context, sc tenancy.Scope, op capacityAgreementOperation,
	plan routingTransferProbePlan, from, to time.Time) (routingTransferProbeObservations, error) {
	out := routingTransferProbeObservations{Target: plan.target.String(), From: from, To: to, Status: "unavailable"}
	interval, err := routingProbeComparisonInterval(plan)
	if err != nil {
		return out, err
	}
	duration := to.Sub(from)
	count := duration / interval
	if duration <= 0 || duration%interval != 0 || count < 1 || to.After(time.Now()) {
		return out, apierror.Validation("the closed window must contain whole intervals of both routing probes")
	}
	if count > maxRoutingProbeSlots || int64(count) > op.budget.MemoryBytes/2048 {
		return out, flowstore.ErrExplorerBudget
	}
	for _, probe := range plan.tests {
		if from.Before(probe.CurrentSince) {
			out.Reason = "current_assignment_does_not_cover_window"
			return out, nil
		}
	}
	scan := routingProbeScan{plan: plan, from: from, to: to, interval: interval, slots: make([][2]routingTransferProbeSlot, int(count))}
	budget := store.ConfiguredMeasurementScanBudget{MemoryBytes: op.budget.MemoryBytes / 8,
		ReadBytes: op.budget.ReadBytes / 8, ReadRows: int64(op.budget.ReadRows / 8), ChargeRead: op.chargeRead}
	err = store.NewEntityRegistry(nil).WalkConfiguredTestMeasurementsInScope(ctx, sc, plan.tests[:], from, to, budget, scan.add)
	if errors.Is(err, store.ErrIncidentImpactBudget) {
		return out, flowstore.ErrExplorerBudget
	}
	if err != nil {
		return out, err
	}
	if !scan.complete() {
		out.Reason = "incomplete_paired_upstream_measurement"
		return out, nil
	}
	out.Status = "measured"
	out.PairedRounds = uint32(count) // bounded by maxRoutingProbeSlots
	out.Source, out.Candidate = scan.stats(0), scan.stats(1)
	digest, err := hashFlowRoleInputs(ctx, nil, struct {
		Target   string
		From, To time.Time
		Expected [2]testspec.RoutingProbeBinding
		Slots    [][2]routingTransferProbeSlot
	}{out.Target, from, to, plan.bindings, scan.slots}, op.budget.MemoryBytes/4)
	copy(out.proof[:], digest)
	return out, err
}

func routingProbeComparisonInterval(plan routingTransferProbePlan) (time.Duration, error) {
	a, b := plan.tests[0].Definition, plan.tests[1].Definition
	if a.IntervalSeconds < 1 || a.IntervalSeconds > 86400 || a.IntervalSeconds != b.IntervalSeconds ||
		a.TimeoutSeconds < 1 || a.TimeoutSeconds != b.TimeoutSeconds || a.TimeoutSeconds >= a.IntervalSeconds {
		return 0, apierror.Validation("paired routing probes require equal intervals and shorter equal timeouts")
	}
	// These parameters alter the measured packet profile or cadence. A local
	// interface, peer or IP may differ while the measured workload stays equal.
	for _, parameter := range [...]string{"count", "mode", "payload_bytes", "dscp", "privileged", "read_buffer_bytes"} {
		if a.Params[parameter] != b.Params[parameter] {
			return 0, apierror.Validation("paired routing probes require the same packet profile")
		}
	}
	return time.Duration(a.IntervalSeconds) * time.Second, nil
}

func (s *routingProbeScan) add(item store.IncidentTestMeasurement) error {
	lane := 0
	if item.TestID == s.plan.tests[1].TestID {
		lane = 1
	}
	source := s.plan.tests[lane]
	if item.TenantID != source.TenantID || item.ContextID != source.ContextID || item.EntityID != source.EntityID ||
		item.TestID != source.TestID || item.AgentID != source.AgentID || item.SourceGeneration != source.SourceGeneration {
		return entity.ErrScopeMismatch
	}
	m := item.ICMP
	if !item.Available || m == nil || m.Version != entity.ICMPVersionEgress || m.Egress == nil || m.RoundTrips == nil ||
		!m.Egress.SameCoordinates(s.plan.bindings[lane].Egress) || item.Alias != s.plan.target.String() ||
		item.ObservationID == "" || item.CaptureDigest == [32]byte{} || m.Requested > entity.MaxICMPEgressAttempts ||
		m.Transmitted == 0 || m.Egress.Transmitted != m.Transmitted || m.Requested != m.Transmitted ||
		m.Replies > m.Transmitted || uint64(len(m.RoundTrips.Nanos)) != uint64(m.Replies) {
		s.unknown = true
		return nil
	}
	if m.StartedAt.Before(s.from) || !m.CompletedAt.Before(s.to) {
		return nil
	}
	index := int(m.StartedAt.Sub(s.from) / s.interval)
	if index >= len(s.slots) || s.slots[index][lane].ObservationID != "" {
		s.unknown = true
		return nil
	}
	s.slots[index][lane] = routingTransferProbeSlot{ObservationID: item.ObservationID, Digest: item.CaptureDigest, StartedAt: m.StartedAt,
		Transmitted: m.Transmitted, Replies: m.Replies, RTTs: slices.Clone(m.RoundTrips.Nanos)}
	return nil
}

func (s *routingProbeScan) complete() bool {
	if s.unknown {
		return false
	}
	for _, pair := range s.slots {
		if pair[0].ObservationID == "" || pair[1].ObservationID == "" ||
			pair[0].StartedAt.Sub(pair[1].StartedAt).Abs() > s.interval/2 {
			return false
		}
	}
	return true
}

func (s *routingProbeScan) stats(lane int) *routingTransferProbeStats {
	out := &routingTransferProbeStats{TestID: s.plan.tests[lane].TestID, AgentID: s.plan.tests[lane].AgentID}
	var samples []uint64
	for _, pair := range s.slots {
		slot := pair[lane]
		out.Transmitted += slot.Transmitted
		out.Replies += slot.Replies
		samples = append(samples, slot.RTTs...)
	}
	out.Reachable = out.Replies > 0
	out.LossRatio = big.NewRat(int64(out.Transmitted-out.Replies), int64(out.Transmitted)).RatString()
	if len(samples) > 0 {
		slices.Sort(samples)
		nanos := strconv.FormatUint(samples[(95*len(samples)+99)/100-1], 10)
		out.P95RTTNanos = &nanos
	}
	return out
}
