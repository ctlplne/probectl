// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flow

import (
	"context"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"time"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/entity"
)

type evidenceSource struct {
	exporter string
	protocol string
	domain   uint32
}

// Accepted identity is refreshed before the server's 24-hour evidence expiry.
// An unavailable or unresolved writer backs off without claiming a canonical
// join or turning every flow packet into an RPC.
const (
	flowEvidenceRefresh         = 12 * time.Hour
	flowEvidenceRetry           = time.Minute
	flowEvidenceUnresolvedRetry = time.Hour
	flowEvidenceMaxLag          = 11 * time.Hour
	flowFaultRefresh            = 5 * time.Minute
	flowFaultPendingMaxAge      = 6 * 24 * time.Hour
)

// FlowFaultEmitter is optional. The bounded quality worker never sends a
// fault through the raw UDP/bus path or blocks raw flow publication on RPC.
type FlowFaultEmitter interface {
	SubmitFaults(context.Context, []entity.FaultObservation) (int, error)
}

// RefreshEvidenceAfterRotation drops accepted-snapshot throttles so the next
// batch authenticates current exporter identity with the new certificate.
func (c *Collector) RefreshEvidenceAfterRotation() {
	if c == nil || c.evidenceReset == nil {
		return
	}
	select {
	case c.evidenceReset <- struct{}{}:
	default:
	}
}

// evidenceLoop has one worker and a one-batch queue so a slow restricted RPC
// never stalls the raw flow bus. It submits at most 64 claims for each batch,
// once per exporter/domain/protocol per refresh or retry interval.
func (c *Collector) evidenceLoop(ctx context.Context) {
	lastAccepted := make(map[evidenceSource]time.Time)
	lastAttempt := make(map[evidenceSource]time.Time)
	lastPartial := make(map[evidenceSource]time.Time)
	lastFault := make(map[string]time.Time)
	pendingFault := make(map[string]entity.FaultObservation)
	for {
		select {
		case <-ctx.Done():
			return
		case <-c.evidenceReset:
			lastAccepted = make(map[evidenceSource]time.Time)
			lastAttempt = make(map[evidenceSource]time.Time)
			lastPartial = make(map[evidenceSource]time.Time)
			// A newly issued SVID cannot attest a fault observed before its
			// issuance. Retain the successful outage throttle but restate any
			// unacknowledged current fault at the next quality window.
			pendingFault = make(map[string]entity.FaultObservation)
		case receipts := <-c.faultQueue:
			c.sendFlowFaults(ctx, receipts, lastFault, pendingFault)
		case batch := <-c.evidenceQueue:
			now := c.now()
			claims, keys := c.flowEvidenceClaims(batch, lastAccepted, lastAttempt, lastPartial, now)
			if len(claims) == 0 {
				continue
			}
			accepted, unresolved, err := c.evidence.Submit(ctx, claims)
			for _, key := range keys {
				lastAttempt[key] = now
			}
			if len(lastAttempt) > 4096 {
				// A hostile exporter can vary observation-domain IDs, including
				// while the RPC is failing. The optional throttle stays bounded.
				lastAccepted = make(map[evidenceSource]time.Time)
				lastAttempt = make(map[evidenceSource]time.Time)
				lastPartial = make(map[evidenceSource]time.Time)
			}
			if err != nil {
				c.stats.EvidenceErrors.Add(1)
				c.log.Warn("flow canonical evidence unavailable; raw events retained",
					"tenant_id", c.cfg.TenantID, "agent_id", c.cfg.AgentID,
					"count", len(claims), "error", err.Error())
				continue
			}
			c.stats.EvidenceAccepted.Add(uint64(accepted))
			c.stats.EvidenceUnresolved.Add(uint64(unresolved))
			if unresolved == 0 && accepted == len(claims) {
				for _, key := range keys {
					lastAccepted[key] = now
					delete(lastPartial, key)
				}
			} else if accepted > 0 {
				// The response is aggregate, so throttle all keys in a partial
				// batch instead of rewriting accepted aliases per flow packet.
				// A wholly unresolved batch wrote no accepted aliases and can
				// retry after the ordinary one-minute transport interval.
				for _, key := range keys {
					lastPartial[key] = now
				}
			}
		}
	}
}

// sendFlowFaults consumes only the existing, validated quality state for an
// explicitly configured exporter. One pending UUID survives a lost response;
// the server's durable receipt then prevents an incident replay. A successful
// persistent outage refreshes within the normal 10-minute correlation window.
func (c *Collector) sendFlowFaults(ctx context.Context, receipts []QualityReceipt,
	lastFault map[string]time.Time, pending map[string]entity.FaultObservation) {
	emitter, ok := c.evidence.(FlowFaultEmitter)
	if !ok {
		return
	}
	now := c.now()
	// One exporter may have several flow protocols. A live protocol means the
	// exporter is not silent, regardless of another protocol's stale window.
	allStale := make(map[string]bool, len(receipts))
	windowEnd := make(map[string]time.Time, len(receipts))
	windowStart := make(map[string]time.Time, len(receipts))
	for _, receipt := range receipts {
		exporter := receipt.ExporterAddress
		if _, configured := c.evidenceSources[exporter]; !configured {
			continue
		}
		if receipt.WindowEndedAt.After(windowEnd[exporter]) {
			windowEnd[exporter] = receipt.WindowEndedAt
		}
		if start, seen := windowStart[exporter]; !seen || receipt.WindowStartedAt.Before(start) {
			windowStart[exporter] = receipt.WindowStartedAt
		}
		if _, seen := allStale[exporter]; !seen {
			allStale[exporter] = true
		}
		if receipt.State != QualityStateStale ||
			receipt.Reason != QualityReasonNoRecentPackets {
			allStale[exporter] = false
		}
	}
	exporters := make([]string, 0, len(allStale))
	for exporter := range allStale {
		exporters = append(exporters, exporter)
	}
	sort.Strings(exporters)
	latestPacket := make(map[string]time.Time, len(exporters))
	c.qualityMu.Lock()
	lastEviction := c.qualityEvictedAt
	for key, row := range c.quality {
		if row != nil && row.lastPacketAt.After(latestPacket[key.exporter]) {
			latestPacket[key.exporter] = row.lastPacketAt
		}
	}
	c.qualityMu.Unlock()
	faults := make([]entity.FaultObservation, 0, 64)
	flush := func() {
		if len(faults) == 0 {
			return
		}
		accepted, err := emitter.SubmitFaults(ctx, faults)
		if err != nil || accepted != len(faults) {
			if err == nil {
				err = fmt.Errorf("fault batch accepted %d of %d", accepted, len(faults))
			}
			c.stats.EvidenceErrors.Add(1)
			c.log.Warn("flow exporter fault evidence unavailable; quality receipt retained",
				"tenant_id", c.cfg.TenantID, "agent_id", c.cfg.AgentID,
				"count", len(faults), "error", err)
		} else {
			for _, fault := range faults {
				lastFault[fault.Target] = now
				delete(pending, fault.Target)
			}
		}
		faults = faults[:0]
	}
	for _, exporter := range exporters {
		// The bounded table may have discarded a recovery packet after this
		// receipt was queued. A window spanning any eviction is incomplete;
		// suppress the optional fault until a complete later window exists.
		if !lastEviction.IsZero() && !lastEviction.Before(windowStart[exporter]) {
			allStale[exporter] = false
		}
		// The optional one-batch queue may hold a stale window while a new
		// packet arrives. A dropped recovery batch must not turn that old
		// snapshot into a current exporter-silence signal.
		if !windowEnd[exporter].IsZero() && !latestPacket[exporter].IsZero() &&
			!latestPacket[exporter].Before(windowEnd[exporter]) {
			allStale[exporter] = false
		}
		if !allStale[exporter] {
			delete(lastFault, exporter)
			delete(pending, exporter)
			continue
		}
		if last := lastFault[exporter]; !last.IsZero() && now.Before(last.Add(flowFaultRefresh)) {
			continue
		}
		fault, exists := pending[exporter]
		if exists && now.Sub(fault.ObservedAt) > flowFaultPendingMaxAge {
			// The receiver refuses observations more than seven days old. A
			// continuing outage is a new event after six days, not an endless
			// retry of a stale UUID that can no longer be accepted.
			delete(pending, exporter)
			exists = false
		}
		if !exists {
			id, err := crypto.UUIDv4()
			if err != nil {
				c.stats.EvidenceErrors.Add(1)
				continue
			}
			fault = entity.FaultObservation{ID: id,
				Source: entity.SourceKey{AgentID: c.cfg.AgentID,
					Kind: entity.FlowExporter, SourceRef: exporter},
				Target: exporter, Kind: entity.FaultFlowExporterSilent,
				ObservedAt: now}
			pending[exporter] = fault
		}
		faults = append(faults, fault)
		if len(faults) == 64 {
			flush()
		}
	}
	flush()
}

func (c *Collector) flowEvidenceClaims(batch []Record, lastAccepted,
	lastAttempt, lastPartial map[evidenceSource]time.Time, now time.Time) ([]entity.Observation, []evidenceSource) {
	claims := make([]entity.Observation, 0, 64)
	keys := make([]evidenceSource, 0, 32)
	seen := make(map[evidenceSource]struct{})
	for _, rec := range batch {
		switch rec.Protocol {
		case ProtoNetFlow5, ProtoNetFlow9, ProtoIPFIX, ProtoSFlow5:
		default:
			continue
		}
		addr, err := netip.ParseAddr(rec.Exporter)
		if err != nil || addr.Zone() != "" {
			continue
		}
		exporter := addr.Unmap().String()
		if _, allowed := c.evidenceSources[exporter]; !allowed {
			continue
		}
		key := evidenceSource{exporter: exporter, protocol: rec.Protocol, domain: rec.ObservationDomain}
		at := rec.ObservedAt.UTC()
		// A delayed packet may be valid raw telemetry but cannot refresh
		// identity for 12 hours if its server-owned evidence expiry is
		// already close. Check this before deduplication: a stale record
		// must not hide a fresh one with the same exporter/domain later in
		// this bounded batch.
		if at.IsZero() || !at.After(now.Add(-flowEvidenceMaxLag)) {
			continue
		}
		if _, duplicate := seen[key]; duplicate {
			continue
		}
		if len(seen) >= 4096 {
			break // untrusted domain churn never allocates an unbounded scan map
		}
		seen[key] = struct{}{}
		// An hour of slack covers the next RPC and clock skew; the server
		// still validates the original timestamp.
		if last := lastAccepted[key]; !last.IsZero() && now.Before(last.Add(flowEvidenceRefresh)) {
			continue
		}
		if last := lastPartial[key]; !last.IsZero() && now.Before(last.Add(flowEvidenceUnresolvedRetry)) {
			continue
		}
		if last := lastAttempt[key]; !last.IsZero() && now.Before(last.Add(flowEvidenceRetry)) {
			continue
		}
		if len(claims) == 64 {
			break
		}
		source := entity.SourceKey{AgentID: c.cfg.AgentID, Kind: entity.FlowExporter,
			SourceRef: exporter}
		for _, alias := range []entity.AliasKey{
			{Kind: entity.AddressAlias, Value: exporter},
			{Kind: entity.FlowExporterAlias, Value: fmt.Sprintf("%s/%s/%d", exporter, rec.Protocol, rec.ObservationDomain)},
		} {
			id, err := crypto.UUIDv4()
			if err != nil {
				c.stats.EvidenceErrors.Add(1)
				return nil, nil
			}
			claims = append(claims, entity.Observation{ID: id, Source: source,
				Alias: alias, SourceRef: "flow:" + rec.Protocol + ":domain:" +
					strconv.FormatUint(uint64(rec.ObservationDomain), 10), ObservedAt: at})
		}
		keys = append(keys, key)
	}
	return claims, keys
}
