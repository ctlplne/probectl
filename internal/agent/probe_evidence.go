// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package agent

import (
	"context"
	"errors"
	"math"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/canary"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/entity"
)

var errProbeEvidenceFull = errors.New("agent: probe evidence memory admission exhausted")

type queuedProbeEvidence struct {
	key         string
	observation entity.Observation
	bytes       int64
}

// One worker coalesces current observations per executable definition. The
// existing configured record/byte budgets bound pending plus in-flight memory;
// transport outages cannot block collection or ordinary result forwarding.
type probeEvidenceQueue struct {
	mu                  sync.Mutex
	emitter             SiteEvidenceEmitter
	pending             map[string]queuedProbeEvidence
	order               []string
	wake                chan struct{}
	maxRecords, records int
	maxBytes, bytes     int64
}

// WithProbeEvidence is configured before Run after the evidence credential has
// been checked against this agent's ordinary mTLS tenant/agent identity.
func (a *Agent) WithProbeEvidence(emitter SiteEvidenceEmitter) {
	if a == nil || a.host == nil || a.buffer == nil || emitter == nil {
		return
	}
	bytes := a.buffer.maxBytes
	if bytes <= 0 {
		bytes = defaultMaxBytes // an unbounded disk option never creates unbounded RAM
	}
	a.host.probeEvidence = &probeEvidenceQueue{emitter: emitter,
		pending: make(map[string]queuedProbeEvidence), wake: make(chan struct{}, 1),
		maxRecords: a.buffer.maxRecords, maxBytes: bytes}
}

func (h *Host) enqueueProbeEvidence(schedule scheduled, result canary.Result) {
	observation, err := h.probeObservation(schedule, result)
	if err == nil && observation.ICMP == nil {
		return // local-only/non-ICMP tests do not author canonical source evidence
	}
	if err == nil {
		err = h.probeEvidence.enqueue(observation)
	}
	if err != nil {
		if h.metrics != nil {
			h.metrics.Error()
		}
		records, bytes := h.probeEvidence.usage()
		h.log.Warn("probe evidence refused; ordinary collection continues", "tenant_id", h.tenantID,
			"agent_id", h.agentID, "memory_exhausted", errors.Is(err, errProbeEvidenceFull),
			"queued_records", records, "queued_bytes", bytes, "max_records", h.probeEvidence.maxRecords, "max_bytes", h.probeEvidence.maxBytes)
	}
}

func (h *Host) probeObservation(schedule scheduled, result canary.Result) (entity.Observation, error) {
	m := result.ICMP
	if result.Type != "icmp" || schedule.definitionHash == "" || schedule.testID == "" || m == nil {
		return entity.Observation{}, nil
	}
	if id, err := uuid.Parse(schedule.testID); err != nil || id == uuid.Nil || id.String() != schedule.testID {
		return entity.Observation{}, nil
	}
	requested := canary.ICMPRequestedPackets(schedule.canary)
	if requested == 0 {
		return entity.Observation{}, nil
	}
	if m.Expected < 0 || uint64(m.Expected) != requested {
		return entity.Observation{}, ErrEvidenceBatchInvalid
	}
	for _, count := range []int{m.Expected, m.Attempted, m.Transmitted, m.Replies, m.SendErrors} {
		if count < 0 || uint64(count) > math.MaxUint32 {
			return entity.Observation{}, ErrEvidenceBatchInvalid
		}
	}
	id, err := crypto.UUIDv4()
	if err != nil {
		return entity.Observation{}, err
	}
	observation := entity.Observation{ID: id,
		Source: entity.SourceKey{AgentID: h.agentID, Kind: entity.PathAgent, SourceRef: schedule.testID},
		Alias:  entity.AliasKey{Kind: entity.AddressAlias, Value: m.TargetIP}, SourceRef: "icmp:configured-test", ObservedAt: m.CompletedAt,
		ICMP: &entity.ICMPMeasurement{Version: 1, DefinitionHash: schedule.definitionHash,
			StartedAt: m.StartedAt, CompletedAt: m.CompletedAt, Requested: uint32(m.Expected), Attempted: uint32(m.Attempted),
			Transmitted: uint32(m.Transmitted), Replies: uint32(m.Replies), SendErrors: uint32(m.SendErrors),
			ReadComplete: m.ReadComplete, Canceled: m.Canceled, IOFailed: m.IOFailed, Responders: m.Responders}}
	return observation.Normalize(time.Now())
}

func probeEvidenceMemory(observation entity.Observation) int64 {
	// Conservative retained object/map/string charge, not a population ceiling.
	size := int64(1024 + 4*(len(observation.ID)+len(observation.Source.AgentID)+len(observation.Source.SourceRef)+len(observation.Alias.Value)+len(observation.ICMP.DefinitionHash)))
	for _, address := range observation.ICMP.Responders {
		size += int64(128 + 4*len(address))
	}
	return size
}

func (q *probeEvidenceQueue) enqueue(observation entity.Observation) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	key := observation.Source.SourceRef + "/" + observation.ICMP.DefinitionHash
	previous, exists := q.pending[key]
	if exists && observation.ObservedAt.Before(previous.observation.ObservedAt) {
		return nil
	}
	if exists && observation.ObservedAt.Equal(previous.observation.ObservedAt) {
		if observation.ID == previous.observation.ID {
			return nil
		}
		// Keep distinct same-clock observations so a source reader can
		// refuse conflicting health instead of accepting an arbitrary one.
		key += "/" + observation.ID
		previous, exists = q.pending[key]
		if exists {
			return nil
		}
	}
	bytes := probeEvidenceMemory(observation)
	if (!exists && q.records >= q.maxRecords) || bytes > q.maxBytes-(q.bytes-previous.bytes) {
		return errProbeEvidenceFull
	}
	if !exists {
		q.records++
		q.order = append(q.order, key)
	}
	q.bytes += bytes - previous.bytes
	q.pending[key] = queuedProbeEvidence{key: key, observation: observation, bytes: bytes}
	select {
	case q.wake <- struct{}{}:
	default:
	}
	return nil
}

func (q *probeEvidenceQueue) take() []queuedProbeEvidence {
	q.mu.Lock()
	defer q.mu.Unlock()
	count := min(64, len(q.order)) // existing evidence RPC batch contract
	batch := make([]queuedProbeEvidence, 0, count)
	for _, key := range q.order[:count] {
		batch = append(batch, q.pending[key])
		delete(q.pending, key)
	}
	q.order = q.order[count:]
	return batch // in-flight entries retain their memory/record charge
}

func (q *probeEvidenceQueue) release(batch []queuedProbeEvidence) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.records -= len(batch)
	for _, item := range batch {
		q.bytes -= item.bytes
	}
}

func (h *Host) runProbeEvidence(ctx context.Context) {
	q := h.probeEvidence
	backoff := minBackoff
	for ctx.Err() == nil {
		batch := q.take()
		if len(batch) == 0 {
			select {
			case <-ctx.Done():
				return
			case <-q.wake:
				continue
			}
		}
		observations := make([]entity.Observation, len(batch))
		for i, item := range batch {
			observations[i] = item.observation
		}
		call, cancel := context.WithTimeout(ctx, 5*time.Second)
		accepted, unresolved, err := q.emitter.Submit(call, observations)
		cancel()
		if err == nil && (accepted < 0 || unresolved < 0 || accepted > len(batch) || unresolved != len(batch)-accepted) {
			err = ErrEvidenceBatchInvalid
		}
		q.release(batch)
		if err == nil {
			backoff = minBackoff
			continue
		}
		if h.metrics != nil {
			h.metrics.Error()
		}
		h.log.Warn("probe evidence delivery failed; ordinary collection continues", "tenant_id", h.tenantID, "agent_id", h.agentID, "observations", len(batch))
		for _, item := range batch {
			// A newer queued observation wins; retries retain their UUID and
			// never replace fresh unknown/healthy data with an old failure.
			if err := q.enqueue(item.observation); err != nil && h.metrics != nil {
				h.metrics.Error()
			}
		}
		if !sleep(ctx, jittered(backoff)) {
			return
		}
		backoff = min(backoff*2, maxBackoff)
	}
}

func (q *probeEvidenceQueue) usage() (int, int64) {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.records, q.bytes
}
