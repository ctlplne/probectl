// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"math/bits"
	"sort"
	"strconv"
	"time"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type carrierSLATestKey struct{ context, device, agent, test string }

func carrierSLASourceKey(item store.IncidentConfiguredTest) carrierSLATestKey {
	return carrierSLATestKey{item.ContextID, item.EntityID, item.AgentID, item.TestID}
}

type carrierSLAOriginals struct {
	source                                       store.IncidentConfiguredTest
	population                                   flow.CarrierSLAPopulation
	originals, good, failed, unknown, samples    uint64
	transmitted, lost, rttSum                    big.Int
	rtts                                         []uint64
	packetUnknown, latencyUnknown, repairUnknown bool
	failureStart                                 time.Time
	maximumRepair                                time.Duration
	lastAt                                       time.Time
	lastID                                       string
	digest                                       [32]byte
}

type carrierSLAAccumulator struct {
	tenant       string
	from, to     time.Time
	sources      []carrierSLAOriginals
	indexes      map[carrierSLATestKey]int
	memory, work int64
	partial      bool
}

func newCarrierSLAAccumulator(ctx context.Context, sources []store.IncidentConfiguredTest, from, to time.Time, memory, work int64) (*carrierSLAAccumulator, error) {
	tenant, ok := tenancy.FromContext(ctx)
	if !ok {
		return nil, tenancy.ErrNoTenant
	}
	if len(sources) == 0 || from.IsZero() || !to.After(from) {
		return nil, flow.ErrCarrierSLAInput
	}
	if memory < 8192 || int64(len(sources)) > memory/4096 || work <= 0 {
		return nil, store.ErrClientReportBudget
	}
	a := &carrierSLAAccumulator{tenant: tenant.String(), from: from, to: to, indexes: map[carrierSLATestKey]int{}, memory: memory, work: work}
	for _, source := range sources {
		if source.TenantID != a.tenant {
			return nil, entity.ErrScopeMismatch
		}
		key := carrierSLASourceKey(source)
		if _, found := a.indexes[key]; found {
			return nil, flow.ErrCarrierSLAInput
		}
		a.indexes[key] = len(a.sources)
		a.sources = append(a.sources, carrierSLAOriginals{source: source, population: flow.CarrierSLAPopulation{ID: source.ContextID + ":" + source.EntityID + ":" + source.AgentID + ":" + source.TestID, ContextID: source.ContextID, DeviceID: source.EntityID, AgentID: source.AgentID, TestID: source.TestID, ObservedNotBefore: source.CurrentSince}})
		a.memory -= 4096 + int64(len(source.AgentID))
	}
	if a.memory < 0 {
		return nil, store.ErrClientReportBudget
	}
	return a, ctx.Err()
}

func (a *carrierSLAAccumulator) observe(ctx context.Context, item store.IncidentTestMeasurement) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if item.TenantID != a.tenant {
		return entity.ErrScopeMismatch
	}
	key := carrierSLATestKey{item.ContextID, item.EntityID, item.AgentID, item.TestID}
	index, ok := a.indexes[key]
	if !ok {
		return entity.ErrScopeMismatch
	}
	p := &a.sources[index]
	if item.SourceGeneration != p.source.SourceGeneration || item.EvidenceID == "" || item.ObservedAt.Before(a.from) || !item.ObservedAt.Before(a.to) || item.ObservedAt.Before(p.lastAt) || item.ObservedAt.Equal(p.lastAt) && item.EvidenceID <= p.lastID {
		return flow.ErrCarrierSLAInput
	}
	raw, err := json.Marshal(item)
	if err != nil {
		return err
	}
	if int64(len(raw))+256 > a.work || int64(len(raw)) > a.memory/4 {
		return store.ErrClientReportBudget
	}
	a.work -= int64(len(raw)) + 256
	p.digest = carrierSLAChainDigest(p.digest, raw)
	p.lastAt, p.lastID = item.ObservedAt, item.EvidenceID
	p.originals++
	observation := incidentTestObservation(item)
	started, completed := item.ObservedAt, item.ObservedAt
	if item.ICMP != nil {
		started, completed = item.ICMP.StartedAt, item.ICMP.CompletedAt
	}
	if item.Outcome != nil {
		started, completed = item.Outcome.StartedAt, item.Outcome.CompletedAt
	}
	if started.Before(a.from) || !completed.Before(a.to) {
		observation.Status = "unknown"
	}
	switch observation.Status {
	case "successful":
		p.good++
	case "failed":
		p.failed++
	default:
		p.unknown++
		p.packetUnknown, p.latencyUnknown, p.repairUnknown = true, true, true
		p.failureStart = time.Time{}
		return nil
	}
	if observation.Status == "failed" {
		if p.failureStart.IsZero() {
			p.failureStart = completed
		}
	} else if !p.failureStart.IsZero() {
		span := completed.Sub(p.failureStart)
		if span > p.maximumRepair {
			p.maximumRepair = span
		}
		p.failureStart = time.Time{}
	}
	if m := item.ICMP; m != nil {
		p.transmitted.Add(&p.transmitted, new(big.Int).SetUint64(uint64(m.Transmitted)))
		p.lost.Add(&p.lost, new(big.Int).SetUint64(uint64(m.Transmitted-m.Replies)))
		if m.RoundTrips == nil {
			p.latencyUnknown = true
			return nil
		}
		if int64(len(m.RoundTrips.Nanos)) > a.memory/16 {
			return store.ErrClientReportBudget
		}
		a.memory -= int64(len(m.RoundTrips.Nanos)) * 16
		for _, nanos := range m.RoundTrips.Nanos {
			p.rttSum.Add(&p.rttSum, new(big.Int).SetUint64(nanos))
			p.samples++
		}
		p.rtts = append(p.rtts, m.RoundTrips.Nanos...)
	} else {
		p.packetUnknown, p.latencyUnknown = true, true
	}
	return nil
}

func carrierSLAChainDigest(previous [32]byte, raw []byte) [32]byte {
	var digest [32]byte
	copy(digest[:], crypto.Hash(append(previous[:], raw...)))
	return digest
}

func (a *carrierSLAAccumulator) finish(ctx context.Context, terms flow.CarrierSLATerms, memory, work int64) (flow.CarrierSLACredit, []flow.CarrierSLAPopulation, error) {
	populations := make([]flow.CarrierSLAPopulation, 0, len(a.sources))
	citations := make([]string, 0, len(a.sources))
	var good, total, samples uint64
	var transmitted, lost, rttSum big.Int
	rtts := []uint64{}
	complete, packetsComplete, latencyComplete, repairComplete := !a.partial, true, true, true
	var maximumRepair time.Duration
	for _, p := range a.sources {
		if err := ctx.Err(); err != nil {
			return flow.CarrierSLACredit{}, nil, err
		}
		pop := p.population
		pop.Originals, pop.Successful, pop.Failed, pop.Unknown = strconv.FormatUint(p.originals, 10), strconv.FormatUint(p.good, 10), strconv.FormatUint(p.failed, 10), strconv.FormatUint(p.unknown, 10)
		pop.Transmitted, pop.Lost, pop.RTTSamples = p.transmitted.String(), p.lost.String(), strconv.FormatUint(p.samples, 10)
		pop.Digest = hex.EncodeToString(p.digest[:])
		populations = append(populations, pop)
		citations = append(citations, pop.ID+":sha256:"+pop.Digest)
		complete = complete && p.originals > 0 && p.unknown == 0
		packetsComplete = packetsComplete && !p.packetUnknown
		latencyComplete = latencyComplete && !p.latencyUnknown
		repairComplete = repairComplete && !p.repairUnknown && p.failureStart.IsZero()
		good, total, samples = good+p.good, total+p.originals, samples+p.samples
		transmitted.Add(&transmitted, &p.transmitted)
		lost.Add(&lost, &p.lost)
		rttSum.Add(&rttSum, &p.rttSum)
		if int64(len(p.rtts)) > a.memory/16 {
			return flow.CarrierSLACredit{}, nil, store.ErrClientReportBudget
		}
		a.memory -= int64(len(p.rtts)) * 16
		rtts = append(rtts, p.rtts...)
		if p.maximumRepair > maximumRepair {
			maximumRepair = p.maximumRepair
		}
	}
	comparisons := int64(bits.Len(uint(len(rtts))) + 1)
	if int64(len(rtts)) > a.work/comparisons {
		return flow.CarrierSLACredit{}, nil, store.ErrClientReportBudget
	}
	sort.Slice(rtts, func(i, j int) bool { return rtts[i] < rtts[j] })
	measurements := make([]flow.CarrierSLAMeasurement, 0, len(terms.Rules))
	for _, rule := range terms.Rules {
		m := flow.CarrierSLAMeasurement{TenantID: a.tenant, ID: rule.ID, RuleID: rule.ID, Basis: rule.Basis, From: a.from, To: a.to, Complete: complete, Citations: citations}
		switch {
		case rule.Metric == "availability" && rule.Basis == "original_execution_ratio":
			m.Complete = m.Complete && total > 0
			if total > 0 {
				m.Value = new(big.Rat).SetFrac(new(big.Int).SetUint64(good), new(big.Int).SetUint64(total)).RatString()
			}
		case rule.Metric == "loss" && rule.Basis == "original_packet_ratio":
			m.Complete = m.Complete && packetsComplete && transmitted.Sign() > 0
			if transmitted.Sign() > 0 {
				m.Value = new(big.Rat).SetFrac(&lost, &transmitted).RatString()
			}
		case rule.Metric == "latency_nanos" && rule.Basis == "original_rtt_mean":
			m.Complete = m.Complete && latencyComplete && samples > 0
			if samples > 0 {
				m.Value = new(big.Rat).SetFrac(&rttSum, new(big.Int).SetUint64(samples)).RatString()
			}
		case rule.Metric == "latency_nanos" && rule.Basis == "original_rtt_p95":
			m.Complete = m.Complete && latencyComplete && samples > 0
			if samples > 0 {
				rank := samples - samples/20
				m.Value = strconv.FormatUint(rtts[rank-1], 10)
			}
		case rule.Metric == "repair_nanos" && rule.Basis == "original_failure_interval":
			m.Complete = m.Complete && repairComplete
			m.Value = strconv.FormatInt(int64(maximumRepair), 10)
		default:
			m.Complete = false
		}
		measurements = append(measurements, m)
	}
	credit, err := flow.AssessCarrierSLA(ctx, terms, a.from, a.to, measurements, memory, work)
	return credit, populations, err
}
