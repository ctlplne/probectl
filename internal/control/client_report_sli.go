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
	"strconv"
	"time"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/incident"
	"github.com/ctlplne/probectl/internal/slo"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testspec"
)

type clientReportOutcomeCounts struct {
	Successful, Failed, Unknown, Canceled          string
	AvailabilityNumerator, AvailabilityDenominator string
	Coverage                                       string
}

type clientReportTestSelector struct {
	ContextID, EntityID, TestID, AgentID, Name, Type, DefinitionDigest string
	SourceGeneration                                                   int64
}

type clientReportAvailability struct {
	TenantID                       string
	Source                         clientReportTestSelector
	From, To                       time.Time
	Counts                         clientReportOutcomeCounts
	OriginalCount, OriginalsDigest string
}

type clientReportSLO struct {
	TenantID, Name, DisplayName, Service, DefinitionDigest, ObjectiveRatio, Basis string
	From, To                                                                      time.Time
	Counts                                                                        clientReportOutcomeCounts
	ObservedMeetsObjective                                                        *bool
	Sources                                                                       []clientReportTestSelector
	OriginalCount, OriginalsDigest                                                string
}

type clientReportOutcomeCounter struct {
	successful, failed, unknown, canceled, originals uint64
	chain                                            [32]byte
}

func (c *clientReportOutcomeCounter) add(observation incident.ImpactTestObservation, digest [32]byte) {
	c.originals++
	switch observation.Status {
	case "successful":
		c.successful++
	case "failed":
		c.failed++
	case "canceled":
		c.canceled++
		c.unknown++
	default:
		c.unknown++
	}
	var step [64]byte
	copy(step[:32], c.chain[:])
	copy(step[32:], digest[:])
	copy(c.chain[:], crypto.Hash(step[:]))
}

func (c clientReportOutcomeCounter) counts() clientReportOutcomeCounts {
	coverage := "observed_outcomes_only_not_schedule_completeness"
	if c.successful+c.failed == 0 {
		coverage = "no_known_outcomes"
	} else if c.unknown > 0 {
		coverage = "partial_observation_coverage"
	}
	return clientReportOutcomeCounts{Successful: strconv.FormatUint(c.successful, 10), Failed: strconv.FormatUint(c.failed, 10), Unknown: strconv.FormatUint(c.unknown, 10), Canceled: strconv.FormatUint(c.canceled, 10),
		AvailabilityNumerator: strconv.FormatUint(c.successful, 10), AvailabilityDenominator: strconv.FormatUint(c.successful+c.failed, 10), Coverage: coverage}
}

type clientReportSourceCursor struct {
	at time.Time
	id string
}

// Source state is proportional to configured tests and SLO matches, never the
// number of retained executions. Repository cursors supply unique originals in
// source/clock/ID order; each full capture digest contributes to the hash chain.
// The digest is query provenance, never a reusable source-read grant.
type clientReportSLIAccumulator struct {
	tenant          string
	from, to, first time.Time
	selected        map[incidentTestSummaryKey]int
	availability    []clientReportAvailability
	slos            []clientReportSLO
	counters        []clientReportOutcomeCounter
	sloCounters     []clientReportOutcomeCounter
	matches         [][]int
	cursors         []clientReportSourceCursor
	work            int64
	finished        bool
	failed          error
}

func newClientReportSLIAccumulator(ctx context.Context, tenant string, sources []store.IncidentConfiguredTest, definitions []slo.SLO, from, to time.Time, memory, work int64) (*clientReportSLIAccumulator, error) {
	bound, ok := tenancy.FromContext(ctx)
	if !ok || bound.String() != tenant {
		return nil, entity.ErrScopeMismatch
	}
	if from.IsZero() || !to.After(from) || memory < 4096 || work <= 0 {
		return nil, store.ErrClientReportBudget
	}
	a := &clientReportSLIAccumulator{tenant: tenant, from: from, to: to, first: from, selected: map[incidentTestSummaryKey]int{}, availability: []clientReportAvailability{}, slos: []clientReportSLO{}, work: work}
	if int64(len(sources)) > memory/4096 || int64(len(definitions)) > memory/4096 {
		return nil, store.ErrClientReportBudget
	}
	for _, source := range sources {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if source.TenantID != tenant {
			return nil, entity.ErrScopeMismatch
		}
		if source.SourceGeneration <= 0 {
			return nil, entity.ErrInvalidClaim
		}
		if source.Definition.ID != source.TestID || source.Definition.Type != source.Type || source.Definition.Target != source.Target {
			return nil, entity.ErrConflictingEvidence
		}
		key := incidentTestSummaryKey{source.ContextID, source.EntityID, source.TestID, source.AgentID}
		if _, found := a.selected[key]; found {
			return nil, entity.ErrConflictingEvidence
		}
		digest, err := testspec.DefinitionHash(source.Definition)
		if err != nil {
			return nil, err
		}
		selector := clientReportTestSelector{ContextID: source.ContextID, EntityID: source.EntityID, TestID: source.TestID, AgentID: source.AgentID, Name: source.Name, Type: source.Type, DefinitionDigest: digest, SourceGeneration: source.SourceGeneration}
		body, err := json.Marshal(selector)
		if err != nil {
			return nil, err
		}
		memory -= 4096 + 8*int64(len(body))
		if memory < 0 {
			return nil, store.ErrClientReportBudget
		}
		a.selected[key] = len(a.availability)
		a.availability = append(a.availability, clientReportAvailability{TenantID: tenant, Source: selector, From: from, To: to})
		counter := clientReportOutcomeCounter{}
		seed, err := json.Marshal(struct {
			Domain, Tenant string
			From, To       time.Time
			Selector       clientReportTestSelector
		}{"probectl.client-report-test-originals.v1", tenant, from, to, selector})
		if err != nil {
			return nil, err
		}
		copy(counter.chain[:], crypto.Hash(seed))
		a.counters = append(a.counters, counter)
		a.matches = append(a.matches, nil)
		a.cursors = append(a.cursors, clientReportSourceCursor{})
	}
	for _, definition := range definitions {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		item, counter, err := newClientReportSLO(tenant, definition, to)
		if err != nil {
			return nil, err
		}
		if item.From.Before(a.first) {
			a.first = item.From
		}
		encoded, err := json.Marshal(item)
		if err != nil {
			return nil, err
		}
		memory -= 4096 + 8*int64(len(encoded))
		if memory < 0 {
			return nil, store.ErrClientReportBudget
		}
		index := len(a.slos)
		for sourceIndex, source := range sources {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			if a.work <= 0 {
				return nil, store.ErrClientReportBudget
			}
			a.work--
			selector := a.availability[sourceIndex].Source
			matches, err := incidentSLOMatchesTest(definition, source, incident.ImpactTest{DefinitionDigest: selector.DefinitionDigest, Type: selector.Type})
			if err != nil {
				return nil, err
			}
			if !matches {
				continue
			}
			memory -= 2048 + 4*int64(len(selector.Name)+len(selector.AgentID)+len(selector.TestID))
			if memory < 0 {
				return nil, store.ErrClientReportBudget
			}
			a.matches[sourceIndex] = append(a.matches[sourceIndex], index)
			item.Sources = append(item.Sources, selector)
		}
		// Include the complete selected source/definition identities in provenance.
		seed, err := json.Marshal(item)
		if err != nil {
			return nil, err
		}
		copy(counter.chain[:], crypto.Hash(seed))
		a.slos = append(a.slos, item)
		a.sloCounters = append(a.sloCounters, counter)
	}
	return a, nil
}

func newClientReportSLO(tenant string, definition slo.SLO, to time.Time) (clientReportSLO, clientReportOutcomeCounter, error) {
	item := clientReportSLO{TenantID: tenant, Name: definition.Name, DisplayName: definition.DisplayName, Service: definition.Service, From: to.Add(-definition.Window), To: to, Sources: []clientReportTestSelector{}, Basis: "configured_window_ending_at_month_boundary_under_current_definition_not_historical_definition_attestation"}
	if !definition.ForTenant(tenant) {
		return clientReportSLO{}, clientReportOutcomeCounter{}, entity.ErrScopeMismatch
	}
	if definition.Window <= 0 {
		return clientReportSLO{}, clientReportOutcomeCounter{}, entity.ErrInvalidClaim
	}
	body, err := json.Marshal(definition)
	if err != nil {
		return clientReportSLO{}, clientReportOutcomeCounter{}, err
	}
	item.DefinitionDigest = hex.EncodeToString(crypto.Hash(append([]byte("probectl.client-report-slo.v1\n"), body...)))
	item.ObjectiveRatio = strconv.FormatFloat(definition.Objective, 'g', -1, 64)
	objective, valid := new(big.Rat).SetString(item.ObjectiveRatio)
	if !valid || objective.Sign() <= 0 || objective.Cmp(big.NewRat(1, 1)) > 0 {
		return clientReportSLO{}, clientReportOutcomeCounter{}, entity.ErrInvalidClaim
	}
	return item, clientReportOutcomeCounter{}, nil
}

func (a *clientReportSLIAccumulator) observe(ctx context.Context, read store.IncidentTestMeasurement) (operationErr error) {
	defer func() {
		if operationErr != nil {
			a.failed = operationErr
		}
	}()
	if a.failed != nil {
		return a.failed
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	bound, ok := tenancy.FromContext(ctx)
	if !ok || bound.String() != a.tenant || read.TenantID != a.tenant {
		return entity.ErrScopeMismatch
	}
	if a.finished || read.EvidenceID == "" || read.CaptureDigest == ([32]byte{}) || read.ObservedAt.Before(a.first) || !read.ObservedAt.Before(a.to) {
		return entity.ErrInvalidClaim
	}
	index, found := a.selected[incidentTestSummaryKey{read.ContextID, read.EntityID, read.TestID, read.AgentID}]
	if !found {
		return entity.ErrScopeMismatch
	}
	if read.SourceGeneration != a.availability[index].Source.SourceGeneration {
		return entity.ErrConflictingEvidence
	}
	cursor := a.cursors[index]
	if read.ObservedAt.Before(cursor.at) || read.ObservedAt.Equal(cursor.at) && read.EvidenceID <= cursor.id {
		return entity.ErrConflictingEvidence
	}
	if a.work < int64(1+len(a.matches[index])) {
		return store.ErrClientReportBudget
	}
	a.work -= int64(1 + len(a.matches[index]))
	a.cursors[index] = clientReportSourceCursor{at: read.ObservedAt, id: read.EvidenceID}
	observation := incidentTestObservation(read)
	if !read.ObservedAt.Before(a.from) {
		a.counters[index].add(observation, read.CaptureDigest)
	}
	for _, sloIndex := range a.matches[index] {
		if !read.ObservedAt.Before(a.slos[sloIndex].From) {
			a.sloCounters[sloIndex].add(observation, read.CaptureDigest)
		}
	}
	return nil
}

func (a *clientReportSLIAccumulator) finish(ctx context.Context) ([]clientReportAvailability, []clientReportSLO, error) {
	if a.failed != nil {
		return nil, nil, a.failed
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	bound, ok := tenancy.FromContext(ctx)
	if !ok || bound.String() != a.tenant {
		return nil, nil, entity.ErrScopeMismatch
	}
	if a.finished {
		return nil, nil, entity.ErrInvalidClaim
	}
	a.finished = true
	for index := range a.availability {
		counter := a.counters[index]
		a.availability[index].Counts = counter.counts()
		a.availability[index].OriginalCount = strconv.FormatUint(counter.originals, 10)
		a.availability[index].OriginalsDigest = hex.EncodeToString(counter.chain[:])
	}
	for index := range a.slos {
		counter := a.sloCounters[index]
		item := &a.slos[index]
		item.Counts = counter.counts()
		item.OriginalCount = strconv.FormatUint(counter.originals, 10)
		item.OriginalsDigest = hex.EncodeToString(counter.chain[:])
		if counter.successful+counter.failed == 0 {
			continue
		}
		objective, valid := new(big.Rat).SetString(item.ObjectiveRatio)
		if !valid {
			return nil, nil, entity.ErrInvalidClaim
		}
		numerator := new(big.Int).SetUint64(counter.successful)
		denominator := new(big.Int).SetUint64(counter.successful + counter.failed)
		meets := new(big.Rat).SetFrac(numerator, denominator).Cmp(objective) >= 0
		item.ObservedMeetsObjective = &meets
	}
	return a.availability, a.slos, nil
}
