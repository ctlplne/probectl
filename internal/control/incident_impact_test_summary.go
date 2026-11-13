// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"encoding/hex"
	"math/big"
	"strconv"
	"time"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/incident"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/testspec"
)

type incidentTestSummaryKey struct{ context, entity, test, agent string }

func summarizeIncidentTests(ctx context.Context, tenant string, sources []store.IncidentConfiguredTest, reads []store.IncidentTestMeasurement, from, to time.Time, maxBytes int64) ([]incident.ImpactTest, error) {
	out := make([]incident.ImpactTest, 0, len(sources))
	selected := make(map[incidentTestSummaryKey]int, len(sources))
	remaining := maxBytes
	for _, source := range sources {
		if source.TenantID != tenant {
			return nil, entity.ErrScopeMismatch
		}
		remaining -= int64(2048 + 4*(len(source.AgentID)+len(source.Name)+len(source.Type)))
		if remaining < 0 {
			return nil, flowstore.ErrExplorerBudget
		}
		key := incidentTestSummaryKey{source.ContextID, source.EntityID, source.TestID, source.AgentID}
		if _, exists := selected[key]; exists {
			return nil, entity.ErrConflictingEvidence
		}
		digest, err := testspec.DefinitionHash(source.Definition)
		if err != nil {
			return nil, err
		}
		selected[key] = len(out)
		period := func(start, end time.Time) incident.ImpactTestPeriod {
			return incident.ImpactTestPeriod{From: start, To: end, Coverage: "no_retained_observations", Observations: []incident.ImpactTestObservation{}}
		}
		out = append(out, incident.ImpactTest{ContextID: source.ContextID, EntityID: source.EntityID, TestID: source.TestID, AgentID: source.AgentID, Name: source.Name, Type: source.Type, DefinitionDigest: digest,
			Current: period(from, to), Previous: period(from.Add(-7*24*time.Hour), to.Add(-7*24*time.Hour))})
	}
	for _, read := range reads {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if read.TenantID != tenant {
			return nil, entity.ErrScopeMismatch
		}
		i, found := selected[incidentTestSummaryKey{read.ContextID, read.EntityID, read.TestID, read.AgentID}]
		if !found {
			return nil, entity.ErrScopeMismatch
		}
		observation := incidentTestObservation(read)
		for _, period := range []*incident.ImpactTestPeriod{&out[i].Current, &out[i].Previous} {
			if read.ObservedAt.Before(period.From) || !read.ObservedAt.Before(period.To) {
				continue
			}
			remaining -= int64(1024 + 4*(len(observation.EvidenceID)+len(observation.Reason)))
			if remaining < 0 {
				return nil, flowstore.ErrExplorerBudget
			}
			addIncidentTestObservation(period, observation)
		}
	}
	return out, ctx.Err()
}

func incidentTestObservation(read store.IncidentTestMeasurement) incident.ImpactTestObservation {
	out := incident.ImpactTestObservation{EvidenceID: read.EvidenceID, Digest: hex.EncodeToString(read.CaptureDigest[:]), ObservedAt: read.ObservedAt, Status: "unknown", Reason: read.Reason}
	if !read.Available {
		return out
	}
	if m := read.Outcome; m != nil {
		switch {
		case m.Canceled:
			out.Status, out.Reason = "canceled", "runtime_canceled"
		case m.Success:
			out.Status = "successful"
		default:
			out.Status = "failed"
		}
		return out
	}
	if m := read.ICMP; m != nil {
		out.Packets = &incident.ImpactTestPackets{Requested: strconv.FormatUint(uint64(m.Requested), 10), Transmitted: strconv.FormatUint(uint64(m.Transmitted), 10), Received: strconv.FormatUint(uint64(m.Replies), 10)}
		switch {
		case m.Canceled:
			out.Status, out.Reason = "canceled", "runtime_canceled"
		case m.Attempted != m.Requested || m.Transmitted != m.Requested || m.SendErrors != 0 || !m.ReadComplete || m.IOFailed:
			out.Reason = "incomplete_local_io"
		case m.Replies > 0:
			out.Status = "successful"
		default:
			out.Status = "failed"
		}
		if out.Status == "successful" || out.Status == "failed" {
			out.Packets.Lost = strconv.FormatUint(uint64(m.Transmitted-m.Replies), 10)
		}
	}
	return out
}

func addIncidentTestObservation(period *incident.ImpactTestPeriod, observation incident.ImpactTestObservation) {
	period.Observations = append(period.Observations, observation)
	switch observation.Status {
	case "successful":
		period.Successful++
	case "failed":
		period.Failed++
	case "canceled":
		period.Canceled++
		period.Unknown++
	default:
		period.Unknown++
	}
	period.Coverage = "unavailable_test_observations"
	if period.Successful+period.Failed > 0 {
		period.Coverage = "observed_attested_test_outcomes"
		if period.Unknown > 0 {
			period.Coverage = "partial_test_observation_coverage"
		}
	}
	if observation.Packets == nil || observation.Status == "unknown" || observation.Status == "canceled" {
		return
	}
	if period.Packets == nil {
		period.Packets = &incident.ImpactTestPackets{Requested: "0", Transmitted: "0", Received: "0", Lost: "0"}
	}
	for _, pair := range [][2]*string{{&period.Packets.Requested, &observation.Packets.Requested}, {&period.Packets.Transmitted, &observation.Packets.Transmitted}, {&period.Packets.Received, &observation.Packets.Received}, {&period.Packets.Lost, &observation.Packets.Lost}} {
		var total, next big.Int
		total.SetString(*pair[0], 10)
		next.SetString(*pair[1], 10)
		*pair[0] = total.Add(&total, &next).String()
	}
}
