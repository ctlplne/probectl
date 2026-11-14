// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"encoding/json"
	"errors"
	"strings"

	"github.com/ctlplne/probectl/internal/ai/mcp"
	"github.com/ctlplne/probectl/internal/change"
	"github.com/ctlplne/probectl/internal/incident"
)

// These values are typed original metrics, not arbitrary source strings.
// Keep exact mathematical values through ordinary text redaction without
// exempting an agent ID, display label or unknown source field.
type nativeChangeEffectRatio string

func (ratio nativeChangeEffectRatio) MarshalJSON() ([]byte, error) {
	parts := strings.Split(string(ratio), "/")
	if len(parts) > 2 {
		return nil, errors.New("invalid original measurement ratio")
	}
	first, err := mcp.NativePeeringCounter(parts[0]).MarshalJSON()
	if err != nil || len(parts) == 1 {
		return first, err
	}
	if parts[1] == "0" {
		return nil, errors.New("zero original measurement denominator")
	}
	second, err := mcp.NativePeeringCounter(parts[1]).MarshalJSON()
	if err != nil {
		return nil, err
	}
	return append(append(first[:len(first)-1], '/'), second[1:]...), nil
}

type nativeChangeEffectPackets struct {
	Transmitted mcp.NativePeeringCounter `json:"transmitted"`
	Replies     mcp.NativePeeringCounter `json:"replies"`
	Lost        json.RawMessage          `json:"lost"`
}

func nativeChangeEffectPacketCounts(value *change.EffectPackets) (*nativeChangeEffectPackets, error) {
	if value == nil {
		return nil, nil
	}
	lost := json.RawMessage(`""`) // Incomplete original execution: unknown.
	if value.Lost != "" {
		encoded, err := mcp.NativePeeringCounter(value.Lost).MarshalJSON()
		if err != nil {
			return nil, err
		}
		lost = encoded
	}
	return &nativeChangeEffectPackets{mcp.NativePeeringCounter(value.Transmitted), mcp.NativePeeringCounter(value.Replies), lost}, nil
}

func nativeChangeEffectPeriod(value change.EffectTestPeriod) (json.RawMessage, error) {
	type rtts struct {
		Nanos          []mcp.NativePeeringCounter `json:"nanos"`
		ExecutionNanos mcp.NativePeeringCounter   `json:"execution_nanos"`
	}
	type observation struct {
		change.EffectTestObservation
		EvidenceID    mcp.NativeRoleUUID         `json:"evidence_id"`
		ObservationID mcp.NativeRoleUUID         `json:"observation_id"`
		CaptureDigest mcp.NativeRoleDigest       `json:"capture_digest"`
		Packets       *nativeChangeEffectPackets `json:"packets,omitempty"`
		RoundTrips    *rtts                      `json:"round_trips,omitempty"`
	}
	type latency struct {
		change.EffectLatency
		Samples      mcp.NativePeeringCounter `json:"samples"`
		SumNanos     mcp.NativePeeringCounter `json:"sum_nanos"`
		MinimumNanos mcp.NativePeeringCounter `json:"minimum_nanos"`
		MaximumNanos mcp.NativePeeringCounter `json:"maximum_nanos"`
		MeanNanos    nativeChangeEffectRatio  `json:"mean_nanos"`
	}
	packets, err := nativeChangeEffectPacketCounts(value.Packets)
	if err != nil {
		return nil, err
	}
	out := struct {
		change.EffectTestPeriod
		Packets      *nativeChangeEffectPackets `json:"packets,omitempty"`
		LossRatio    *nativeChangeEffectRatio   `json:"loss_ratio,omitempty"`
		Latency      *latency                   `json:"latency,omitempty"`
		Observations []observation              `json:"observations"`
	}{EffectTestPeriod: value, Packets: packets, Observations: []observation{}}
	if value.LossRatio != nil {
		ratio := nativeChangeEffectRatio(*value.LossRatio)
		out.LossRatio = &ratio
	}
	if v := value.Latency; v != nil {
		out.Latency = &latency{*v, mcp.NativePeeringCounter(v.Samples), mcp.NativePeeringCounter(v.SumNanos), mcp.NativePeeringCounter(v.MinimumNanos), mcp.NativePeeringCounter(v.MaximumNanos), nativeChangeEffectRatio(v.MeanNanos)}
	}
	for _, item := range value.Observations {
		packets, err := nativeChangeEffectPacketCounts(item.Packets)
		if err != nil {
			return nil, err
		}
		row := observation{EffectTestObservation: item, EvidenceID: mcp.NativeRoleUUID(item.EvidenceID), ObservationID: mcp.NativeRoleUUID(item.ObservationID), CaptureDigest: mcp.NativeRoleDigest(item.CaptureDigest), Packets: packets}
		if item.RoundTrips != nil {
			row.RoundTrips = &rtts{Nanos: make([]mcp.NativePeeringCounter, len(item.RoundTrips.Nanos)), ExecutionNanos: mcp.NativePeeringCounter(item.RoundTrips.ExecutionNanos)}
			for i, sample := range item.RoundTrips.Nanos {
				row.RoundTrips.Nanos[i] = mcp.NativePeeringCounter(sample)
			}
		}
		out.Observations = append(out.Observations, row)
	}
	return json.Marshal(out)
}

func marshalNativeChangeEffects(value changeEffectsResponse) (json.RawMessage, error) {
	if value.ContractVersion != "probectl.change-effects.v1" {
		return nil, errors.New("invalid original change effect contract")
	}
	// Reuse the exact counter/capture/member projection without manufacturing
	// an incident response or exposing the temporary projection's incident ID.
	bridge, err := marshalNativeIncidentImpact(incident.ImpactResponse{ContractVersion: "probectl.incident-impact.v1", IncidentID: strings.TrimPrefix(value.Original.ID, "device-config:"), Current: value.After, Previous: value.Before, Members: value.Members})
	if err != nil {
		return nil, err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(bridge, &fields); err != nil {
		return nil, err
	}
	body, err := json.Marshal(map[string]any{"items": []change.Event{value.Original}})
	if err != nil {
		return nil, err
	}
	body, err = marshalNativeChangeTimeline(body)
	if err != nil {
		return nil, err
	}
	var timeline struct{ Items []json.RawMessage }
	if err := json.Unmarshal(body, &timeline); err != nil || len(timeline.Items) != 1 {
		return nil, errors.New("original change projection unavailable")
	}
	type test struct {
		change.EffectTest
		ContextID mcp.NativeRoleUUID `json:"context_id"`
		EntityID  mcp.NativeRoleUUID `json:"entity_id"`
		TestID    mcp.NativeRoleUUID `json:"test_id"`
		Before    json.RawMessage    `json:"before"`
		After     json.RawMessage    `json:"after"`
	}
	out := struct {
		changeEffectsResponse
		ContractVersion json.RawMessage `json:"contract_version"`
		Original        json.RawMessage `json:"original"`
		Before          json.RawMessage `json:"before"`
		After           json.RawMessage `json:"after"`
		Members         json.RawMessage `json:"members"`
		Tests           []test          `json:"tests"`
	}{value, json.RawMessage(`"probectl\u002echange-effects\u002ev1"`), timeline.Items[0], fields["previous"], fields["current"], fields["members"], []test{}}
	for _, item := range value.Tests {
		before, err := nativeChangeEffectPeriod(item.Before)
		if err != nil {
			return nil, err
		}
		after, err := nativeChangeEffectPeriod(item.After)
		if err != nil {
			return nil, err
		}
		out.Tests = append(out.Tests, test{item, mcp.NativeRoleUUID(item.ContextID), mcp.NativeRoleUUID(item.EntityID), mcp.NativeRoleUUID(item.TestID), before, after})
	}
	return json.Marshal(out)
}
