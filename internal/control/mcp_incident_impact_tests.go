// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"github.com/ctlplne/probectl/internal/ai/mcp"
	"github.com/ctlplne/probectl/internal/incident"
)

type nativeIncidentTestPackets struct {
	Requested   mcp.NativePeeringCounter `json:"requested"`
	Transmitted mcp.NativePeeringCounter `json:"transmitted"`
	Received    mcp.NativePeeringCounter `json:"received"`
	Lost        mcp.NativePeeringCounter `json:"lost,omitempty"`
}

type nativeIncidentTestObservation struct {
	incident.ImpactTestObservation
	EvidenceID mcp.NativeRoleUUID         `json:"evidence_id"`
	Digest     mcp.NativeRoleDigest       `json:"digest"`
	Packets    *nativeIncidentTestPackets `json:"packets,omitempty"`
}

type nativeIncidentTestPeriod struct {
	incident.ImpactTestPeriod
	Packets      *nativeIncidentTestPackets      `json:"packets,omitempty"`
	Observations []nativeIncidentTestObservation `json:"observations"`
}

type nativeIncidentImpactTest struct {
	incident.ImpactTest
	ContextID        mcp.NativeRoleUUID       `json:"context_id"`
	EntityID         mcp.NativeRoleUUID       `json:"entity_id"`
	TestID           mcp.NativeRoleUUID       `json:"test_id"`
	DefinitionDigest mcp.NativeRoleDigest     `json:"definition_digest"`
	Current          nativeIncidentTestPeriod `json:"current"`
	Previous         nativeIncidentTestPeriod `json:"previous"`
}

func nativeIncidentTestPacketCounts(input *incident.ImpactTestPackets) *nativeIncidentTestPackets {
	if input == nil {
		return nil
	}
	return &nativeIncidentTestPackets{mcp.NativePeeringCounter(input.Requested), mcp.NativePeeringCounter(input.Transmitted), mcp.NativePeeringCounter(input.Received), mcp.NativePeeringCounter(input.Lost)}
}

func nativeIncidentTestComparison(input incident.ImpactTestPeriod) nativeIncidentTestPeriod {
	out := nativeIncidentTestPeriod{input, nativeIncidentTestPacketCounts(input.Packets), make([]nativeIncidentTestObservation, 0, len(input.Observations))}
	for _, observation := range input.Observations {
		out.Observations = append(out.Observations, nativeIncidentTestObservation{observation, mcp.NativeRoleUUID(observation.EvidenceID), mcp.NativeRoleDigest(observation.Digest), nativeIncidentTestPacketCounts(observation.Packets)})
	}
	return out
}

func nativeIncidentImpactTests(input []incident.ImpactTest) []nativeIncidentImpactTest {
	out := make([]nativeIncidentImpactTest, 0, len(input))
	for _, item := range input {
		out = append(out, nativeIncidentImpactTest{item, mcp.NativeRoleUUID(item.ContextID), mcp.NativeRoleUUID(item.EntityID), mcp.NativeRoleUUID(item.TestID), mcp.NativeRoleDigest(item.DefinitionDigest), nativeIncidentTestComparison(item.Current), nativeIncidentTestComparison(item.Previous)})
	}
	return out
}
