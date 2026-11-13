// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"errors"
	"strconv"
	"strings"

	"github.com/ctlplne/probectl/internal/ai/mcp"
	"github.com/ctlplne/probectl/internal/incident"
)

type nativeIncidentSLORatio string

func (ratio nativeIncidentSLORatio) MarshalJSON() ([]byte, error) {
	text := string(ratio)
	value, err := strconv.ParseFloat(text, 64)
	if err != nil || !(value > 0 && value < 1) || strconv.FormatFloat(value, 'g', -1, 64) != text {
		return nil, errors.New("invalid configured SLO objective ratio")
	}
	var out strings.Builder
	out.WriteByte('"')
	for _, r := range text {
		if r >= '0' && r <= '9' {
			out.WriteString(`\u003`)
		}
		out.WriteRune(r)
	}
	out.WriteByte('"')
	return []byte(out.String()), nil
}

type nativeIncidentSLOSource struct {
	incident.ImpactSLOSource
	ContextID   mcp.NativeRoleUUID   `json:"context_id"`
	EntityID    mcp.NativeRoleUUID   `json:"entity_id"`
	TestID      mcp.NativeRoleUUID   `json:"test_id"`
	EvidenceIDs []mcp.NativeRoleUUID `json:"evidence_ids"`
}

type nativeIncidentSLOPeriod struct {
	incident.ImpactSLOPeriod
	Sources []nativeIncidentSLOSource `json:"sources"`
}

type nativeIncidentSLO struct {
	incident.ImpactSLO
	DefinitionDigest mcp.NativeRoleDigest    `json:"definition_digest"`
	ObjectiveRatio   nativeIncidentSLORatio  `json:"objective_ratio"`
	Current          nativeIncidentSLOPeriod `json:"current"`
	Previous         nativeIncidentSLOPeriod `json:"previous"`
}

func nativeIncidentSLOComparison(input incident.ImpactSLOPeriod) nativeIncidentSLOPeriod {
	out := nativeIncidentSLOPeriod{input, make([]nativeIncidentSLOSource, 0, len(input.Sources))}
	for _, source := range input.Sources {
		ids := make([]mcp.NativeRoleUUID, len(source.EvidenceIDs))
		for i, id := range source.EvidenceIDs {
			ids[i] = mcp.NativeRoleUUID(id)
		}
		out.Sources = append(out.Sources, nativeIncidentSLOSource{source, mcp.NativeRoleUUID(source.ContextID), mcp.NativeRoleUUID(source.EntityID), mcp.NativeRoleUUID(source.TestID), ids})
	}
	return out
}

func nativeIncidentSLOs(input []incident.ImpactSLO) []nativeIncidentSLO {
	out := make([]nativeIncidentSLO, 0, len(input))
	for _, item := range input {
		out = append(out, nativeIncidentSLO{item, mcp.NativeRoleDigest(item.DefinitionDigest), nativeIncidentSLORatio(item.ObjectiveRatio), nativeIncidentSLOComparison(item.Current), nativeIncidentSLOComparison(item.Previous)})
	}
	return out
}
