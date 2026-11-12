// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"time"

	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
)

type incidentImpactPoint struct {
	contextID, agent, exporter, protocol string
	domain                               uint32
}
type incidentImpactPointCoverage struct {
	whole   bool
	indices map[uint32]time.Time
}
type incidentImpactCoverage map[incidentImpactPoint]*incidentImpactPointCoverage

func incidentImpactSourceCoverage(sources []store.IncidentImpactSource) incidentImpactCoverage {
	out := incidentImpactCoverage{}
	for _, source := range sources {
		for _, selection := range source.Selections {
			key := incidentImpactPoint{source.Member.ContextID, selection.AgentID, selection.Exporter.String(), selection.Protocol, selection.Domain}
			point := out[key]
			if point == nil {
				point = &incidentImpactPointCoverage{indices: map[uint32]time.Time{}}
				out[key] = point
			}
			point.whole = point.whole || selection.WholeDevice
			for _, index := range selection.InterfaceIndices {
				if old, found := point.indices[index]; !found || source.InterfaceNotBefore.Before(old) {
					point.indices[index] = source.InterfaceNotBefore
				}
			}
		}
	}
	return out
}

func (coverage incidentImpactCoverage) covers(row flowstore.Row, owner store.CapturedFlowOwner) bool {
	point := coverage[incidentImpactPoint{owner.Owner.ContextID, row.AgentID, row.Exporter, row.Protocol, row.ObsDomain}]
	if point == nil {
		return false
	}
	if point.whole {
		return true
	}
	for _, index := range []uint32{row.InIf, row.OutIf} {
		if index == 0 {
			continue
		}
		since, found := point.indices[index]
		if found && !since.IsZero() && !owner.Reference.CapturedAt.Before(since) && !row.TS.Before(since) && (row.StartTS.IsZero() || !row.StartTS.Before(since)) {
			return true
		}
	}
	return false
}
