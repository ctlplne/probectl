// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"slices"
	"strings"
	"time"

	"github.com/ctlplne/probectl/internal/incident"
	"github.com/ctlplne/probectl/internal/opendata"
	"github.com/ctlplne/probectl/internal/store"
)

type incidentProviderAttribution struct {
	asOf       time.Time
	ranges     *opendata.Enricher
	incomplete bool
	provider   string
	service    string
	sources    map[string]incident.VerdictProviderSource
}

// Observe only peers that already participate in a corroborating failure pair.
// A disagreement or a missing or expired source keeps the generic verdict.
func (a *incidentProviderAttribution) observe(ctx context.Context, read store.IncidentTestMeasurement, remaining *int64) {
	if a.ranges == nil || a.incomplete {
		return
	}
	peer := read.Outcome.HTTPSPeer()
	// Bound per-observation range work independently of the underlying
	// verdict's evidence budget. Exhaustion leaves the generic verdict.
	const lookupCharge = 2048
	if peer == "" || *remaining < lookupCharge {
		a.incomplete = true
		return
	}
	*remaining -= lookupCharge
	sources := a.ranges.LocalServiceRanges(ctx, peer, read.ObservedAt)
	original := opendata.ClassifyServiceRanges(sources, read.ObservedAt)
	match := opendata.ClassifyServiceRanges(sources, a.asOf)
	if match.Status != "known" || original.Status != "known" || original.Provider != match.Provider ||
		original.Service != match.Service || (a.provider != "" && a.provider != match.Provider) {
		a.incomplete = true
		return
	}
	if a.provider == "" {
		a.provider, a.service = match.Provider, match.Service
		a.sources = make(map[string]incident.VerdictProviderSource)
	} else if a.service != match.Service {
		a.service = ""
	}
	found := false
	for _, source := range sources {
		single := opendata.ClassifyServiceRanges([]opendata.ServiceRangeStatus{source}, a.asOf)
		if single.Status != "known" || single.Provider != match.Provider || single.Service != match.Service || source.Digest == "" {
			continue
		}
		found = true
		key := source.Publisher + ":" + source.Digest
		if _, already := a.sources[key]; already {
			continue
		}
		cost := int64(256 + 4*len(key))
		if cost > *remaining {
			a.incomplete = true
			return
		}
		*remaining -= cost
		a.sources[key] = incident.VerdictProviderSource{
			Publisher: source.Publisher, Digest: source.Digest, FetchedAt: source.FetchedAt, ValidUntil: source.ValidUntil,
		}
	}
	a.incomplete = !found
}

func (a *incidentProviderAttribution) result() *incident.VerdictRemoteProvider {
	if a.incomplete || len(a.sources) == 0 {
		return nil
	}
	sources := make([]incident.VerdictProviderSource, 0, len(a.sources))
	for _, source := range a.sources {
		sources = append(sources, source)
	}
	slices.SortFunc(sources, func(left, right incident.VerdictProviderSource) int {
		if compared := strings.Compare(left.Publisher, right.Publisher); compared != 0 {
			return compared
		}
		return strings.Compare(left.Digest, right.Digest)
	})
	return &incident.VerdictRemoteProvider{Provider: a.provider, Service: a.service, Sources: sources}
}
