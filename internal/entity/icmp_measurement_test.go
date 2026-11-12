// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package entity

import (
	"errors"
	"slices"
	"strings"
	"testing"
	"time"
)

func icmpObservationFixture() Observation {
	end := time.Now().UTC().Truncate(time.Microsecond)
	return Observation{ID: "bf806db0-b5ae-4059-998d-97b9c7226a05",
		Source: SourceKey{AgentID: "agent-one", Kind: PathAgent, SourceRef: "e3fed09f-a38f-4637-9a6d-ef8471b6e7ca"},
		Alias:  AliasKey{Kind: AddressAlias, Value: "2001:db8::99"}, SourceRef: "icmp:configured-test", ObservedAt: end,
		ICMP: &ICMPMeasurement{Version: 1, DefinitionHash: strings.Repeat("a", 64), StartedAt: end.Add(-time.Second), CompletedAt: end,
			Requested: 3, Attempted: 3, Transmitted: 3, Replies: 2, ReadComplete: true, Responders: []string{"2001:db8::3", "2001:db8::2"}}}
}

func TestICMPMeasurementObservationPreservesAnycastAndUnknownLocalIO(t *testing.T) {
	original := icmpObservationFixture()
	got, err := original.Normalize(time.Now())
	if err != nil || !slices.Equal(got.ICMP.Responders, []string{"2001:db8::2", "2001:db8::3"}) || original.ICMP.Responders[0] != "2001:db8::3" {
		t.Fatal("actual anycast responders were lost or the original was mutated", got.ICMP, err)
	}
	local := icmpObservationFixture()
	local.ICMP.Transmitted = 2
	local.ICMP.SendErrors = 1
	local.ICMP.Replies = 0
	local.ICMP.Responders = nil
	local.ICMP.IOFailed = true
	got, err = local.Normalize(time.Now())
	if err != nil || got.ICMP.Transmitted != 2 || got.ICMP.Replies != 0 || !got.ICMP.IOFailed || got.ICMP.SendErrors != 1 {
		t.Fatal("local IO failure became complete network failure or was silently discarded", got.ICMP, err)
	}
	legacy := icmpObservationFixture()
	legacy.ICMP = nil
	if got, err := legacy.Normalize(time.Now()); err != nil || got.ICMP != nil {
		t.Fatal("legacy address evidence acquired health authority", err)
	}
}

func TestICMPMeasurementObservationRefusesMalformedSourceAndCounts(t *testing.T) {
	mutations := map[string]func(*Observation){
		"version":                      func(v *Observation) { v.ICMP.Version = 2 },
		"hash":                         func(v *Observation) { v.ICMP.DefinitionHash = "not-a-definition" },
		"source family":                func(v *Observation) { v.Source.Kind = FlowExporter },
		"configured reference":         func(v *Observation) { v.Source.SourceRef = "router-name" },
		"provenance":                   func(v *Observation) { v.SourceRef = "result:metric" },
		"zero requested":               func(v *Observation) { v.ICMP.Requested = 0 },
		"attempted exceeds profile":    func(v *Observation) { v.ICMP.Attempted = 4 },
		"transmitted exceeds attempts": func(v *Observation) { v.ICMP.Transmitted = 4 },
		"replies exceed transmissions": func(v *Observation) { v.ICMP.Replies = 4 },
		"send error count":             func(v *Observation) { v.ICMP.SendErrors = 1 },
		"observation clock":            func(v *Observation) { v.ICMP.CompletedAt = v.ICMP.CompletedAt.Add(time.Second) },
		"backward interval":            func(v *Observation) { v.ICMP.StartedAt = v.ICMP.CompletedAt.Add(time.Second) },
		"missing responder":            func(v *Observation) { v.ICMP.Responders = nil },
		"duplicate responder":          func(v *Observation) { v.ICMP.Responders = []string{"2001:db8::2", "2001:db8::2"} },
		"multicast responder":          func(v *Observation) { v.ICMP.Responders = []string{"ff02::1"} },
		"different family":             func(v *Observation) { v.ICMP.Responders = []string{"192.0.2.1"} },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			original := icmpObservationFixture()
			mutate(&original)
			if _, err := original.Normalize(time.Now()); !errors.Is(err, ErrInvalidClaim) {
				t.Fatal("malformed health evidence was accepted", err)
			}
		})
	}
}
