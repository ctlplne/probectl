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

func TestICMPNetworkErrorObservationPreservesCompletePopulation(t *testing.T) {
	original := icmpObservationFixture()
	m := original.ICMP
	m.Version, m.Requested, m.Attempted, m.Transmitted, m.Replies = 2, 100000, 100000, 100000, 0
	m.Responders = nil
	for i := m.Requested; i > 0; i-- {
		m.NetworkErrors = append(m.NetworkErrors, ICMPNetworkError{Sequence: i - 1, Responder: "2001:db8::1", Type: 1,
			ReceivedAt: m.CompletedAt, PacketDigest: strings.Repeat("a", 64), Conflicting: i == 1})
	}
	got, err := original.Normalize(time.Now())
	if err != nil || len(got.ICMP.NetworkErrors) != 100000 || got.ICMP.NetworkErrors[99999].Sequence != 99999 || !got.ICMP.NetworkErrors[0].Conflicting {
		t.Fatal("complete configured error population or conflict marker changed", err)
	}
	if original.ICMP.NetworkErrors[0].Sequence != 99999 {
		t.Fatal("normalization mutated the original population")
	}
}

func TestICMPNetworkErrorObservationRejectsInvalidEvidence(t *testing.T) {
	for name, mutate := range map[string]func(*ICMPMeasurement){
		"legacy version":         func(m *ICMPMeasurement) { m.Version = 1 },
		"missing outcomes":       func(m *ICMPMeasurement) { m.NetworkErrors = nil },
		"duplicate sequence":     func(m *ICMPMeasurement) { m.NetworkErrors = append(m.NetworkErrors, m.NetworkErrors[0]) },
		"outside population":     func(m *ICMPMeasurement) { m.NetworkErrors[0].Sequence = m.Requested },
		"wrong family":           func(m *ICMPMeasurement) { m.NetworkErrors[0].Responder = "192.0.2.1" },
		"wrong message type":     func(m *ICMPMeasurement) { m.NetworkErrors[0].Type = 3 },
		"bad code":               func(m *ICMPMeasurement) { m.NetworkErrors[0].Code = 256 },
		"noncanonical responder": func(m *ICMPMeasurement) { m.NetworkErrors[0].Responder = "2001:0db8::1" },
		"bad digest":             func(m *ICMPMeasurement) { m.NetworkErrors[0].PacketDigest = strings.Repeat("A", 64) },
		"missing digest":         func(m *ICMPMeasurement) { m.NetworkErrors[0].PacketDigest = strings.Repeat("0", 64) },
		"old outcome":            func(m *ICMPMeasurement) { m.NetworkErrors[0].ReceivedAt = m.StartedAt.Add(-time.Microsecond) },
		"future outcome":         func(m *ICMPMeasurement) { m.NetworkErrors[0].ReceivedAt = m.CompletedAt.Add(time.Microsecond) },
	} {
		t.Run(name, func(t *testing.T) {
			observation := icmpObservationFixture()
			observation.ICMP.Version = 2
			observation.ICMP.NetworkErrors = []ICMPNetworkError{{Responder: "2001:db8::1", Type: 1, ReceivedAt: observation.ObservedAt, PacketDigest: strings.Repeat("a", 64)}}
			mutate(observation.ICMP)
			if _, err := observation.Normalize(time.Now()); !errors.Is(err, ErrInvalidClaim) {
				t.Fatal("invalid network error evidence accepted", err)
			}
		})
	}
}
