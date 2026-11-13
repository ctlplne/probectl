// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package entity

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestConfiguredProbeOutcomeKeepsExactTestAndOriginalClock(t *testing.T) {
	end := time.Now().UTC().Add(-time.Second)
	id := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	valid := Observation{ID: uuid.NewString(), Source: SourceKey{AgentID: "test-agent", Kind: PathAgent, SourceRef: id}, Alias: AliasKey{Kind: ConfiguredTestAlias, Value: id}, SourceRef: "probe:configured-test", ObservedAt: end,
		Outcome: &ProbeOutcome{Version: 1, DefinitionHash: strings.Repeat("a", 64), CanaryType: "http", StartedAt: end.Add(-time.Second), CompletedAt: end, Success: false}}
	got, err := valid.Normalize(time.Now())
	if err != nil || got.Outcome == nil || got.Outcome == valid.Outcome || got.Outcome.Success || got.Alias.Value != id || !got.Outcome.StartedAt.Equal(valid.Outcome.StartedAt.Truncate(time.Microsecond)) {
		t.Fatal("configured outcome lost its exact definition, failed result or original clock", got, err)
	}
	for name, mutate := range map[string]func(*Observation){
		"other source":              func(o *Observation) { o.Source.Kind = DeviceTarget },
		"other test":                func(o *Observation) { o.Alias.Value = uuid.NewString() },
		"address guess":             func(o *Observation) { o.Alias = AliasKey{Kind: AddressAlias, Value: "192.0.2.1"} },
		"missing metadata":          func(o *Observation) { o.Outcome = nil },
		"two typed outcomes":        func(o *Observation) { o.ICMP = &ICMPMeasurement{} },
		"wrong source ref":          func(o *Observation) { o.SourceRef = "icmp:configured-test" },
		"uppercase identity":        func(o *Observation) { o.Alias.Value = strings.ToUpper(id) },
		"bad digest":                func(o *Observation) { o.Outcome.DefinitionHash = "not-a-definition" },
		"future version":            func(o *Observation) { o.Outcome.Version = 3 },
		"ICMP relabel":              func(o *Observation) { o.Outcome.CanaryType = "icmp" },
		"raw label":                 func(o *Observation) { o.Outcome.CanaryType = "password=private" },
		"backwards clock":           func(o *Observation) { o.Outcome.StartedAt = end.Add(time.Second) },
		"different completed clock": func(o *Observation) { o.Outcome.CompletedAt = end.Add(time.Millisecond) },
	} {
		t.Run(name, func(t *testing.T) {
			changed := valid
			outcome := *valid.Outcome
			changed.Outcome = &outcome
			mutate(&changed)
			if _, err := changed.Normalize(time.Now()); !errors.Is(err, ErrInvalidClaim) && !errors.Is(err, ErrInvalidAlias) {
				t.Fatal("invalid configured probe claim was accepted", err)
			}
		})
	}
}
