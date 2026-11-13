// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/testspec"
)

func TestProbeOutcomeMatchesExactExecutableDefinitionAndBindingClock(t *testing.T) {
	now := time.Now().UTC()
	definition := testspec.ExecutableDefinition{ID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", Type: "http", Target: "https://example.test/health", IntervalSeconds: 30, TimeoutSeconds: 5, Params: map[string]string{"method": "GET"}}
	digest, err := testspec.DefinitionHash(definition)
	if err != nil {
		t.Fatal(err)
	}
	claim := entity.Observation{Source: entity.SourceKey{Kind: entity.PathAgent, SourceRef: definition.ID}, Alias: entity.AliasKey{Kind: entity.ConfiguredTestAlias, Value: definition.ID}, ObservedAt: now,
		Outcome: &entity.ProbeOutcome{Version: 1, DefinitionHash: digest, CanaryType: "http", StartedAt: now.Add(-time.Second), CompletedAt: now, Success: false}}
	before := now.Add(-time.Minute)
	if ok, err := matchesProbeOutcomeDefinition(claim, definition, before, before); err != nil || !ok {
		t.Fatal("current failed result lost its exact profile", ok, err)
	}
	for name, change := range map[string]func(*testspec.ExecutableDefinition){
		"other test":     func(d *testspec.ExecutableDefinition) { d.ID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb" },
		"other protocol": func(d *testspec.ExecutableDefinition) { d.Type = "tcp" },
		"other URL":      func(d *testspec.ExecutableDefinition) { d.Target += "?other=1" },
		"other cadence":  func(d *testspec.ExecutableDefinition) { d.IntervalSeconds++ },
		"other timeout":  func(d *testspec.ExecutableDefinition) { d.TimeoutSeconds++ },
		"other method":   func(d *testspec.ExecutableDefinition) { d.Params = map[string]string{"method": "POST"} },
	} {
		t.Run(name, func(t *testing.T) {
			changed := definition
			change(&changed)
			if ok, err := matchesProbeOutcomeDefinition(claim, changed, before, before); err != nil || ok {
				t.Fatal("old executable profile remained current", ok, err)
			}
		})
	}
	for _, clocks := range [][2]time.Time{{now, before}, {before, now}} {
		if ok, err := matchesProbeOutcomeDefinition(claim, definition, clocks[0], clocks[1]); err != nil || ok {
			t.Fatal("later definition or binding retroactively authorized a result", ok, err)
		}
	}
}
