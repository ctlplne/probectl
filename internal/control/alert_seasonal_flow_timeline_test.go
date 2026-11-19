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
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/alert"
)

func TestSeasonalFlowTimelineKeepsSharedRoutingAcrossEveryWindow(t *testing.T) {
	const periods = 42*24 + 1
	first := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	routing := &flowRoutingSnapshotValidity{Digest: strings.Repeat("a", 64), InputDigest: strings.Repeat("b", 64)}
	inputs := make([]reportFlowInput, 0, periods)
	for i := range periods {
		end := first.Add(time.Duration(i) * time.Hour)
		inputs = append(inputs, reportFlowInput{ID: "00000000-0000-4000-8000-000000000001", Version: "1",
			Period: "current", From: end.Add(-10 * time.Minute), To: end, RoutingSource: true, Routing: routing})
	}
	common, err := compactSeasonalFlowTimeline(t.Context(), inputs)
	if err != nil || common.SharedRouting != routing || len(common.Periods) != periods {
		t.Fatal("grouped receipt lost the original clock population or shared routing requirement", err)
	}
	for _, period := range common.Periods {
		if !period.RoutingSource || period.Routing != nil {
			t.Fatal("the grouped receipt duplicated or lost its original routing lineage")
		}
	}
	raw, err := json.Marshal(storedSeasonalFlowScope{Version: 3, Timeline: common})
	if err != nil || len(raw) > alert.SeasonalFlowScopeBytes {
		t.Fatal("the full calendar exceeded the compact proof budget", err)
	}
	var restored storedSeasonalFlowScope
	if err := json.Unmarshal(raw, &restored); err != nil {
		t.Fatal(err)
	}
	expanded, err := restored.expandedInputs(t.Context(), 1<<20)
	if err != nil || len(expanded) != len(inputs) {
		t.Fatal("the stored proof lost comparison windows", err)
	}
	for i, input := range expanded {
		if !input.From.Equal(inputs[i].From) || !input.To.Equal(inputs[i].To) || input.Routing != restored.Timeline.SharedRouting ||
			input.Routing.Digest != routing.Digest || input.Routing.InputDigest != routing.InputDigest {
			t.Fatal("reconstructed window lost its exact clock or routing requirement", i)
		}
	}
	restored.Timeline.Periods[1].RoutingSource = false
	if inputs, err := restored.expandedInputs(t.Context(), 1<<20); !errors.Is(err, alert.ErrSeasonalSource) || inputs != nil {
		t.Fatal("an incomplete shared routing proof was admitted", err)
	}
}
