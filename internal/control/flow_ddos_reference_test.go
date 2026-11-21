// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"errors"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/alert"
	"github.com/ctlplne/probectl/internal/anomaly"
	"github.com/ctlplne/probectl/internal/flow"
)

func TestCitedDDoSClockKeepsSelectedWeekForBothEvidenceWindows(t *testing.T) {
	end := time.Date(2026, time.November, 20, 14, 15, 5, 0, time.UTC)
	settings := ddosAssessmentSettings{Input: flow.DDoSAssessmentInput{PeriodSeconds: 5, ReferenceMode: flow.DDoSReferenceWeeklyRepresentative}}
	clock, err := ddosClocks(end, settings.Input.PeriodSeconds)
	if err != nil {
		t.Fatal(err)
	}
	fill := func(w anomaly.FlowFieldComparisonClocks, week int) flow.DDoSAssessment {
		return flow.DDoSAssessment{ReferenceMode: settings.Input.ReferenceMode,
			Before: flow.DDoSWindowEvidence{From: w.After.Start.AddDate(0, 0, -7*week), To: w.After.End.AddDate(0, 0, -7*week)},
			After:  flow.DDoSWindowEvidence{From: w.After.Start, To: w.After.End}}
	}
	proof := alert.DDoSEvaluationEvidence{Previous: fill(clock.Previous, 3), Current: fill(clock.Current, 3)}
	kept, err := citedDDoSClocks(proof, settings)
	if err != nil || !kept.Previous.Before.End.Equal(proof.Previous.Before.To) || !kept.Current.Before.End.Equal(proof.Current.Before.To) {
		t.Fatal("routing review did not keep both original reference clocks", kept, err)
	}
	proof.Previous = fill(clock.Previous, 2)
	if _, err := citedDDoSClocks(proof, settings); !errors.Is(err, alert.ErrQueryGroups) {
		t.Fatal("a mixed-week episode could be reconstructed as an original", err)
	}
	settings.Input.ReferenceMode = ""
	proof = alert.DDoSEvaluationEvidence{Previous: fill(clock.Previous, 3), Current: fill(clock.Current, 3)}
	if _, err := citedDDoSClocks(proof, settings); !errors.Is(err, alert.ErrQueryGroups) {
		t.Fatal("legacy rules could use an unexpected reference week", err)
	}
}
