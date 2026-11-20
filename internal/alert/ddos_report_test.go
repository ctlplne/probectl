// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package alert

import (
	"errors"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/anomaly"
	"github.com/ctlplne/probectl/internal/flow"
)

func TestDDoSReportKeepsExactRatesAndOriginalWindows(t *testing.T) {
	start := time.Date(2026, 11, 20, 0, 0, 0, 0, time.UTC)
	assessment := func(at time.Time, bytes, packets, citation string) flow.DDoSAssessment {
		return flow.DDoSAssessment{
			ViewID: "view", Version: "1", Prefix: "192.0.2.0/24", Direction: "ingress",
			After: flow.DDoSWindowEvidence{
				From: at, To: at.Add(time.Minute), Source: "raw", ResolutionSeconds: 60, Bytes: bytes, Packets: packets, Citation: citation,
			},
			Detection: &anomaly.DDoSDetection{
				Class: anomaly.DDoSSYN, Confidence: "corroborated", CurrentCitation: citation, CurrentBytes: bytes, CurrentPackets: packets,
			},
		}
	}
	evidence := DDoSEvaluationEvidence{
		IncidentID: "incident", EpisodeID: "episode",
		Previous: assessment(start, "9007199254740993", "200", "first"),
		Current:  assessment(start.Add(time.Minute), "600000", "300", "second"),
	}
	report, err := SummarizeDDoSReport(evidence)
	if err != nil || report.ObservedSeconds != 120 || report.PeakBitRate.Count != "72057594037927944" ||
		report.PeakBitRate.PerSecond != "1200959900632132.400" || report.PeakPacketRate.PerSecond != "5.000" ||
		!report.PeakBitRate.From.Equal(start) || !report.PeakPacketRate.From.Equal(start.Add(time.Minute)) ||
		report.Windows[1].Evidence.Citation != "second" || report.Windows[1].Vector != anomaly.DDoSSYN {
		t.Fatalf("report lost its original windows or wide exact counters: %+v %v", report, err)
	}
	evidence.Current.After.From = evidence.Current.After.From.Add(5 * time.Minute)
	if _, err := SummarizeDDoSReport(evidence); !errors.Is(err, anomaly.ErrDDoSCoverage) {
		t.Fatalf("incomplete report clocks were accepted: %v", err)
	}
}
