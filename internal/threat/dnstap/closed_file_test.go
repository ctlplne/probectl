// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package dnstap

import (
	"bytes"
	"errors"
	"testing"
	"time"
)

func TestReduceClosedCaptureKeepsBucketsAndRefusesPartialFiles(t *testing.T) {
	file, at := ordinaryResolverCapture(t)
	start := at.Truncate(ResolverInterval)
	end := start.Add(2 * ResolverInterval)
	got, err := ReduceClosedCapture(t.Context(), bytes.NewReader(file), start, end)
	first := ResolverIntervalCounts{From: start, To: start.Add(ResolverInterval), Responses: 1, NameErrors: 1}
	second := ResolverIntervalCounts{From: first.To, To: end}
	if err != nil || got.Frames != 1 || got.Selected != 1 || len(got.Intervals) != 2 ||
		got.Intervals[0] != first || got.Intervals[1] != second {
		t.Fatalf("got %+v, %v", got, err)
	}
	got, err = ReduceClosedCapture(t.Context(), bytes.NewReader(file[:len(file)-12]), start, end)
	if !errors.Is(err, ErrIncomplete) || got.Intervals != nil {
		t.Fatalf("incomplete capture returned publishable counts: %+v, %v", got, err)
	}
	got, err = ReduceClosedCapture(t.Context(), bytes.NewReader(file), first.To, end)
	if !errors.Is(err, ErrCaptureWindow) || got.Intervals != nil {
		t.Fatalf("out-of-window capture returned publishable counts: %+v, %v", got, err)
	}
}

func TestResolverPressureRequiresAdjacentObservedFailures(t *testing.T) {
	from := time.Date(2026, 11, 20, 3, 0, 0, 0, time.UTC)
	rule := PressureRule{MinResponses: 100, MinErrors: 50, ErrorShareBasisPoints: 5000}
	first := ResolverIntervalCounts{From: from, To: from.Add(ResolverInterval), Responses: 200, NameErrors: 100}
	second := ResolverIntervalCounts{From: first.To, To: first.To.Add(ResolverInterval), Responses: 100, NameErrors: 50}
	got, err := AssessResolverPressure(rule, first, second)
	if err != nil || len(got) != 1 || got[0] != (ResolverPressure{Kind: NameErrorPressure, Previous: first, Current: second}) {
		t.Fatalf("sustained modeled name-error pressure: %+v, %v", got, err)
	}
	ordinary := second
	ordinary.Responses, ordinary.NameErrors = 1000, 2
	got, err = AssessResolverPressure(rule, first, ordinary)
	if err != nil || len(got) != 0 {
		t.Fatalf("ordinary response burst: %+v, %v", got, err)
	}
	gap := second
	gap.From, gap.To = gap.From.Add(time.Minute), gap.To.Add(time.Minute)
	got, err = AssessResolverPressure(rule, first, gap)
	if !errors.Is(err, ErrCaptureWindow) || len(got) != 0 {
		t.Fatalf("missing source coverage: %+v, %v", got, err)
	}
}
