// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"net/netip"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/anomaly"
)

func TestDDoSApplicationKeepsCompletedRequestsThatCrossTheWindowEnd(t *testing.T) {
	from := time.Date(2026, time.November, 20, 11, 30, 0, 0, time.UTC)
	to := from.Add(5 * time.Second)
	window := anomaly.DDoSObservation{TenantID: benchmarkDDoSTenant, Target: netip.MustParsePrefix("192.0.2.1/32"), From: from, To: to}
	spans := benchmarkDDoSAppSpans(benchmarkDDoSApplication{Requests: 20, LatencyMS: 25}, from)
	spans[0].Start = to.Add(-5 * time.Millisecond)
	completion := spans[0].Start.Add(spans[0].Duration)
	observed, usable, err := projectDDoSApplicationWindow(t.Context(), window, "synthetic-public-site", 443, completion, spans)
	if err != nil || !usable || observed.Requests != 20 || observed.Successes != 20 || len(observed.Digest) != 64 {
		t.Fatal("a completed request left the matching observation clock unqualified", observed, usable, err)
	}
	if _, usable, err := projectDDoSApplicationWindow(t.Context(), window, "synthetic-public-site", 443, completion.Add(-time.Nanosecond), spans); err != nil || usable {
		t.Fatal("future evidence qualified the current observation", err)
	}
	spans[0].Duration = 6 * time.Second
	spans[1].Duration = 6 * time.Second
	completion = spans[0].Start.Add(spans[0].Duration)
	if _, usable, err := projectDDoSApplicationWindow(t.Context(), window, "synthetic-public-site", 443, completion.Add(-time.Nanosecond), spans); err != nil || usable {
		t.Fatal("an ongoing slow request qualified the current observation", err)
	}
	observed, usable, err = projectDDoSApplicationWindow(t.Context(), window, "synthetic-public-site", 443, completion, spans)
	if err != nil || !usable || observed.Requests != 20 || observed.P95 != 6*time.Second {
		t.Fatal("completed slow requests did not contribute their measured latency", observed, usable, err)
	}
}
