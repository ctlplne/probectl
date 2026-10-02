// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package perf

import (
	"strings"
	"testing"
)

// TestScaleGateCatchesInjectedRegression is the explicit PLAT-10 gate-integrity
// proof. The finding's complaint was that the perf "gates" run in-memory fakes
// or "cannot fail". This asserts the opposite for every ARMED branch of the SLO
// evaluator: a deliberately-regressed report produces the matching violation,
// and a healthy report produces none — so the gate is neither inert nor a
// blanket failer. The ABSOLUTE throughput/p95 SLO NUMBERS still require a
// reference-hardware run (EXC-GATE-01 / the PLAT-10 measured L/XL/XXL rows +
// 72h soak), which cannot run on this host; the gate's fail-machinery, however,
// is proven here, in CI, with no services.
func TestScaleGateCatchesInjectedRegression(t *testing.T) {
	p, err := ProfileFor(TierM, 1)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		rep  ScaleReport
		want string // the violation must contain this
	}{
		{
			name: "throughput floor (reference scale)",
			rep: ScaleReport{Profile: p, AtCIScale: false,
				Ingest: IngestReport{Throughput: p.SLO.MinIngestThroughput / 2, PublishLatency: LatencyStat{P95: p.SLO.MaxPublishP95 / 2}}},
			want: "ingest throughput",
		},
		{
			name: "publish p95 ceiling (reference scale)",
			rep: ScaleReport{Profile: p, AtCIScale: false,
				Ingest: IngestReport{Throughput: p.SLO.MinIngestThroughput, PublishLatency: LatencyStat{P95: p.SLO.MaxPublishP95 * 3}}},
			want: "publish p95",
		},
		{
			name: "noisy-neighbor correctness (CI scale, always armed)",
			rep: ScaleReport{Profile: p, AtCIScale: true,
				Noisy: NoisyReport{Ran: true, QuietCorrect: false, FairnessOn: true, NoisyPublished: 100, NoisyAdmitFrac: 0.1}},
			want: "CORRECTNESS BROKEN",
		},
		{
			name: "fairness gate not shedding (CI scale, SCALE-004)",
			rep: ScaleReport{Profile: p, AtCIScale: true,
				Noisy: NoisyReport{Ran: true, QuietCorrect: true, FairnessOn: true, NoisyPublished: 2000, NoisyAdmitFrac: 1.0}},
			want: "did NOT shed",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := tc.rep
			r.evaluate()
			found := false
			for _, v := range r.Violations {
				if strings.Contains(v, tc.want) {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("PLAT-10: injected %s regression did not trip the gate; violations=%v", tc.name, r.Violations)
			}
		})
	}

	// A healthy reference-scale report trips nothing — the gate must not be a
	// blanket failer (which would be as useless as one that cannot fail).
	healthy := ScaleReport{Profile: p, AtCIScale: false,
		Ingest: IngestReport{Throughput: p.SLO.MinIngestThroughput, PublishLatency: LatencyStat{P95: p.SLO.MaxPublishP95 / 2}},
		Noisy:  NoisyReport{Ran: true, QuietCorrect: true, FairnessOn: true, NoisyPublished: 2000, NoisyAdmitFrac: 0.4}}
	healthy.evaluate()
	if len(healthy.Violations) != 0 {
		t.Fatalf("PLAT-10: a healthy report must trip no gate, got %v", healthy.Violations)
	}
}
