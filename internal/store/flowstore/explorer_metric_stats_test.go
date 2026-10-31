// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flowstore

import (
	"math/big"
	"testing"
	"time"
)

func TestExplorerMetricStatisticsIncludeIdleBucketsAndExactIntegers(t *testing.T) {
	samples := []metricBucket{{value: big.NewRat(100, 1), duration: time.Minute}, {value: big.NewRat(200, 1), duration: time.Minute}}
	for _, tc := range []struct{ calculation, want string }{{"avg", "15"}, {"p95", "100"}, {"p99", "200"}, {"max", "200"}, {"total", "300"}} {
		got, err := calculateFlowMetric(samples, 20, 20*time.Minute, tc.calculation, big.NewRat(300, 1), false)
		if err != nil || got.RatString() != tc.want {
			t.Fatalf("%s with18 idle buckets=%v %v, want%s", tc.calculation, got, err, tc.want)
		}
	}
	huge, _ := new(big.Int).SetString("36893488147419103230", 10)
	value := new(big.Rat).SetInt(huge)
	got, err := calculateFlowMetric([]metricBucket{{value: value, duration: time.Minute}}, 1, time.Minute, "p99", value, false)
	if err != nil || got.Num().Cmp(huge) != 0 {
		t.Fatalf("percentile rounded a large integer: %v %v", got, err)
	}
	// Weighted zeros do not allocate a million buckets for a mostly-idle range.
	got, err = calculateFlowMetric(samples, 1000000, 1000000*time.Minute, "p99", big.NewRat(300, 1), false)
	if err != nil || got.Sign() != 0 {
		t.Fatalf("sparse long-range percentile=%v %v", got, err)
	}
}

func TestExplorerMetricRateAverageWeightsPartialBucketsAndDistinctTotal(t *testing.T) {
	samples := []metricBucket{{value: big.NewRat(100, 1), duration: time.Minute}, {value: big.NewRat(200, 1), duration: 30 * time.Second}}
	got, err := calculateFlowMetric(samples, 2, 90*time.Second, "avg", big.NewRat(12000, 1), true)
	if err != nil || got.RatString() != "400/3" {
		t.Fatalf("partial-bucket average=%v %v", got, err)
	}
	// The same IP in both buckets is one whole-window distinct value.
	got, err = calculateFlowMetric([]metricBucket{{value: big.NewRat(1, 1), duration: time.Minute}, {value: big.NewRat(1, 1), duration: time.Minute}}, 2, 2*time.Minute, "total", big.NewRat(1, 1), false)
	if err != nil || got.RatString() != "1" {
		t.Fatalf("distinct bucket counts were summed: %v %v", got, err)
	}
}
