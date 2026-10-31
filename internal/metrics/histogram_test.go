// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package metrics

import (
	"math"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func TestHistogramExposesConsistentCumulativeBuckets(t *testing.T) {
	r := New("test", "test")
	bounds := []float64{0.125, 1}
	h, err := r.Histogram("probectl_fixture_duration_seconds", "Fixture duration.", bounds)
	if err != nil {
		t.Fatal(err)
	}
	bounds[0] = 100 // The caller cannot mutate the registered bucket policy.
	for _, value := range []float64{0.125, 0.5, 2, -1, math.NaN(), math.Inf(1)} {
		h.Observe(value)
	}
	again, err := r.Histogram("probectl_fixture_duration_seconds", "Same family.", []float64{0.125, 1})
	if err != nil || again != h {
		t.Fatal("re-registration reset observations", err)
	}
	w := httptest.NewRecorder()
	r.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/metrics", nil))
	for _, want := range []string{"# TYPE probectl_fixture_duration_seconds histogram", `probectl_fixture_duration_seconds_bucket{le="0.125"} 1`, `probectl_fixture_duration_seconds_bucket{le="1"} 2`, `probectl_fixture_duration_seconds_bucket{le="+Inf"} 3`, "probectl_fixture_duration_seconds_sum 2.625", "probectl_fixture_duration_seconds_count 3"} {
		if !strings.Contains(w.Body.String(), want+"\n") {
			t.Fatal("incorrect histogram exposition", want)
		}
	}
	if _, err := r.Histogram("probectl_fixture_duration_seconds", "Changed bounds.", []float64{1}); err == nil {
		t.Fatal("registered bucket policy changed")
	}
	for _, invalid := range [][]float64{nil, {0}, {-1}, {1, 1}, {2, 1}, {math.NaN()}, {math.Inf(1)}} {
		if _, err := r.Histogram("invalid_fixture", "invalid", invalid); err == nil {
			t.Fatal("invalid histogram accepted")
		}
	}
}

func TestHistogramConcurrentScrapesNeverSplitBucketCountSnapshot(t *testing.T) {
	r := New("test", "test")
	h, err := r.Histogram("probectl_concurrent", "Concurrent fixture.", []float64{1})
	if err != nil {
		t.Fatal(err)
	}
	var workers sync.WaitGroup
	for i := 0; i < 8; i++ {
		workers.Go(func() {
			for j := 0; j < 1000; j++ {
				h.Observe(0.5)
			}
		})
	}
	for i := 0; i < 30; i++ {
		w := httptest.NewRecorder()
		r.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/metrics", nil))
		var finite, infinite, count string
		for _, line := range strings.Split(w.Body.String(), "\n") {
			if strings.HasPrefix(line, `probectl_concurrent_bucket{le="1"} `) {
				_, finite, _ = strings.Cut(line, " ")
			}
			if strings.HasPrefix(line, `probectl_concurrent_bucket{le="+Inf"} `) {
				_, infinite, _ = strings.Cut(line, " ")
			}
			if strings.HasPrefix(line, "probectl_concurrent_count ") {
				_, count, _ = strings.Cut(line, " ")
			}
		}
		if count == "" || finite != count || infinite != count {
			t.Fatal("histogram scrape observed a torn count/bucket snapshot")
		}
	}
	workers.Wait()
	w := httptest.NewRecorder()
	r.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/metrics", nil))
	if !strings.Contains(w.Body.String(), "probectl_concurrent_count 8000\n") {
		t.Fatal("lost concurrent observations")
	}
}
