// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package metrics

import (
	"errors"
	"fmt"
	"io"
	"math"
	"slices"
	"sort"
	"sync"
)

// Histogram retains fixed bucket counts, never per-request samples or labels.
// Construct with Registry.Histogram; observations and scrapes are concurrent-safe.
type Histogram struct {
	mu     sync.Mutex
	bounds []float64
	bins   []uint64
	count  uint64
	sum    float64
	help   string
}

// Histogram registers a fixed, strictly increasing set of finite positive
// bounds. Re-registering identical bounds preserves the existing observations.
// Names follow the same code-owned identifier convention as Counter.
func (r *Registry) Histogram(name, help string, bounds []float64) (*Histogram, error) {
	for i, bound := range bounds {
		if bound <= 0 || math.IsNaN(bound) || math.IsInf(bound, 0) || i > 0 && bound <= bounds[i-1] {
			return nil, errors.New("metrics: histogram bounds must be finite, positive and strictly increasing")
		}
	}
	if len(bounds) == 0 {
		return nil, errors.New("metrics: histogram requires finite bounds")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if existing := r.histograms[name]; existing != nil {
		if !slices.Equal(existing.bounds, bounds) {
			return nil, errors.New("metrics: histogram bounds cannot change after registration")
		}
		return existing, nil
	}
	h := &Histogram{bounds: slices.Clone(bounds), bins: make([]uint64, len(bounds)+1), help: help}
	r.histograms[name] = h
	return h, nil
}

// Observe records a non-negative finite value. Invalid observations are ignored
// so instrumentation cannot change request behavior or poison exposition.
func (h *Histogram) Observe(value float64) {
	if h == nil || value < 0 || math.IsNaN(value) || math.IsInf(value, 0) {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.bins) == 0 {
		return
	}
	index := sort.Search(len(h.bounds), func(i int) bool { return value <= h.bounds[i] })
	h.bins[index]++
	h.count++
	h.sum += value
}

func (h *Histogram) write(w io.Writer, name string) {
	h.mu.Lock()
	count, sum := h.count, h.sum
	bins := slices.Clone(h.bins)
	h.mu.Unlock()
	fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s histogram\n", name, h.help, name)
	var cumulative uint64
	for i, bound := range h.bounds {
		cumulative += bins[i]
		fmt.Fprintf(w, "%s_bucket{le=%q} %d\n", name, fmt.Sprintf("%g", bound), cumulative)
	}
	fmt.Fprintf(w, "%s_bucket{le=\"+Inf\"} %d\n%s_sum %g\n%s_count %d\n", name, count, name, sum, name, count)
}
