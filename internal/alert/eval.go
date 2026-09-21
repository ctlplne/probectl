// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package alert

import "math"

// baseline holds a rolling window of recent values for anomaly detection. It is
// the stateful core of a Baseline rule: until the window is full it reports
// "warming" and never fires (cold-start handling — S16 watch-out).
type baseline struct {
	window int
	buf    []float64
}

type baselineEvaluation struct {
	anomalous bool
	warming   bool
	mean      float64
	std       float64
	samples   int
	required  int
}

func newBaseline(window int) *baseline {
	if window < 2 {
		window = 2
	}
	return &baseline{window: window}
}

// evaluate compares value against the established baseline, then records it (the
// baseline is adaptive). It returns whether value is anomalous and whether the
// baseline is still warming up.
func (b *baseline) evaluate(value, sensitivity float64) baselineEvaluation {
	if len(b.buf) < b.window {
		b.add(value)
		mean, std := meanStd(b.buf)
		return baselineEvaluation{
			warming: true, mean: mean, std: std, samples: len(b.buf), required: b.window,
		}
	}
	mean, std := meanStd(b.buf)
	anomalous := false
	if std == 0 {
		anomalous = value != mean
	} else {
		anomalous = math.Abs(value-mean) > sensitivity*std
	}
	b.add(value)
	return baselineEvaluation{
		anomalous: anomalous, mean: mean, std: std, samples: b.window, required: b.window,
	}
}

func (b *baseline) add(v float64) {
	b.buf = append(b.buf, v)
	if len(b.buf) > b.window {
		b.buf = b.buf[1:]
	}
}

// meanStd returns the mean and population standard deviation of xs.
func meanStd(xs []float64) (mean, std float64) {
	n := float64(len(xs))
	if n == 0 {
		return 0, 0
	}
	var sum float64
	for _, x := range xs {
		sum += x
	}
	mean = sum / n
	var variance float64
	for _, x := range xs {
		d := x - mean
		variance += d * d
	}
	return mean, math.Sqrt(variance / n)
}
