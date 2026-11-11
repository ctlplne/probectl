// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package device

import "context"

// emitExactCounters owns complete copies before the legacy in-place filter can
// change the metric slice. Delivery failure stays observable and never prevents
// the independent legacy stream. No sender witness or continuity is inferred.
func (r *Runtime) emitExactCounters(ctx context.Context, metrics []Metric) {
	emitter, available := r.emit.(CounterEmitter)
	if !available {
		r.stats.ExactCounterUnavailable.Add(1)
		return
	}
	count := 0
	for _, metric := range metrics {
		if err := ctx.Err(); err != nil {
			r.stats.ExactCounterEmitErrors.Add(1)
			return
		}
		if metric.ExactCounter == nil {
			continue
		}
		if r.cfg == nil || r.cfg.TenantID == "" || r.cfg.AgentID == "" || metric.TenantID != r.cfg.TenantID || metric.AgentID != r.cfg.AgentID || metric.Source != SourceSNMP || !isCounter(metric.Name) || (metric.ExactCounter.Width != 32 && metric.ExactCounter.Width != 64) || (metric.ExactCounter.Width == 32 && metric.ExactCounter.Value > 1<<32-1) {
			r.stats.ExactCounterEmitErrors.Add(1)
			r.log.Error("exact counter batch refused invalid collector scope or counter domain")
			return // No valid prefix may escape a mixed/invalid batch.
		}
		count++
	}
	if count == 0 {
		return
	}
	owned := make([]Metric, 0, count)
	for _, metric := range metrics {
		if err := ctx.Err(); err != nil {
			r.stats.ExactCounterEmitErrors.Add(1)
			return
		}
		if metric.ExactCounter == nil {
			continue
		}
		exact := *metric.ExactCounter
		metric.ExactCounter = &exact
		metric.InterfaceAddresses = append([]string(nil), metric.InterfaceAddresses...)
		owned = append(owned, metric)
	}
	if err := emitter.EmitCounters(ctx, owned); err != nil {
		r.stats.ExactCounterEmitErrors.Add(1)
		r.log.Error("exact counter delivery failed", "tenant_id", r.cfg.TenantID, "samples", len(owned), "reason", "delivery_failed")
		return
	}
	r.stats.ExactCounterBatches.Add(1)
	r.stats.ExactCounterSamples.Add(uint64(len(owned)))
}
