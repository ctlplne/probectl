// SPDX-License-Identifier: LicenseRef-probectl-TBD

package flowstore

import (
	"context"
	"math"
	"sort"
	"strconv"

	"github.com/imfeelingtheagi/probectl/internal/anomaly"
)

var defaultAnomalyModel anomaly.Model = anomaly.NewLocalZScoreModel()

// DetectAnomaliesWithModel runs a pluggable local anomaly model over
// tenant-scoped flow capacity features. It is exported for tests and future
// model swaps; the default store path uses local-zscore-v1 and never phones home.
func DetectAnomaliesWithModel(ctx context.Context, points []CapacityPoint, q AnomalyQuery, model anomaly.Model) ([]Anomaly, error) {
	if model == nil {
		model = defaultAnomalyModel
	}
	findings, err := model.Evaluate(ctx, capacityAnomalyFeatures(q.TenantID, points), anomaly.Query{
		TenantID:    q.TenantID,
		Sensitivity: q.Sensitivity,
		MinValue:    0,
	})
	if err != nil {
		return nil, err
	}
	out := make([]Anomaly, 0, len(findings))
	for _, f := range findings {
		if f.Metric != "bps" || f.Current < q.MinBps {
			continue
		}
		exporter, iface, ok := splitCapacitySubject(f.Subject)
		if !ok {
			continue
		}
		out = append(out, Anomaly{
			Exporter:         exporter,
			Iface:            iface,
			TS:               f.TS,
			CurrentBps:       f.Current,
			BaselineBps:      f.Baseline,
			StdDevBps:        f.Stddev,
			Sigma:            f.Score,
			Model:            f.Model,
			TrainingWindow:   f.TrainingWindow,
			FeatureCitations: f.Citations,
			Features:         f.Features,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Sigma > out[j].Sigma })
	return out, nil
}

// detectAnomalies is the shared local-model detector. Memory and ClickHouse both
// feed it their tenant-scoped capacity series so the two backends flag
// identically (the memory store is the reference implementation for the SQL).
func detectAnomalies(points []CapacityPoint, q AnomalyQuery) []Anomaly {
	out, err := DetectAnomaliesWithModel(context.Background(), points, q, defaultAnomalyModel)
	if err == nil {
		return out
	}
	// The fallback keeps legacy behavior available if a future model plugin is
	// misconfigured. The default model should not reach this path after q has
	// been normalized by the store.
	return detectAnomaliesStatistical(points, q)
}

func detectAnomaliesStatistical(points []CapacityPoint, q AnomalyQuery) []Anomaly {
	type key struct {
		exporter string
		iface    uint32
	}
	series := make(map[key][]CapacityPoint)
	for _, p := range points {
		k := key{p.Exporter, p.Iface}
		series[k] = append(series[k], p)
	}

	var out []Anomaly
	for k, pts := range series {
		sort.Slice(pts, func(i, j int) bool { return pts[i].TS.Before(pts[j].TS) })
		// Need a baseline of at least 3 buckets plus the bucket under test.
		if len(pts) < 4 {
			continue
		}
		base := pts[:len(pts)-1]
		cur := pts[len(pts)-1]

		var sum float64
		for _, p := range base {
			sum += p.Bps
		}
		mean := sum / float64(len(base))
		var sq float64
		for _, p := range base {
			d := p.Bps - mean
			sq += d * d
		}
		std := math.Sqrt(sq / float64(len(base)))

		if cur.Bps < q.MinBps {
			continue
		}
		threshold := mean + q.Sensitivity*std
		if std == 0 {
			// A flat baseline: anything materially above it is anomalous.
			if cur.Bps <= mean*1.5 {
				continue
			}
		} else if cur.Bps <= threshold {
			continue
		}
		sigma := 0.0
		if std > 0 {
			sigma = (cur.Bps - mean) / std
		}
		out = append(out, Anomaly{
			Exporter:    k.exporter,
			Iface:       k.iface,
			TS:          cur.TS,
			CurrentBps:  cur.Bps,
			BaselineBps: mean,
			StdDevBps:   std,
			Sigma:       sigma,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Sigma > out[j].Sigma })
	return out
}

func capacityAnomalyFeatures(tenantID string, points []CapacityPoint) []anomaly.Feature {
	features := make([]anomaly.Feature, 0, len(points)*2)
	for _, p := range points {
		subject := capacitySubject(p.Exporter, p.Iface)
		ref := capacityCitation(p)
		features = append(features,
			anomaly.Feature{
				TenantID: tenantID,
				Plane:    "flow",
				Source:   p.Exporter,
				Subject:  subject,
				Metric:   "bps",
				TS:       p.TS,
				Value:    p.Bps,
				Citation: ref,
			},
			anomaly.Feature{
				TenantID: tenantID,
				Plane:    "flow",
				Source:   p.Exporter,
				Subject:  subject,
				Metric:   "pps",
				TS:       p.TS,
				Value:    p.Pps,
				Citation: ref,
			},
		)
	}
	return features
}

func capacitySubject(exporter string, iface uint32) string {
	return exporter + "\x00" + strconv.FormatUint(uint64(iface), 10)
}

func splitCapacitySubject(subject string) (string, uint32, bool) {
	for i := 0; i < len(subject); i++ {
		if subject[i] != 0 {
			continue
		}
		n, err := strconv.ParseUint(subject[i+1:], 10, 32)
		if err != nil {
			return "", 0, false
		}
		return subject[:i], uint32(n), true
	}
	return "", 0, false
}

func capacityCitation(p CapacityPoint) string {
	return "flow:capacity:" + p.Exporter + ":if" + strconv.FormatUint(uint64(p.Iface), 10) + ":" +
		strconv.FormatInt(p.TS.Unix(), 10)
}
