// SPDX-License-Identifier: LicenseRef-probectl-TBD

// Package anomaly provides local, pluggable anomaly models over tenant-scoped
// feature vectors. The default model is in-process and deterministic: it makes
// no network calls, needs no external model server, and treats every input row as
// untrusted until its tenant matches the query tenant.
package anomaly

import (
	"context"
	"errors"
	"fmt"
	"math"
	"sort"
	"time"
)

var (
	// ErrNoTenant refuses unscoped model evaluation.
	ErrNoTenant = errors.New("anomaly: tenant_id is required")
	// ErrCrossTenantFeature refuses feature vectors that do not belong to the
	// query tenant. A model must not learn from another tenant's data.
	ErrCrossTenantFeature = errors.New("anomaly: feature tenant does not match query tenant")
)

// Feature is one numeric observation available to an anomaly model.
type Feature struct {
	TenantID string            `json:"tenant_id"`
	Plane    string            `json:"plane"`
	Source   string            `json:"source"`
	Subject  string            `json:"subject"`
	Metric   string            `json:"metric"`
	TS       time.Time         `json:"ts"`
	Value    float64           `json:"value"`
	Citation string            `json:"citation"`
	Attrs    map[string]string `json:"attrs,omitempty"`
}

// Citation is evidence behind a finding. Ref is intentionally a caller-owned
// pointer such as an event id, fixture id, or file:line style receipt; the model
// does not fetch it.
type Citation struct {
	Ref    string `json:"ref"`
	Plane  string `json:"plane"`
	Source string `json:"source"`
	Metric string `json:"metric"`
}

// TrainingWindow records the local samples the model learned normal behavior
// from before scoring the current observation.
type TrainingWindow struct {
	Start   time.Time `json:"start"`
	End     time.Time `json:"end"`
	Samples int       `json:"samples"`
}

// Query controls one tenant-scoped model evaluation.
type Query struct {
	TenantID    string
	Sensitivity float64
	MinValue    float64
}

// Finding is one anomalous subject/metric, with model and training provenance.
type Finding struct {
	TenantID       string             `json:"tenant_id"`
	Plane          string             `json:"plane"`
	Source         string             `json:"source"`
	Subject        string             `json:"subject"`
	Metric         string             `json:"metric"`
	TS             time.Time          `json:"ts"`
	Current        float64            `json:"current"`
	Baseline       float64            `json:"baseline"`
	Stddev         float64            `json:"stddev"`
	Score          float64            `json:"score"`
	Model          string             `json:"model"`
	TrainingWindow TrainingWindow     `json:"training_window"`
	Citations      []Citation         `json:"citations"`
	Features       map[string]float64 `json:"features"`
}

// Model evaluates tenant-scoped features for anomalies.
type Model interface {
	Name() string
	Evaluate(ctx context.Context, features []Feature, q Query) ([]Finding, error)
}

// NewLocalZScoreModel returns the built-in local model. It learns a per-series
// mean/stddev from the training window and scores the latest sample. It also
// carries the whole latest subject vector into each finding so callers can cite
// multi-signal context without sending data anywhere.
func NewLocalZScoreModel() Model { return LocalZScoreModel{} }

// LocalZScoreModel is probectl's air-gapped default anomaly model.
type LocalZScoreModel struct{}

// Name identifies the local model in API results and audit receipts.
func (LocalZScoreModel) Name() string { return "local-zscore-v1" }

// Evaluate scores each tenant-local series. It refuses mixed-tenant input before
// learning, so a caller cannot accidentally train tenant A's model on tenant B.
func (m LocalZScoreModel) Evaluate(ctx context.Context, features []Feature, q Query) ([]Finding, error) {
	if q.TenantID == "" {
		return nil, ErrNoTenant
	}
	if q.Sensitivity <= 0 {
		q.Sensitivity = 3
	}
	for _, f := range features {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		if f.TenantID != q.TenantID {
			return nil, fmt.Errorf("%w: got %q want %q", ErrCrossTenantFeature, f.TenantID, q.TenantID)
		}
	}

	latestVectors := latestSubjectVectors(features, q.TenantID)
	series := groupSeries(features)
	var out []Finding
	for _, pts := range series {
		sort.Slice(pts, func(i, j int) bool { return pts[i].TS.Before(pts[j].TS) })
		if len(pts) < 4 {
			continue
		}
		base := pts[:len(pts)-1]
		cur := pts[len(pts)-1]
		if cur.Value < q.MinValue {
			continue
		}
		mean, std := meanStddev(base)
		score, ok := highScore(cur.Value, mean, std, q.Sensitivity)
		if !ok {
			continue
		}
		out = append(out, Finding{
			TenantID: cur.TenantID,
			Plane:    cur.Plane,
			Source:   cur.Source,
			Subject:  cur.Subject,
			Metric:   cur.Metric,
			TS:       cur.TS,
			Current:  cur.Value,
			Baseline: mean,
			Stddev:   std,
			Score:    score,
			Model:    m.Name(),
			TrainingWindow: TrainingWindow{
				Start:   base[0].TS,
				End:     base[len(base)-1].TS,
				Samples: len(base),
			},
			Citations: append(currentCitation(cur), trainingCitations(base)...),
			Features:  latestVectors[subjectVectorKey(cur.TenantID, cur.Subject, cur.TS)],
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Score != out[j].Score {
			return out[i].Score > out[j].Score
		}
		if out[i].Subject != out[j].Subject {
			return out[i].Subject < out[j].Subject
		}
		return out[i].Metric < out[j].Metric
	})
	return out, nil
}

type seriesKey struct {
	tenant, plane, source, subject, metric string
}

func groupSeries(features []Feature) map[seriesKey][]Feature {
	series := make(map[seriesKey][]Feature)
	for _, f := range features {
		if f.Metric == "" || f.Subject == "" || f.TS.IsZero() {
			continue
		}
		k := seriesKey{f.TenantID, f.Plane, f.Source, f.Subject, f.Metric}
		series[k] = append(series[k], f)
	}
	return series
}

func latestSubjectVectors(features []Feature, tenantID string) map[string]map[string]float64 {
	latest := make(map[string]time.Time)
	for _, f := range features {
		if f.TenantID != tenantID || f.Subject == "" || f.TS.IsZero() {
			continue
		}
		k := f.TenantID + "\x00" + f.Subject
		if f.TS.After(latest[k]) {
			latest[k] = f.TS
		}
	}
	out := make(map[string]map[string]float64)
	for _, f := range features {
		if f.TenantID != tenantID || f.Subject == "" || !f.TS.Equal(latest[f.TenantID+"\x00"+f.Subject]) {
			continue
		}
		k := subjectVectorKey(f.TenantID, f.Subject, f.TS)
		if out[k] == nil {
			out[k] = make(map[string]float64)
		}
		out[k][f.Plane+"."+f.Metric] = f.Value
	}
	return out
}

func subjectVectorKey(tenantID, subject string, ts time.Time) string {
	return tenantID + "\x00" + subject + "\x00" + ts.Format(time.RFC3339Nano)
}

func meanStddev(base []Feature) (float64, float64) {
	var sum float64
	for _, f := range base {
		sum += f.Value
	}
	mean := sum / float64(len(base))
	var sq float64
	for _, f := range base {
		d := f.Value - mean
		sq += d * d
	}
	return mean, math.Sqrt(sq / float64(len(base)))
}

func highScore(value, mean, std, sensitivity float64) (float64, bool) {
	if std == 0 {
		switch {
		case mean == 0 && value > 0:
			return sensitivity + 1, true
		case mean > 0 && value > mean*1.5:
			return sensitivity + (value/mean - 1), true
		default:
			return 0, false
		}
	}
	score := (value - mean) / std
	return score, score > sensitivity
}

func currentCitation(f Feature) []Citation {
	if f.Citation == "" {
		return nil
	}
	return []Citation{{Ref: f.Citation, Plane: f.Plane, Source: f.Source, Metric: f.Metric}}
}

func trainingCitations(base []Feature) []Citation {
	if len(base) == 0 {
		return nil
	}
	first := base[0]
	last := base[len(base)-1]
	out := make([]Citation, 0, 2)
	if first.Citation != "" {
		out = append(out, Citation{Ref: first.Citation, Plane: first.Plane, Source: first.Source, Metric: first.Metric})
	}
	if last.Citation != "" && last.Citation != first.Citation {
		out = append(out, Citation{Ref: last.Citation, Plane: last.Plane, Source: last.Source, Metric: last.Metric})
	}
	return out
}
