package promapi

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/store/tsdb"
)

// DefaultLookback is how far an instant query looks back for the latest sample
// of each series (mirrors Prometheus's 5m lookback delta).
const DefaultLookback = 5 * time.Minute

// DefaultMaxSeries caps the number of distinct series a single query or
// federation scrape may return (cardinality guard — S40 "watch out for").
const DefaultMaxSeries = 5000

// Point is one (timestamp, value) sample.
type Point struct {
	TimeMillis int64
	Value      float64
}

// ResultSeries is one distinct series in a query result: its identity (metric
// name + labels) and its samples.
type ResultSeries struct {
	Metric string
	Labels map[string]string
	Points []Point
}

// seriesKey canonically identifies a series (metric + sorted labels).
func seriesKey(metric string, labels map[string]string) string {
	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	b.WriteString(metric)
	for _, k := range keys {
		b.WriteByte(0)
		b.WriteString(k)
		b.WriteByte(1)
		b.WriteString(labels[k])
	}
	return b.String()
}

// collect groups snapshot samples matching sel into distinct series, keeping
// samples within [startMs, endMs]. Series order is stable (first-seen).
func collect(snapshot []tsdb.Series, sel Selector, startMs, endMs int64, maxSeries int) ([]ResultSeries, error) {
	if maxSeries <= 0 {
		maxSeries = DefaultMaxSeries
	}
	idx := map[string]int{}
	var out []ResultSeries
	for _, s := range snapshot {
		if s.TimeMillis < startMs || s.TimeMillis > endMs {
			continue
		}
		if !sel.Matches(s.Metric, s.Labels) {
			continue
		}
		k := seriesKey(s.Metric, s.Labels)
		i, ok := idx[k]
		if !ok {
			if len(out) >= maxSeries {
				return nil, fmt.Errorf("query matches more than %d series (cardinality cap); narrow the selector", maxSeries)
			}
			labels := make(map[string]string, len(s.Labels))
			for lk, lv := range s.Labels {
				labels[lk] = lv
			}
			out = append(out, ResultSeries{Metric: s.Metric, Labels: labels})
			i = len(out) - 1
			idx[k] = i
		}
		out[i].Points = append(out[i].Points, Point{TimeMillis: s.TimeMillis, Value: s.Value})
	}
	for i := range out {
		sort.Slice(out[i].Points, func(a, b int) bool { return out[i].Points[a].TimeMillis < out[i].Points[b].TimeMillis })
	}
	return out, nil
}

// Instant evaluates sel at time at: the latest sample of each matching series
// within the lookback window. Series with no sample in the window are omitted.
func Instant(snapshot []tsdb.Series, sel Selector, at time.Time, lookback time.Duration, maxSeries int) ([]ResultSeries, error) {
	if lookback <= 0 {
		lookback = DefaultLookback
	}
	atMs := at.UnixMilli()
	series, err := collect(snapshot, sel, atMs-lookback.Milliseconds(), atMs, maxSeries)
	if err != nil {
		return nil, err
	}
	out := series[:0]
	for _, rs := range series {
		if len(rs.Points) == 0 {
			continue
		}
		rs.Points = rs.Points[len(rs.Points)-1:] // latest only
		out = append(out, rs)
	}
	return out, nil
}

// Range evaluates sel over [start, end]: every stored sample of each matching
// series inside the window, time-ascending. (Raw samples — no step
// interpolation; Grafana renders them directly.)
func Range(snapshot []tsdb.Series, sel Selector, start, end time.Time, maxSeries int) ([]ResultSeries, error) {
	return collect(snapshot, sel, start.UnixMilli(), end.UnixMilli(), maxSeries)
}

// LabelNames returns the sorted set of label names (plus __name__) across
// snapshot samples in [start, end] matching every selector in sels (an empty
// sels means "all series").
func LabelNames(snapshot []tsdb.Series, sels []Selector, start, end time.Time, maxSeries int) ([]string, error) {
	set := map[string]bool{"__name__": true}
	collected, err := collectMulti(snapshot, sels, start, end, maxSeries)
	if err != nil {
		return nil, err
	}
	for _, rs := range collected {
		for k := range rs.Labels {
			set[k] = true
		}
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out, nil
}

// LabelValues returns the sorted distinct values of one label (__name__ yields
// metric names) across matching samples.
func LabelValues(snapshot []tsdb.Series, name string, sels []Selector, start, end time.Time, maxSeries int) ([]string, error) {
	set := map[string]bool{}
	collected, err := collectMulti(snapshot, sels, start, end, maxSeries)
	if err != nil {
		return nil, err
	}
	for _, rs := range collected {
		if name == "__name__" {
			set[rs.Metric] = true
			continue
		}
		if v, ok := rs.Labels[name]; ok {
			set[v] = true
		}
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out, nil
}

// Series returns the distinct series identities matching any of sels in
// [start, end].
func Series(snapshot []tsdb.Series, sels []Selector, start, end time.Time, maxSeries int) ([]ResultSeries, error) {
	return collectMulti(snapshot, sels, start, end, maxSeries)
}

// collectMulti unions matches across selectors (deduplicated by series key).
func collectMulti(snapshot []tsdb.Series, sels []Selector, start, end time.Time, maxSeries int) ([]ResultSeries, error) {
	if maxSeries <= 0 {
		maxSeries = DefaultMaxSeries
	}
	seen := map[string]bool{}
	var out []ResultSeries
	for _, sel := range sels {
		series, err := collect(snapshot, sel, start.UnixMilli(), end.UnixMilli(), maxSeries)
		if err != nil {
			return nil, err
		}
		for _, rs := range series {
			k := seriesKey(rs.Metric, rs.Labels)
			if seen[k] {
				continue
			}
			seen[k] = true
			if len(out) >= maxSeries {
				return nil, fmt.Errorf("query matches more than %d series (cardinality cap); narrow the selector", maxSeries)
			}
			out = append(out, rs)
		}
	}
	return out, nil
}
