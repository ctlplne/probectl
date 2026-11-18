// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"encoding/json"
	"maps"
	"math"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/promapi"
	"github.com/ctlplne/probectl/internal/store/tsdb"
)

const deviceSampleTimePrefix = "probectl_observation_time_"

type deviceSampleQuerier interface {
	InstantVectorAt(context.Context, string, time.Time, int64) ([]tsdb.LabeledSample, error)
}

func deviceMetricSelector(tenant, device, metric string) promapi.Selector {
	sel := promapi.Selector{Metric: metric}
	if metric == "" {
		sel.Matchers = append(sel.Matchers, promapi.Matcher{Name: "__name__", Op: "=~", Value: deviceMetricPrefix + ".+"})
	}
	if device != "" {
		sel.Matchers = append(sel.Matchers, promapi.Matcher{Name: "device", Op: "=", Value: device})
	}
	return promapi.ForceTenant(sel, tenant)
}

// An instant vector's envelope timestamps are query evaluation times. Discover
// the metric names, then read values and timestamps in a single evaluation.
// Each timestamp branch selects one metric under the same tenant/device scope
// and restores its name in a namespace disjoint from stored device metrics.
func deviceMetricSeriesFromTSDB(ctx context.Context, q deviceSampleQuerier, tenant, device, metric string, maxQueryBytes int64) ([]tsdb.Series, error) {
	for _, value := range []string{tenant, device, metric} {
		if strings.ContainsAny(value, "\"\\\n") {
			return nil, apierror.BadRequest("device metrics filter contains characters that cannot appear in a label value")
		}
	}
	at := time.Now().UTC().Truncate(time.Millisecond)
	selector := deviceMetricSelector(tenant, device, metric)
	queryLimit := maxQueryBytes * 2
	discover := `group by (__name__, tenant_id) (` + selector.String() + `)`
	samples, err := q.InstantVectorAt(ctx, discover, at, queryLimit)
	if err != nil {
		return nil, apierror.Unavailable("device metrics are temporarily unavailable from the TSDB").Wrap(err)
	}
	if len(samples) == 0 {
		return nil, nil
	}
	metrics := make(map[string]struct{})
	for _, sample := range samples {
		if !deviceMetricBelongsToSelection(sample, tenant, "", metric) {
			return nil, apierror.Unavailable("device metric series are outside the requested scope")
		}
		metrics[sample.Labels["__name__"]] = struct{}{}
	}
	query, err := deviceSampleTimesQuery(selector, metrics, tenant, device, maxQueryBytes)
	if err != nil {
		return nil, err
	}
	observations, err := q.InstantVectorAt(ctx, query, at, queryLimit)
	if err != nil {
		return nil, apierror.Unavailable("stored device metric times are temporarily unavailable").Wrap(err)
	}
	series, byLabels, times, err := indexDeviceMetricValues(observations, tenant, device, metric)
	if err != nil {
		return nil, err
	}
	if err := joinDeviceSampleTimes(series, byLabels, times, at.UnixMilli()); err != nil {
		return nil, err
	}
	return series, nil
}

func deviceMetricBelongsToSelection(sample tsdb.LabeledSample, tenant, device, metric string) bool {
	name := sample.Labels["__name__"]
	return sample.Labels[promapi.TenantLabel] == tenant && (device == "" || sample.Labels["device"] == device) &&
		(metric == "" || name == metric) && strings.HasPrefix(name, deviceMetricPrefix) && promapi.ValidMetricName(name)
}

func indexDeviceMetricValues(samples []tsdb.LabeledSample, tenant, device, metric string) ([]tsdb.Series, map[string]int, []tsdb.LabeledSample, error) {
	series := make([]tsdb.Series, 0, len(samples)/2)
	byLabels := make(map[string]int, len(samples)/2)
	times := make([]tsdb.LabeledSample, 0, len(samples)/2)
	for _, sample := range samples {
		name := sample.Labels["__name__"]
		if strings.HasPrefix(name, deviceSampleTimePrefix) {
			times = append(times, sample)
			continue
		}
		if !deviceMetricBelongsToSelection(sample, tenant, device, metric) {
			return nil, nil, nil, apierror.Unavailable("device metric series are outside the requested scope")
		}
		key, _ := json.Marshal(sample.Labels) // A map of strings always has a JSON representation.
		if _, duplicate := byLabels[string(key)]; duplicate {
			return nil, nil, nil, apierror.Unavailable("the TSDB returned duplicate device metric series")
		}
		byLabels[string(key)] = len(series)
		labels := maps.Clone(sample.Labels)
		delete(labels, "__name__")
		series = append(series, tsdb.Series{Metric: name, Labels: labels, Value: sample.Value})
	}
	return series, byLabels, times, nil
}

func deviceSampleTimesQuery(values promapi.Selector, metrics map[string]struct{}, tenant, device string, remaining int64) (string, error) {
	var query strings.Builder
	query.WriteString(values.String())
	remaining -= int64(query.Len())
	const union = ` or on (__name__) `
	for _, name := range slices.Sorted(maps.Keys(metrics)) {
		selector := deviceMetricSelector(tenant, device, name)
		term := `label_replace(timestamp(` + selector.String() + `), "__name__", ` + strconv.Quote(deviceSampleTimePrefix+name) + `, "tenant_id", ".+")`
		remaining -= int64(len(term) + len(union))
		if remaining < 0 {
			return "", apierror.TooLarge("device metric timestamp query exceeds configured query memory")
		}
		query.WriteString(union)
		query.WriteString(term)
	}
	return query.String(), nil
}

func joinDeviceSampleTimes(series []tsdb.Series, byLabels map[string]int, times []tsdb.LabeledSample, atMillis int64) error {
	if len(times) != len(series) {
		return apierror.Unavailable("the TSDB returned an incomplete device metric timestamp vector")
	}
	for _, sample := range times {
		labels := maps.Clone(sample.Labels)
		labels["__name__"] = strings.TrimPrefix(labels["__name__"], deviceSampleTimePrefix)
		key, _ := json.Marshal(labels)
		index, found := byLabels[string(key)]
		millis := math.Round(sample.Value * 1000)
		if !found || series[index].TimeMillis != 0 || !(millis > 0 && millis <= float64(atMillis)) {
			return apierror.Unavailable("device metric timestamps do not match the requested series")
		}
		series[index].TimeMillis = int64(millis)
	}
	return nil
}
