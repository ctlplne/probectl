// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package promapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/ctlplne/probectl/internal/store/tsdb"
)

// ReadRawSamples uses an instant range-vector selector to preserve the stored
// sample times in (after, through]. A step query can repeat old values at its
// evaluation times, which would fabricate seasonal training observations.
func (u *Upstream) ReadRawSamples(ctx context.Context, sel Selector, after, through time.Time, maxBytes int64) ([]ResultSeries, error) {
	if err := requireScoped(sel); err != nil {
		return nil, err
	}
	if !ValidMetricName(sel.Metric) {
		return nil, errors.New("promapi: raw samples require an exact metric")
	}
	for _, matcher := range sel.Matchers {
		if !ValidLabelName(matcher.Name) || matcher.Name == "__name__" || matcher.Op != "=" {
			return nil, errors.New("promapi: raw samples require exact label matchers")
		}
	}
	duration := through.Sub(after)
	if u == nil || maxBytes <= 0 || maxBytes == math.MaxInt64 || after.IsZero() || duration <= 0 ||
		!through.Add(-duration).Equal(after) || after.Nanosecond()%int(time.Millisecond) != 0 || through.Nanosecond()%int(time.Millisecond) != 0 {
		return nil, errors.New("promapi: invalid raw-sample admission")
	}
	query := url.Values{
		"query": {fmt.Sprintf("%s[%dms]", sel.String(), duration.Milliseconds())},
		"time":  {through.UTC().Format(time.RFC3339Nano)},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.base+"/api/v1/query", strings.NewReader(query.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := u.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("promapi: raw samples: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("promapi: raw sample upstream status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > maxBytes {
		return nil, errors.New("promapi: raw sample response exceeds admission")
	}
	return readRawSampleMatrix(ctx, body, sel, after.UnixMilli(), through.UnixMilli())
}

type rawMatrixSeries struct {
	Labels     map[string]string `json:"metric"`
	Points     []rawMatrixPoint  `json:"values"`
	Histograms []json.RawMessage `json:"histograms"`
}

func readRawSampleMatrix(ctx context.Context, body []byte, sel Selector, after, through int64) ([]ResultSeries, error) {
	var wire struct {
		Status   string            `json:"status"`
		Warnings []json.RawMessage `json:"warnings"`
		Data     struct {
			Type   string            `json:"resultType"`
			Series []rawMatrixSeries `json:"result"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &wire); err != nil || wire.Status != "success" || wire.Data.Type != "matrix" ||
		wire.Data.Series == nil || len(wire.Warnings) != 0 {
		return nil, errors.New("promapi: expected a complete raw sample matrix")
	}
	series := make([]ResultSeries, 0, len(wire.Data.Series))
	seen := make(map[string]bool, len(wire.Data.Series))
	for _, row := range wire.Data.Series {
		metric := row.Labels["__name__"]
		if !sel.Matches(metric, row.Labels) || len(row.Histograms) != 0 {
			return nil, errors.New("promapi: unexpected series in raw sample matrix")
		}
		delete(row.Labels, "__name__")
		key := tsdb.SeriesIdentity(metric, row.Labels)
		if seen[key] {
			return nil, errors.New("promapi: duplicate series in raw sample matrix")
		}
		seen[key] = true
		points := make([]Point, 0, len(row.Points))
		previous := after
		for i, point := range row.Points {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			// Older Prometheus versions include the left boundary. The local
			// history contract excludes that one endpoint in both backends.
			if i == 0 && point.TimeMillis == after {
				continue
			}
			if point.TimeMillis <= previous || point.TimeMillis > through {
				return nil, errors.New("promapi: unordered or out-of-window raw sample")
			}
			previous = point.TimeMillis
			points = append(points, Point(point))
		}
		series = append(series, ResultSeries{Metric: metric, Labels: row.Labels, Points: points})
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return series, nil
}

type rawMatrixPoint Point

func (p *rawMatrixPoint) UnmarshalJSON(raw []byte) error {
	var fields []json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil || len(fields) != 2 {
		return errors.New("promapi: malformed raw sample")
	}
	millis, err := strconv.ParseFloat(string(fields[0]), 64)
	if err != nil || math.Abs(millis) >= (1<<53)/1000 || math.IsNaN(millis) {
		return errors.New("promapi: raw sample timestamp is invalid")
	}
	var value string
	if err := json.Unmarshal(fields[1], &value); err != nil {
		return errors.New("promapi: raw sample value is invalid")
	}
	number, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return errors.New("promapi: raw sample value is invalid")
	}
	p.TimeMillis, p.Value = int64(math.Round(millis*1000)), number
	return nil
}
