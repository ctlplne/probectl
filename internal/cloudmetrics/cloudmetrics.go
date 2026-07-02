// SPDX-License-Identifier: LicenseRef-probectl-TBD

// Package cloudmetrics imports already-exported AWS CloudWatch, Azure Monitor,
// and Google Cloud Monitoring metric rows into probectl's tenant-scoped TSDB.
// It intentionally does not fetch cloud APIs; operators provide local JSONL
// exports from their own pipeline, preserving the no-phone-home guardrail.
package cloudmetrics

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/klauspost/compress/snappy"
	"google.golang.org/protobuf/proto"

	prompb "github.com/imfeelingtheagi/probectl/internal/gen/prometheus/v1"
	"github.com/imfeelingtheagi/probectl/internal/store/tsdb"
)

type Provider string

const (
	ProviderAWSCloudWatch    Provider = "aws_cloudwatch_export"
	ProviderAzureMonitor     Provider = "azure_monitor_export"
	ProviderGCPCloudMonitor  Provider = "gcp_cloud_monitoring_export"
	defaultCloudMetricPrefix          = "probectl_cloud_"
)

var (
	ErrNoTenant        = errors.New("cloudmetrics: tenant_id is required")
	ErrNoWriter        = errors.New("cloudmetrics: TSDB writer is required")
	ErrUnknownProvider = errors.New("cloudmetrics: unknown provider")
)

// Load reads newline-delimited exported cloud metric rows and writes normalized
// series to writer. Blank lines and '#' comments are ignored.
func Load(ctx context.Context, provider Provider, tenantID string, r io.Reader, writer tsdb.Writer) (int, error) {
	if writer == nil {
		return 0, ErrNoWriter
	}
	return scan(ctx, provider, tenantID, r, writer.Write)
}

// Parse reads newline-delimited exported cloud metric rows and returns
// normalized series without writing them.
func Parse(ctx context.Context, provider Provider, tenantID string, r io.Reader) ([]tsdb.Series, error) {
	var out []tsdb.Series
	_, err := scan(ctx, provider, tenantID, r, func(_ context.Context, series []tsdb.Series) error {
		out = append(out, series...)
		return nil
	})
	return out, err
}

// EncodeRemoteWrite builds a snappy-compressed Prometheus remote-write request
// for POST /v1/prometheus/write.
func EncodeRemoteWrite(series []tsdb.Series) ([]byte, error) {
	req := &prompb.WriteRequest{Timeseries: make([]*prompb.TimeSeries, 0, len(series))}
	for _, s := range series {
		labels := make([]*prompb.Label, 0, len(s.Labels)+1)
		labels = append(labels, &prompb.Label{Name: "__name__", Value: s.Metric})
		keys := make([]string, 0, len(s.Labels))
		for k := range s.Labels {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			labels = append(labels, &prompb.Label{Name: k, Value: s.Labels[k]})
		}
		req.Timeseries = append(req.Timeseries, &prompb.TimeSeries{
			Labels:  labels,
			Samples: []*prompb.Sample{{Value: s.Value, Timestamp: s.TimeMillis}},
		})
	}
	raw, err := proto.Marshal(req)
	if err != nil {
		return nil, err
	}
	return snappy.Encode(nil, raw), nil
}

type writeFunc func(context.Context, []tsdb.Series) error

func scan(ctx context.Context, provider Provider, tenantID string, r io.Reader, sink writeFunc) (int, error) {
	if strings.TrimSpace(tenantID) == "" {
		return 0, ErrNoTenant
	}
	if !validProvider(provider) {
		return 0, fmt.Errorf("%w %q", ErrUnknownProvider, provider)
	}
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 2*1024*1024)
	count := 0
	pending := make([]tsdb.Series, 0, 512)
	flush := func() error {
		if len(pending) == 0 {
			return nil
		}
		if err := sink(ctx, pending); err != nil {
			return err
		}
		count += len(pending)
		pending = pending[:0]
		return nil
	}
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		series, err := decodeLine(provider, tenantID, []byte(line))
		if err != nil {
			return count, fmt.Errorf("cloudmetrics: %s line %d: %w", provider, lineNo, err)
		}
		pending = append(pending, series...)
		if len(pending) >= 1000 {
			if err := flush(); err != nil {
				return count, err
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return count, fmt.Errorf("cloudmetrics: read %s: %w", provider, err)
	}
	return count, flush()
}

func validProvider(p Provider) bool {
	switch p {
	case ProviderAWSCloudWatch, ProviderAzureMonitor, ProviderGCPCloudMonitor:
		return true
	default:
		return false
	}
}

func decodeLine(provider Provider, tenantID string, raw []byte) ([]tsdb.Series, error) {
	switch provider {
	case ProviderAWSCloudWatch:
		return decodeAWS(tenantID, raw)
	case ProviderAzureMonitor:
		return decodeAzure(tenantID, raw)
	case ProviderGCPCloudMonitor:
		return decodeGCP(tenantID, raw)
	default:
		return nil, fmt.Errorf("%w %q", ErrUnknownProvider, provider)
	}
}

type cloudPoint struct {
	Metric     string
	Source     string
	Value      float64
	At         time.Time
	Provider   string
	Namespace  string
	Unit       string
	ResourceID string
	Labels     map[string]string
}

func (p cloudPoint) series(tenantID string) (tsdb.Series, error) {
	if p.Metric == "" {
		return tsdb.Series{}, errors.New("metric name is required")
	}
	if math.IsNaN(p.Value) || math.IsInf(p.Value, 0) {
		return tsdb.Series{}, errors.New("metric value must be finite")
	}
	if p.At.IsZero() {
		return tsdb.Series{}, errors.New("timestamp is required")
	}
	labels := map[string]string{
		tsdb.TenantLabel:  tenantID,
		"cloud_provider":  p.Provider,
		"source_metric":   p.Source,
		"cloud_namespace": p.Namespace,
	}
	if p.Unit != "" {
		labels["cloud_unit"] = p.Unit
	}
	if p.ResourceID != "" {
		labels["cloud_resource_id"] = p.ResourceID
	}
	for k, v := range p.Labels {
		k = labelName(k)
		if k == "" || k == tsdb.TenantLabel || strings.TrimSpace(v) == "" {
			continue
		}
		labels[k] = strings.TrimSpace(v)
	}
	return tsdb.Series{
		Metric:     defaultCloudMetricPrefix + p.Provider + "_" + labelName(p.Metric),
		Labels:     labels,
		Value:      p.Value,
		TimeMillis: p.At.UnixMilli(),
	}, nil
}

func decodeAWS(tenantID string, raw []byte) ([]tsdb.Series, error) {
	var row struct {
		Namespace  string            `json:"namespace"`
		MetricName string            `json:"metric_name"`
		Metric     string            `json:"metric"`
		Dimensions json.RawMessage   `json:"dimensions"`
		Timestamp  string            `json:"timestamp"`
		Value      json.RawMessage   `json:"value"`
		Unit       string            `json:"unit"`
		AccountID  string            `json:"account_id"`
		Region     string            `json:"region"`
		ResourceID string            `json:"resource_id"`
		Labels     map[string]string `json:"labels"`
	}
	if err := json.Unmarshal(raw, &row); err != nil {
		return nil, err
	}
	at, err := parseTime(row.Timestamp)
	if err != nil {
		return nil, err
	}
	value, err := parseValue(row.Value)
	if err != nil {
		return nil, err
	}
	labels := mergeLabels(row.Labels, parseDimensions(row.Dimensions, "aws_dimension_"))
	copyLabel(labels, "cloud_account_id", row.AccountID)
	copyLabel(labels, "cloud_region", row.Region)
	point := cloudPoint{
		Metric:     first(row.MetricName, row.Metric),
		Source:     first(row.Namespace, "AWS") + "/" + first(row.MetricName, row.Metric),
		Value:      value,
		At:         at,
		Provider:   "aws",
		Namespace:  row.Namespace,
		Unit:       row.Unit,
		ResourceID: row.ResourceID,
		Labels:     labels,
	}
	series, err := point.series(tenantID)
	if err != nil {
		return nil, err
	}
	return []tsdb.Series{series}, nil
}

func decodeAzure(tenantID string, raw []byte) ([]tsdb.Series, error) {
	var row struct {
		Namespace  string            `json:"namespace"`
		Name       string            `json:"name"`
		MetricName string            `json:"metric_name"`
		ResourceID string            `json:"resource_id"`
		TimeStamp  string            `json:"timeStamp"`
		Timestamp  string            `json:"timestamp"`
		Unit       string            `json:"unit"`
		Labels     map[string]string `json:"labels"`
		Average    *float64          `json:"average"`
		Total      *float64          `json:"total"`
		Maximum    *float64          `json:"maximum"`
		Minimum    *float64          `json:"minimum"`
		Count      *float64          `json:"count"`
		Value      *float64          `json:"value"`
	}
	if err := json.Unmarshal(raw, &row); err != nil {
		return nil, err
	}
	at, err := parseTime(first(row.TimeStamp, row.Timestamp))
	if err != nil {
		return nil, err
	}
	value, aggregation, err := azureValue(row.Average, row.Total, row.Maximum, row.Minimum, row.Count, row.Value)
	if err != nil {
		return nil, err
	}
	labels := mergeLabels(row.Labels, nil)
	copyLabel(labels, "aggregation", aggregation)
	metric := first(row.MetricName, row.Name)
	point := cloudPoint{
		Metric:     metric,
		Source:     first(row.Namespace, "Azure") + "/" + metric,
		Value:      value,
		At:         at,
		Provider:   "azure",
		Namespace:  row.Namespace,
		Unit:       row.Unit,
		ResourceID: row.ResourceID,
		Labels:     labels,
	}
	series, err := point.series(tenantID)
	if err != nil {
		return nil, err
	}
	return []tsdb.Series{series}, nil
}

func decodeGCP(tenantID string, raw []byte) ([]tsdb.Series, error) {
	var row struct {
		Metric struct {
			Type   string            `json:"type"`
			Labels map[string]string `json:"labels"`
		} `json:"metric"`
		Resource struct {
			Type   string            `json:"type"`
			Labels map[string]string `json:"labels"`
		} `json:"resource"`
		Unit   string `json:"unit"`
		Points []struct {
			Interval struct {
				EndTime string `json:"endTime"`
			} `json:"interval"`
			Value map[string]json.RawMessage `json:"value"`
		} `json:"points"`
	}
	if err := json.Unmarshal(raw, &row); err != nil {
		return nil, err
	}
	if row.Metric.Type == "" {
		return nil, errors.New("metric.type is required")
	}
	labels := map[string]string{"gcp_resource_type": row.Resource.Type}
	for k, v := range row.Metric.Labels {
		copyLabel(labels, "gcp_metric_"+k, v)
	}
	for k, v := range row.Resource.Labels {
		copyLabel(labels, "gcp_resource_"+k, v)
	}
	out := make([]tsdb.Series, 0, len(row.Points))
	for _, pt := range row.Points {
		at, err := parseTime(pt.Interval.EndTime)
		if err != nil {
			return nil, err
		}
		value, err := gcpValue(pt.Value)
		if err != nil {
			return nil, err
		}
		point := cloudPoint{
			Metric:    row.Metric.Type,
			Source:    row.Metric.Type,
			Value:     value,
			At:        at,
			Provider:  "gcp",
			Namespace: "cloud.google.com",
			Unit:      row.Unit,
			Labels:    labels,
		}
		series, err := point.series(tenantID)
		if err != nil {
			return nil, err
		}
		out = append(out, series)
	}
	return out, nil
}

func parseDimensions(raw json.RawMessage, prefix string) map[string]string {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	var m map[string]string
	if json.Unmarshal(raw, &m) == nil {
		out := map[string]string{}
		for k, v := range m {
			copyLabel(out, prefix+k, v)
		}
		return out
	}
	var arr []struct {
		Name  string `json:"Name"`
		Value string `json:"Value"`
	}
	if json.Unmarshal(raw, &arr) == nil {
		out := map[string]string{}
		for _, d := range arr {
			copyLabel(out, prefix+d.Name, d.Value)
		}
		return out
	}
	return nil
}

func parseTime(s string) (time.Time, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, errors.New("empty timestamp")
	}
	if n, err := strconv.ParseInt(s, 10, 64); err == nil {
		if n > 10_000_000_000 {
			return time.UnixMilli(n).UTC(), nil
		}
		return time.Unix(n, 0).UTC(), nil
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}, err
	}
	return t.UTC(), nil
}

func parseValue(raw json.RawMessage) (float64, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return 0, errors.New("value is required")
	}
	var f float64
	if err := json.Unmarshal(raw, &f); err == nil {
		return f, nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return strconv.ParseFloat(strings.TrimSpace(s), 64)
	}
	return 0, fmt.Errorf("parse value %s", string(raw))
}

func azureValue(vals ...*float64) (float64, string, error) {
	names := []string{"average", "total", "maximum", "minimum", "count", "value"}
	for i, v := range vals {
		if v != nil {
			return *v, names[i], nil
		}
	}
	return 0, "", errors.New("one Azure metric aggregation is required")
}

func gcpValue(values map[string]json.RawMessage) (float64, error) {
	for _, key := range []string{"doubleValue", "int64Value", "value"} {
		if raw, ok := values[key]; ok {
			return parseValue(raw)
		}
	}
	return 0, errors.New("GCP point value is required")
}

func mergeLabels(a, b map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range a {
		copyLabel(out, k, v)
	}
	for k, v := range b {
		copyLabel(out, k, v)
	}
	return out
}

func copyLabel(labels map[string]string, k, v string) {
	if strings.TrimSpace(k) == "" || strings.TrimSpace(v) == "" {
		return
	}
	labels[k] = strings.TrimSpace(v)
}

func first(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func labelName(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	var b strings.Builder
	lastUnderscore := false
	for _, r := range s {
		ok := r == '_' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9'
		if ok {
			if b.Len() == 0 && r >= '0' && r <= '9' {
				b.WriteByte('m')
				b.WriteByte('_')
			}
			b.WriteRune(r)
			lastUnderscore = false
			continue
		}
		if !lastUnderscore && b.Len() > 0 {
			b.WriteByte('_')
			lastUnderscore = true
		}
	}
	return strings.Trim(b.String(), "_")
}
