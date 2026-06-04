package promapi

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
)

// Prometheus HTTP-API envelopes (the wire shapes Grafana's Prometheus
// datasource consumes). Timestamps on this surface are float seconds.

type apiEnvelope struct {
	Status    string `json:"status"`
	Data      any    `json:"data,omitempty"`
	ErrorType string `json:"errorType,omitempty"`
	Error     string `json:"error,omitempty"`
}

func writeEnvelope(w http.ResponseWriter, status int, env apiEnvelope) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(env)
}

// WriteSuccess writes a Prometheus-API success envelope around data.
func WriteSuccess(w http.ResponseWriter, data any) {
	writeEnvelope(w, http.StatusOK, apiEnvelope{Status: "success", Data: data})
}

// WriteError writes a Prometheus-API error envelope (Grafana surfaces .error).
func WriteError(w http.ResponseWriter, status int, errType, msg string) {
	writeEnvelope(w, status, apiEnvelope{Status: "error", ErrorType: errType, Error: msg})
}

// sampleValue renders a value the way the Prometheus API does: [seconds, "v"].
func sampleValue(p Point) [2]any {
	return [2]any{float64(p.TimeMillis) / 1000.0, strconv.FormatFloat(p.Value, 'f', -1, 64)}
}

// metricObject is the series identity object: __name__ + labels.
func metricObject(rs ResultSeries) map[string]string {
	m := make(map[string]string, len(rs.Labels)+1)
	for k, v := range rs.Labels {
		m[k] = v
	}
	if rs.Metric != "" {
		m["__name__"] = rs.Metric
	}
	return m
}

// VectorData renders an instant-query result (resultType "vector").
func VectorData(series []ResultSeries) any {
	result := make([]map[string]any, 0, len(series))
	for _, rs := range series {
		if len(rs.Points) == 0 {
			continue
		}
		result = append(result, map[string]any{
			"metric": metricObject(rs),
			"value":  sampleValue(rs.Points[len(rs.Points)-1]),
		})
	}
	return map[string]any{"resultType": "vector", "result": result}
}

// MatrixData renders a range-query result (resultType "matrix").
func MatrixData(series []ResultSeries) any {
	result := make([]map[string]any, 0, len(series))
	for _, rs := range series {
		values := make([][2]any, 0, len(rs.Points))
		for _, p := range rs.Points {
			values = append(values, sampleValue(p))
		}
		result = append(result, map[string]any{
			"metric": metricObject(rs),
			"values": values,
		})
	}
	return map[string]any{"resultType": "matrix", "result": result}
}

// ScalarData renders a scalar result (Grafana's "1+1" datasource health probe).
func ScalarData(atSeconds float64, v float64) any {
	return map[string]any{"resultType": "scalar",
		"result": [2]any{atSeconds, strconv.FormatFloat(v, 'f', -1, 64)}}
}

// SeriesData renders /api/v1/series (a list of identity objects).
func SeriesData(series []ResultSeries) any {
	out := make([]map[string]string, 0, len(series))
	for _, rs := range series {
		out = append(out, metricObject(rs))
	}
	return out
}

// BuildInfoData advertises a Prometheus-compatible API version so Grafana
// enables its standard Prometheus query editor against probectl.
func BuildInfoData(probectlVersion string) any {
	return map[string]string{
		"version":   "2.47.0", // API-compatibility level, not a Prometheus build
		"revision":  "probectl-" + probectlVersion,
		"branch":    "",
		"buildUser": "",
		"buildDate": "",
		"goVersion": "",
	}
}

// WriteFederation writes series in the Prometheus text exposition format (the
// /federate contract): one `metric{labels} value timestamp_ms` line per sample,
// stable ordering. Lines carry every sample point present in the series.
func WriteFederation(w io.Writer, series []ResultSeries) error {
	sorted := make([]ResultSeries, len(series))
	copy(sorted, series)
	sort.Slice(sorted, func(i, j int) bool {
		return seriesKey(sorted[i].Metric, sorted[i].Labels) < seriesKey(sorted[j].Metric, sorted[j].Labels)
	})
	for _, rs := range sorted {
		ident := expositionIdent(rs)
		for _, p := range rs.Points {
			if _, err := fmt.Fprintf(w, "%s %s %d\n", ident,
				strconv.FormatFloat(p.Value, 'f', -1, 64), p.TimeMillis); err != nil {
				return err
			}
		}
	}
	return nil
}

// FederationContentType is the exposition content type served by /federate.
const FederationContentType = "text/plain; version=0.0.4; charset=utf-8"

func expositionIdent(rs ResultSeries) string {
	keys := make([]string, 0, len(rs.Labels))
	for k := range rs.Labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := rs.Metric
	if len(keys) > 0 {
		out += "{"
		for i, k := range keys {
			if i > 0 {
				out += ","
			}
			out += k + "=" + quoteValue(rs.Labels[k])
		}
		out += "}"
	}
	return out
}
