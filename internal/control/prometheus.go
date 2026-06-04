package control

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/promapi"
	"github.com/imfeelingtheagi/probectl/internal/store/tsdb"
	"github.com/imfeelingtheagi/probectl/internal/version"
)

// Prometheus-compatible surfaces (S40, F30): the Grafana datasource API
// (/v1/grafana/api/v1/*), the federation endpoint (/v1/prometheus/federate),
// and the remote-write receiver (/v1/prometheus/write).
//
// Tenant boundary: every query is parsed into a strict selector and
// tenant-forced (promapi.ForceTenant) BEFORE evaluation — locally over the
// in-memory store, or forwarded upstream as the canonical reconstruction
// (never raw caller input). Remote-write overwrites any tenant_id label with
// the authenticated caller's tenant. RBAC: reads require metrics.read, writes
// metrics.write — enforced by the route table like every /v1 route, after the
// tenant boundary (CLAUDE.md §7 guardrails 1, 5).

// maxRemoteWriteBody caps the compressed remote-write request body.
const maxRemoteWriteBody = 8 << 20 // 8 MiB

// promSnapshotter is the local query side (tsdb.Memory in lightweight mode).
type promSnapshotter interface{ Snapshot() []tsdb.Series }

// WithTSDB attaches the metrics writer backing the Prometheus-compatible
// surfaces. In memory mode queries evaluate locally; in prometheus mode the
// canonical selectors are forwarded to the backing TSDB. Returns s for chaining.
func (s *Server) WithTSDB(w tsdb.Writer) *Server {
	if w != nil {
		s.tsdbWriter = w
		if s.cfg.TSDBMode == "prometheus" && s.cfg.TSDBURL != "" {
			s.promUpstream = promapi.NewUpstream(s.cfg.TSDBURL)
		}
	}
	return s
}

// promReady reports whether a metrics backend is attached; when not, handlers
// answer with a Prometheus-shaped 503 (fail closed, Grafana shows the message).
func (s *Server) promReady(w http.ResponseWriter) bool {
	if s.tsdbWriter == nil {
		promapi.WriteError(w, http.StatusServiceUnavailable, "unavailable",
			"metrics store not configured (control plane started without a TSDB)")
		return false
	}
	return true
}

// promParseTime parses a Prometheus API timestamp (float seconds or RFC 3339).
func promParseTime(v string, def time.Time) (time.Time, error) {
	if v == "" {
		return def, nil
	}
	if f, err := strconv.ParseFloat(v, 64); err == nil {
		return time.UnixMilli(int64(f * 1000)), nil
	}
	if t, err := time.Parse(time.RFC3339, v); err == nil {
		return t, nil
	}
	return time.Time{}, fmt.Errorf("invalid timestamp %q", v)
}

// promSelectors parses + tenant-forces every match[] parameter.
func promSelectors(r *http.Request, tenant string) ([]promapi.Selector, error) {
	if err := r.ParseForm(); err != nil {
		return nil, fmt.Errorf("invalid form: %v", err)
	}
	matches := r.Form["match[]"]
	if len(matches) == 0 {
		// An unscoped discovery query: everything in the caller's tenant.
		return []promapi.Selector{promapi.ForceTenant(promapi.Selector{}, tenant)}, nil
	}
	sels := make([]promapi.Selector, 0, len(matches))
	for _, m := range matches {
		sel, err := promapi.ParseSelector(m)
		if err != nil {
			return nil, err
		}
		sels = append(sels, promapi.ForceTenant(sel, tenant))
	}
	return sels, nil
}

// handlePromQuery serves GET+POST /v1/grafana/api/v1/query (instant queries).
func (s *Server) handlePromQuery(w http.ResponseWriter, r *http.Request) error {
	tid, err := s.principalTenant(r)
	if err != nil {
		return err
	}
	if !s.promReady(w) {
		return nil
	}
	expr := r.FormValue("query")
	// Grafana's datasource health check sends the constant expression "1+1".
	if strings.ReplaceAll(expr, " ", "") == "1+1" {
		promapi.WriteSuccess(w, promapi.ScalarData(float64(time.Now().UnixMilli())/1000.0, 2))
		return nil
	}
	sel, perr := promapi.ParseSelector(expr)
	if perr != nil {
		promapi.WriteError(w, http.StatusBadRequest, "bad_data", perr.Error())
		return nil
	}
	forced := promapi.ForceTenant(sel, tid)
	at, terr := promParseTime(r.FormValue("time"), time.Now())
	if terr != nil {
		promapi.WriteError(w, http.StatusBadRequest, "bad_data", terr.Error())
		return nil
	}
	if snap, ok := s.tsdbWriter.(promSnapshotter); ok {
		res, qerr := promapi.Instant(snap.Snapshot(), forced, at, 0, 0)
		if qerr != nil {
			promapi.WriteError(w, http.StatusUnprocessableEntity, "execution", qerr.Error())
			return nil
		}
		promapi.WriteSuccess(w, promapi.VectorData(res))
		return nil
	}
	return s.promForward(w, r, func() (promapi.Result, error) {
		return s.promUpstream.QueryInstant(r.Context(), forced, at)
	})
}

// handlePromQueryRange serves GET+POST /v1/grafana/api/v1/query_range.
func (s *Server) handlePromQueryRange(w http.ResponseWriter, r *http.Request) error {
	tid, err := s.principalTenant(r)
	if err != nil {
		return err
	}
	if !s.promReady(w) {
		return nil
	}
	sel, perr := promapi.ParseSelector(r.FormValue("query"))
	if perr != nil {
		promapi.WriteError(w, http.StatusBadRequest, "bad_data", perr.Error())
		return nil
	}
	forced := promapi.ForceTenant(sel, tid)
	now := time.Now()
	start, e1 := promParseTime(r.FormValue("start"), now.Add(-time.Hour))
	end, e2 := promParseTime(r.FormValue("end"), now)
	if e1 != nil || e2 != nil || end.Before(start) {
		promapi.WriteError(w, http.StatusBadRequest, "bad_data", "invalid start/end")
		return nil
	}
	if snap, ok := s.tsdbWriter.(promSnapshotter); ok {
		res, qerr := promapi.Range(snap.Snapshot(), forced, start, end, 0)
		if qerr != nil {
			promapi.WriteError(w, http.StatusUnprocessableEntity, "execution", qerr.Error())
			return nil
		}
		promapi.WriteSuccess(w, promapi.MatrixData(res))
		return nil
	}
	return s.promForward(w, r, func() (promapi.Result, error) {
		return s.promUpstream.QueryRange(r.Context(), forced, start, end, r.FormValue("step"))
	})
}

// handlePromSeries serves GET+POST /v1/grafana/api/v1/series.
func (s *Server) handlePromSeries(w http.ResponseWriter, r *http.Request) error {
	tid, err := s.principalTenant(r)
	if err != nil {
		return err
	}
	if !s.promReady(w) {
		return nil
	}
	sels, perr := promSelectors(r, tid)
	if perr != nil {
		promapi.WriteError(w, http.StatusBadRequest, "bad_data", perr.Error())
		return nil
	}
	start, end, terr := promWindow(r)
	if terr != nil {
		promapi.WriteError(w, http.StatusBadRequest, "bad_data", terr.Error())
		return nil
	}
	if snap, ok := s.tsdbWriter.(promSnapshotter); ok {
		res, qerr := promapi.Series(snap.Snapshot(), sels, start, end, 0)
		if qerr != nil {
			promapi.WriteError(w, http.StatusUnprocessableEntity, "execution", qerr.Error())
			return nil
		}
		promapi.WriteSuccess(w, promapi.SeriesData(res))
		return nil
	}
	return s.promForward(w, r, func() (promapi.Result, error) {
		return s.promUpstream.Series(r.Context(), sels, start, end)
	})
}

// handlePromLabels serves GET+POST /v1/grafana/api/v1/labels.
func (s *Server) handlePromLabels(w http.ResponseWriter, r *http.Request) error {
	tid, err := s.principalTenant(r)
	if err != nil {
		return err
	}
	if !s.promReady(w) {
		return nil
	}
	sels, perr := promSelectors(r, tid)
	if perr != nil {
		promapi.WriteError(w, http.StatusBadRequest, "bad_data", perr.Error())
		return nil
	}
	start, end, terr := promWindow(r)
	if terr != nil {
		promapi.WriteError(w, http.StatusBadRequest, "bad_data", terr.Error())
		return nil
	}
	if snap, ok := s.tsdbWriter.(promSnapshotter); ok {
		names, qerr := promapi.LabelNames(snap.Snapshot(), sels, start, end, 0)
		if qerr != nil {
			promapi.WriteError(w, http.StatusUnprocessableEntity, "execution", qerr.Error())
			return nil
		}
		promapi.WriteSuccess(w, names)
		return nil
	}
	return s.promForward(w, r, func() (promapi.Result, error) {
		return s.promUpstream.LabelNames(r.Context(), sels, start, end)
	})
}

// handlePromLabelValues serves GET /v1/grafana/api/v1/label/{name}/values.
func (s *Server) handlePromLabelValues(w http.ResponseWriter, r *http.Request) error {
	tid, err := s.principalTenant(r)
	if err != nil {
		return err
	}
	if !s.promReady(w) {
		return nil
	}
	name := r.PathValue("name")
	// The tenant label's only visible value is the caller's own tenant.
	if name == promapi.TenantLabel {
		promapi.WriteSuccess(w, []string{tid})
		return nil
	}
	sels, perr := promSelectors(r, tid)
	if perr != nil {
		promapi.WriteError(w, http.StatusBadRequest, "bad_data", perr.Error())
		return nil
	}
	start, end, terr := promWindow(r)
	if terr != nil {
		promapi.WriteError(w, http.StatusBadRequest, "bad_data", terr.Error())
		return nil
	}
	if snap, ok := s.tsdbWriter.(promSnapshotter); ok {
		vals, qerr := promapi.LabelValues(snap.Snapshot(), name, sels, start, end, 0)
		if qerr != nil {
			promapi.WriteError(w, http.StatusUnprocessableEntity, "execution", qerr.Error())
			return nil
		}
		promapi.WriteSuccess(w, vals)
		return nil
	}
	return s.promForward(w, r, func() (promapi.Result, error) {
		return s.promUpstream.LabelValues(r.Context(), name, sels, start, end)
	})
}

// handlePromBuildInfo serves GET /v1/grafana/api/v1/status/buildinfo (Grafana
// probes it to pick a query-editor feature level).
func (s *Server) handlePromBuildInfo(w http.ResponseWriter, r *http.Request) error {
	if _, err := s.principalTenant(r); err != nil {
		return err
	}
	promapi.WriteSuccess(w, promapi.BuildInfoData(version.Get().String()))
	return nil
}

// handlePromMetadata serves GET /v1/grafana/api/v1/metadata (Grafana asks for
// metric metadata; probectl serves none yet — an empty success keeps it happy).
func (s *Server) handlePromMetadata(w http.ResponseWriter, r *http.Request) error {
	if _, err := s.principalTenant(r); err != nil {
		return err
	}
	promapi.WriteSuccess(w, map[string]any{})
	return nil
}

// handlePromFederate serves GET /v1/prometheus/federate — the federation
// scrape: the latest sample of every series matching match[], in the text
// exposition format, tenant-scoped.
func (s *Server) handlePromFederate(w http.ResponseWriter, r *http.Request) error {
	tid, err := s.principalTenant(r)
	if err != nil {
		return err
	}
	if !s.promReady(w) {
		return nil
	}
	sels, perr := promSelectors(r, tid)
	if perr != nil {
		promapi.WriteError(w, http.StatusBadRequest, "bad_data", perr.Error())
		return nil
	}
	now := time.Now()
	var out []promapi.ResultSeries
	if snap, ok := s.tsdbWriter.(promSnapshotter); ok {
		snapshot := snap.Snapshot()
		seen := map[string]bool{}
		for _, sel := range sels {
			res, qerr := promapi.Instant(snapshot, sel, now, 0, 0)
			if qerr != nil {
				promapi.WriteError(w, http.StatusUnprocessableEntity, "execution", qerr.Error())
				return nil
			}
			for _, rs := range res {
				k := rs.Metric + "\x00" + fmt.Sprint(rs.Labels)
				if !seen[k] {
					seen[k] = true
					out = append(out, rs)
				}
			}
		}
	} else if s.promUpstream != nil {
		for _, sel := range sels {
			res, ferr := s.promUpstream.QueryInstant(r.Context(), sel, now)
			if ferr != nil {
				promapi.WriteError(w, http.StatusBadGateway, "upstream", ferr.Error())
				return nil
			}
			series, derr := decodeUpstreamVector(res.Body)
			if derr != nil {
				promapi.WriteError(w, http.StatusBadGateway, "upstream", derr.Error())
				return nil
			}
			out = append(out, series...)
		}
	} else {
		promapi.WriteError(w, http.StatusServiceUnavailable, "unavailable", "no local metrics store and no upstream TSDB")
		return nil
	}
	w.Header().Set("Content-Type", promapi.FederationContentType)
	w.WriteHeader(http.StatusOK)
	return promapi.WriteFederation(w, out)
}

// handlePromWrite serves POST /v1/prometheus/write — the remote-write ingest.
// The payload is untrusted: size-, series-, sample-, and label-capped, and the
// tenant label is forced to the authenticated caller's tenant.
func (s *Server) handlePromWrite(w http.ResponseWriter, r *http.Request) error {
	tid, err := s.principalTenant(r)
	if err != nil {
		return err
	}
	if !s.promReady(w) {
		return nil
	}
	body, rerr := io.ReadAll(http.MaxBytesReader(w, r.Body, maxRemoteWriteBody))
	if rerr != nil {
		promapi.WriteError(w, http.StatusRequestEntityTooLarge, "bad_data",
			fmt.Sprintf("body exceeds %d bytes or is unreadable", maxRemoteWriteBody))
		return nil
	}
	series, derr := promapi.DecodeRemoteWrite(body, tid, promapi.WriteLimits{})
	if derr != nil {
		promapi.WriteError(w, http.StatusBadRequest, "bad_data", derr.Error())
		return nil
	}
	if err := s.tsdbWriter.Write(r.Context(), series); err != nil {
		promapi.WriteError(w, http.StatusInternalServerError, "internal", "tsdb write failed")
		s.log.Error("remote-write persist failed", "error", err, "tenant_id", tid)
		return nil
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

// promForward proxies one upstream call, passing the (already canonical,
// tenant-forced) response straight through.
func (s *Server) promForward(w http.ResponseWriter, _ *http.Request, call func() (promapi.Result, error)) error {
	if s.promUpstream == nil {
		promapi.WriteError(w, http.StatusServiceUnavailable, "unavailable",
			"metrics queries need the in-memory TSDB or PROBECTL_TSDB_MODE=prometheus with PROBECTL_TSDB_URL")
		return nil
	}
	res, err := call()
	if err != nil {
		promapi.WriteError(w, http.StatusBadGateway, "upstream", err.Error())
		return nil
	}
	w.Header().Set("Content-Type", res.ContentType)
	w.WriteHeader(res.Status)
	_, _ = w.Write(res.Body)
	return nil
}

// promWindow reads optional start/end bounds (defaults: last hour).
func promWindow(r *http.Request) (time.Time, time.Time, error) {
	now := time.Now()
	start, err := promParseTime(r.FormValue("start"), now.Add(-time.Hour))
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	end, err := promParseTime(r.FormValue("end"), now)
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	return start, end, nil
}

// decodeUpstreamVector decodes a Prometheus instant-query JSON response into
// result series (for federation text rendering in upstream mode).
func decodeUpstreamVector(body []byte) ([]promapi.ResultSeries, error) {
	var resp struct {
		Status string `json:"status"`
		Data   struct {
			ResultType string `json:"resultType"`
			Result     []struct {
				Metric map[string]string `json:"metric"`
				Value  []json.RawMessage `json:"value"` // [seconds(float), "value"(string)]
			} `json:"result"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("upstream response: %v", err)
	}
	if resp.Status != "success" || resp.Data.ResultType != "vector" {
		return nil, fmt.Errorf("upstream returned %s/%s", resp.Status, resp.Data.ResultType)
	}
	out := make([]promapi.ResultSeries, 0, len(resp.Data.Result))
	for _, item := range resp.Data.Result {
		if len(item.Value) != 2 {
			continue
		}
		var secs float64
		var valStr string
		if json.Unmarshal(item.Value[0], &secs) != nil || json.Unmarshal(item.Value[1], &valStr) != nil {
			continue
		}
		val, _ := strconv.ParseFloat(valStr, 64)
		rs := promapi.ResultSeries{
			Metric: item.Metric["__name__"],
			Labels: map[string]string{},
			Points: []promapi.Point{{TimeMillis: int64(secs * 1000), Value: val}},
		}
		for k, v := range item.Metric {
			if k != "__name__" {
				rs.Labels[k] = v
			}
		}
		out = append(out, rs)
	}
	return out, nil
}
