// SPDX-License-Identifier: LicenseRef-probectl-TBD

package control

import (
	"net/http"
	"strconv"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/apierror"
	"github.com/imfeelingtheagi/probectl/internal/store/flowstore"
)

// Flow analytics (S38, F17): tenant-scoped reads over the flow store. The
// tenant comes from the authenticated principal — never from a query param —
// and the store scopes every query by it before anything else (CLAUDE.md §6).

// handleFlowTop serves GET /v1/flows/top — the top-talkers view.
// Query: by=src|dst|pair|src_asn|dst_asn, window=1h, limit=10.
func (s *Server) handleFlowTop(w http.ResponseWriter, r *http.Request) error {
	tid, err := s.principalTenant(r)
	if err != nil {
		return err
	}
	window, err := windowParam(r, "window", time.Hour)
	if err != nil {
		return err
	}
	limit, err := intParam(r, "limit", 10)
	if err != nil {
		return err
	}
	q := flowstore.TopQuery{
		TenantID: tid,
		By:       r.URL.Query().Get("by"),
		Window:   window,
		Limit:    limit,
	}
	rows, err := s.flowStore.TopTalkers(r.Context(), q)
	if err != nil {
		return apierror.BadRequest(err.Error())
	}
	// CORRECT-016: echo the EFFECTIVE limit the store applied (it clamps to
	// <=1000), so a caller that asked for more knows its request was bounded
	// rather than silently assuming it got everything.
	effLimit := limit
	if effLimit <= 0 {
		effLimit = 10
	}
	if effLimit > 1000 {
		effLimit = 1000
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"items":           rows,
		"effective_limit": effLimit,
		"window":          window.String(),
	})
	return nil
}

// handleFlowCapacity serves GET /v1/flows/capacity — per-exporter/interface
// throughput buckets. Query: exporter=, direction=in|out, window=1h, bucket=3m.
func (s *Server) handleFlowCapacity(w http.ResponseWriter, r *http.Request) error {
	tid, err := s.principalTenant(r)
	if err != nil {
		return err
	}
	window, err := windowParam(r, "window", time.Hour)
	if err != nil {
		return err
	}
	bucket, err := windowParam(r, "bucket", 0)
	if err != nil {
		return err
	}
	points, err := s.flowStore.Capacity(r.Context(), flowstore.CapacityQuery{
		TenantID:  tid,
		Exporter:  r.URL.Query().Get("exporter"),
		Direction: r.URL.Query().Get("direction"),
		Window:    window,
		Bucket:    bucket,
	})
	if err != nil {
		return apierror.BadRequest(err.Error())
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": points})
	return nil
}

// handleFlowAnomalies serves GET /v1/flows/anomalies — interfaces whose latest
// bucket departs from their own baseline. Query: window=1h, bucket=, k=3,
// min_bps=1000, exporter=, direction=.
func (s *Server) handleFlowAnomalies(w http.ResponseWriter, r *http.Request) error {
	tid, err := s.principalTenant(r)
	if err != nil {
		return err
	}
	window, err := windowParam(r, "window", time.Hour)
	if err != nil {
		return err
	}
	bucket, err := windowParam(r, "bucket", 0)
	if err != nil {
		return err
	}
	k, err := floatParam(r, "k", 0)
	if err != nil {
		return err
	}
	minBps, err := floatParam(r, "min_bps", 0)
	if err != nil {
		return err
	}
	anomalies, err := s.flowStore.Anomalies(r.Context(), flowstore.AnomalyQuery{
		TenantID:    tid,
		Exporter:    r.URL.Query().Get("exporter"),
		Direction:   r.URL.Query().Get("direction"),
		Window:      window,
		Bucket:      bucket,
		Sensitivity: k,
		MinBps:      minBps,
	})
	if err != nil {
		return apierror.BadRequest(err.Error())
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": anomalies})
	return nil
}

// windowParam parses a duration query parameter (default when absent).
func windowParam(r *http.Request, name string, def time.Duration) (time.Duration, error) {
	v := r.URL.Query().Get(name)
	if v == "" {
		return def, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		return 0, apierror.BadRequest("invalid " + name + ": want a positive Go duration like 30m")
	}
	return d, nil
}

// intParam parses a positive integer query parameter.
func intParam(r *http.Request, name string, def int) (int, error) {
	v := r.URL.Query().Get(name)
	if v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return 0, apierror.BadRequest("invalid " + name + ": want a positive integer")
	}
	return n, nil
}

// floatParam parses a positive float query parameter.
func floatParam(r *http.Request, name string, def float64) (float64, error) {
	v := r.URL.Query().Get(name)
	if v == "" {
		return def, nil
	}
	f, err := strconv.ParseFloat(v, 64)
	if err != nil || f < 0 {
		return 0, apierror.BadRequest("invalid " + name + ": want a non-negative number")
	}
	return f, nil
}
