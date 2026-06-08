package control

import (
	"net/http"
	"strconv"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/apierror"
	"github.com/imfeelingtheagi/probectl/internal/auth"
	"github.com/imfeelingtheagi/probectl/internal/store/otelstore"
)

// The OTLP signal query surface (ARCH-001, Sprint 22): externally-ingested
// traces and logs are queryable the same way every other plane is — tenant
// first (the principal's tenant scopes the store query; never a client
// parameter), then RBAC (metrics.read, the unified telemetry read key).

// handleOTLPTraces serves GET /v1/otlp/traces.
func (s *Server) handleOTLPTraces(w http.ResponseWriter, r *http.Request) error {
	p := auth.PrincipalFrom(r.Context())
	if p == nil {
		return apierror.Unauthorized("authentication required")
	}
	limit, err := intParam(r, "limit", 0)
	if err != nil {
		return apierror.Validation("limit must be a non-negative integer")
	}
	q := otelstore.SpanQuery{
		TraceID: r.URL.Query().Get("trace_id"),
		Service: r.URL.Query().Get("service"),
		Limit:   limit,
	}
	if q.Since, q.Until, err = timeRange(r); err != nil {
		return apierror.Validation(err.Error())
	}
	spans, err := s.otelStore.QuerySpans(r.Context(), p.TenantID, q)
	if err != nil {
		s.log.Warn("otlp trace query failed", "error", err)
		return apierror.Unavailable("trace store unavailable")
	}
	writeJSON(w, http.StatusOK, map[string]any{"spans": spans})
	return nil
}

// handleOTLPLogs serves GET /v1/otlp/logs.
func (s *Server) handleOTLPLogs(w http.ResponseWriter, r *http.Request) error {
	p := auth.PrincipalFrom(r.Context())
	if p == nil {
		return apierror.Unauthorized("authentication required")
	}
	limit, err := intParam(r, "limit", 0)
	if err != nil {
		return apierror.Validation("limit must be a non-negative integer")
	}
	q := otelstore.LogQuery{
		Service: r.URL.Query().Get("service"),
		TraceID: r.URL.Query().Get("trace_id"),
		Limit:   limit,
	}
	if v := r.URL.Query().Get("min_severity"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 || n > 24 {
			return apierror.Validation("min_severity must be an OTel severity number (1-24)")
		}
		q.MinSeverity = int32(n)
	}
	if q.Since, q.Until, err = timeRange(r); err != nil {
		return apierror.Validation(err.Error())
	}
	recs, err := s.otelStore.QueryLogs(r.Context(), p.TenantID, q)
	if err != nil {
		s.log.Warn("otlp log query failed", "error", err)
		return apierror.Unavailable("log store unavailable")
	}
	writeJSON(w, http.StatusOK, map[string]any{"logs": recs})
	return nil
}

// timeRange parses optional since/until RFC3339 query params.
func timeRange(r *http.Request) (since, until time.Time, err error) {
	if v := r.URL.Query().Get("since"); v != "" {
		if since, err = time.Parse(time.RFC3339, v); err != nil {
			return time.Time{}, time.Time{}, errSinceUntil
		}
	}
	if v := r.URL.Query().Get("until"); v != "" {
		if until, err = time.Parse(time.RFC3339, v); err != nil {
			return time.Time{}, time.Time{}, errSinceUntil
		}
	}
	return since, until, nil
}

var errSinceUntil = errTime{}

type errTime struct{}

func (errTime) Error() string { return "since/until must be RFC3339 timestamps" }
