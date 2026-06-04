package control

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/imfeelingtheagi/probectl/internal/ai"
	"github.com/imfeelingtheagi/probectl/internal/apierror"
	"github.com/imfeelingtheagi/probectl/internal/auth"
	"github.com/imfeelingtheagi/probectl/internal/store"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
	"github.com/imfeelingtheagi/probectl/internal/testspec"
)

// apiRoute binds a method+pattern to a handler. This table is the single source
// of truth for routing AND the OpenAPI-matches-handlers check (no undocumented
// routes — CLAUDE.md §6, §8).
type apiRoute struct {
	Method  string
	Pattern string
	Handler apiHandler
	// Permission is the RBAC permission key the caller must hold (within its
	// tenant) to reach the route. Empty means "authenticated, no specific
	// permission" (e.g. /v1/me). The tenant boundary is always enforced first.
	Permission string
}

func (s *Server) apiRoutes() []apiRoute {
	return []apiRoute{
		{http.MethodGet, "/v1/tests", s.handleListTests, permTestRead},
		{http.MethodPost, "/v1/tests", s.handleCreateTest, permTestWrite},
		{http.MethodGet, "/v1/tests/{id}", s.handleGetTest, permTestRead},
		{http.MethodPut, "/v1/tests/{id}", s.handleUpdateTest, permTestWrite},
		{http.MethodDelete, "/v1/tests/{id}", s.handleDeleteTest, permTestWrite},
		{http.MethodGet, "/v1/tests/{id}/path", s.handleGetPath, permTestRead},
		{http.MethodPost, "/v1/tests/{id}/path", s.handleDiscoverPath, permTestWrite},
		{http.MethodGet, "/v1/agents", s.handleListAgents, permAgentRead},
		{http.MethodGet, "/v1/agents/{id}", s.handleGetAgent, permAgentRead},
		{http.MethodPatch, "/v1/agents/{id}", s.handlePatchAgent, permAgentWrite},
		{http.MethodDelete, "/v1/agents/{id}", s.handleDeleteAgent, permAgentWrite},
		{http.MethodGet, "/v1/alerts", s.handleListAlerts, permAlertRead},
		{http.MethodPost, "/v1/alerts", s.handleCreateAlert, permAlertWrite},
		{http.MethodGet, "/v1/alerts/active", s.handleListActiveAlerts, permAlertRead},
		{http.MethodPost, "/v1/alerts/active/silence", s.handleSilenceAlert, permAlertWrite},
		{http.MethodPost, "/v1/alerts/active/ack", s.handleAckAlert, permAlertWrite},
		{http.MethodGet, "/v1/alerts/{id}", s.handleGetAlert, permAlertRead},
		{http.MethodPut, "/v1/alerts/{id}", s.handleUpdateAlert, permAlertWrite},
		{http.MethodDelete, "/v1/alerts/{id}", s.handleDeleteAlert, permAlertWrite},
		{http.MethodGet, "/v1/incidents", s.handleListIncidents, permIncidentRead},
		{http.MethodGet, "/v1/incidents/{id}", s.handleGetIncident, permIncidentRead},
		{http.MethodGet, "/v1/incidents/{id}/changes", s.handleIncidentChanges, permIncidentRead},
		{http.MethodPatch, "/v1/incidents/{id}", s.handlePatchIncident, permIncidentWrite},
		{http.MethodGet, "/v1/changes", s.handleListChanges, permChangeRead},
		{http.MethodGet, "/v1/flows/top", s.handleFlowTop, permFlowRead},
		{http.MethodGet, "/v1/flows/capacity", s.handleFlowCapacity, permFlowRead},
		{http.MethodGet, "/v1/flows/anomalies", s.handleFlowAnomalies, permFlowRead},
		{http.MethodGet, "/v1/grafana/api/v1/query", s.handlePromQuery, ai.PermMetricsRead},
		{http.MethodPost, "/v1/grafana/api/v1/query", s.handlePromQuery, ai.PermMetricsRead},
		{http.MethodGet, "/v1/grafana/api/v1/query_range", s.handlePromQueryRange, ai.PermMetricsRead},
		{http.MethodPost, "/v1/grafana/api/v1/query_range", s.handlePromQueryRange, ai.PermMetricsRead},
		{http.MethodGet, "/v1/grafana/api/v1/series", s.handlePromSeries, ai.PermMetricsRead},
		{http.MethodPost, "/v1/grafana/api/v1/series", s.handlePromSeries, ai.PermMetricsRead},
		{http.MethodGet, "/v1/grafana/api/v1/labels", s.handlePromLabels, ai.PermMetricsRead},
		{http.MethodPost, "/v1/grafana/api/v1/labels", s.handlePromLabels, ai.PermMetricsRead},
		{http.MethodGet, "/v1/grafana/api/v1/label/{name}/values", s.handlePromLabelValues, ai.PermMetricsRead},
		{http.MethodGet, "/v1/grafana/api/v1/status/buildinfo", s.handlePromBuildInfo, ai.PermMetricsRead},
		{http.MethodGet, "/v1/grafana/api/v1/metadata", s.handlePromMetadata, ai.PermMetricsRead},
		{http.MethodGet, "/v1/prometheus/federate", s.handlePromFederate, ai.PermMetricsRead},
		{http.MethodPost, "/v1/prometheus/write", s.handlePromWrite, permMetricsWrite},
		{http.MethodGet, "/v1/results/latest", s.handleLatestResults, permTestRead},
		{http.MethodGet, "/v1/endpoints", s.handleListEndpoints, permAgentRead},
		{http.MethodGet, "/v1/tls/posture", s.handleTLSPosture, permThreatRead},
		{http.MethodGet, "/v1/threat/detections", s.handleThreatDetections, permThreatRead},
		{http.MethodGet, "/v1/cmdb/lookup", s.handleCMDBLookup, permCMDBRead},
		{http.MethodGet, "/v1/secrets/health", s.handleSecretsHealth, permDirectoryRead},
		{http.MethodGet, "/v1/topology", s.handleTopology, ai.PermTopologyRead},
		{http.MethodGet, "/v1/cost/summary", s.handleCostSummary, ai.PermMetricsRead},
		{http.MethodPost, "/v1/topology/whatif", s.handleWhatIf, ai.PermTopologyRead},
		{http.MethodGet, "/v1/incidents/{id}/cis", s.handleIncidentCIs, permIncidentRead},
		{http.MethodGet, "/v1/agents/{id}/ci", s.handleAgentCI, permAgentRead},
		{http.MethodGet, "/v1/audit", s.handleListAudit, permAuditRead},
		{http.MethodGet, "/v1/audit/verify", s.handleVerifyAudit, permAuditRead},
		{http.MethodPost, "/v1/ai/ask", s.handleAIAsk, permAIQuery},
		{http.MethodPost, "/v1/ai/feedback", s.handleAIFeedback, permAIQuery},
		{http.MethodPost, "/v1/ai/author", s.handleAIAuthor, permTestWrite},
		{http.MethodPost, "/v1/ai/discover", s.handleAIDiscover, permTestWrite},
		{http.MethodGet, "/v1/abac/policies", s.handleListPolicies, permDirectoryRead},
		{http.MethodPost, "/v1/abac/policies", s.handleCreatePolicy, permDirectoryWrite},
		{http.MethodDelete, "/v1/abac/policies/{id}", s.handleDeletePolicy, permDirectoryWrite},
		{http.MethodGet, "/v1/me", s.handleMe, ""},
	}
}

// inTenant runs fn inside the caller's tenant — resolved from the authenticated
// principal (tenant boundary first) — in an RLS-enforced transaction. The auth
// middleware has already injected the principal; a missing one is a 401.
func (s *Server) inTenant(r *http.Request, fn func(context.Context, tenancy.Scope) error) error {
	p := auth.PrincipalFrom(r.Context())
	if p == nil {
		return apierror.Unauthorized("authentication required")
	}
	ctx := tenancy.WithTenant(r.Context(), tenancy.ID(p.TenantID))
	return tenancy.InTenant(ctx, s.pool, fn)
}

// --- tests ---

type testRequest struct {
	Name            string            `json:"name"`
	Type            string            `json:"type"`
	Target          string            `json:"target"`
	IntervalSeconds int               `json:"interval_seconds"`
	TimeoutSeconds  int               `json:"timeout_seconds"`
	Params          map[string]string `json:"params"`
	Enabled         *bool             `json:"enabled"`
}

// toInput validates the request against the canonical test schema (shared with AI
// authoring, S26) and maps it to a store input.
func (req testRequest) toInput() (store.TestInput, error) {
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	spec, err := testspec.Clean(testspec.Spec{
		Name:            req.Name,
		Type:            req.Type,
		Target:          req.Target,
		IntervalSeconds: req.IntervalSeconds,
		TimeoutSeconds:  req.TimeoutSeconds,
		Params:          req.Params,
		Enabled:         enabled,
	})
	if err != nil {
		return store.TestInput{}, apierror.Validation(err.Error())
	}
	return store.TestInput{
		Name:            spec.Name,
		Type:            spec.Type,
		Target:          spec.Target,
		IntervalSeconds: spec.IntervalSeconds,
		TimeoutSeconds:  spec.TimeoutSeconds,
		Params:          spec.Params,
		Enabled:         spec.Enabled,
	}, nil
}

func (s *Server) handleListTests(w http.ResponseWriter, r *http.Request) error {
	var tests []store.Test
	if err := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
		t, e := store.Tests{}.List(ctx, sc)
		tests = t
		return e
	}); err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": tests})
	return nil
}

func (s *Server) handleCreateTest(w http.ResponseWriter, r *http.Request) error {
	var req testRequest
	if err := decodeJSON(r, &req); err != nil {
		return err
	}
	in, err := req.toInput()
	if err != nil {
		return err
	}
	var created *store.Test
	if err := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
		t, e := store.Tests{}.Create(ctx, sc, in)
		if e != nil {
			return e
		}
		created = t
		return s.recordAudit(ctx, sc, r, "test.create", t.ID, map[string]any{"name": t.Name, "type": t.Type})
	}); err != nil {
		return err
	}
	w.Header().Set("Location", "/v1/tests/"+created.ID)
	writeJSON(w, http.StatusCreated, created)
	return nil
}

func (s *Server) handleGetTest(w http.ResponseWriter, r *http.Request) error {
	id := r.PathValue("id")
	var t *store.Test
	if err := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
		x, e := store.Tests{}.Get(ctx, sc, id)
		t = x
		return e
	}); err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, t)
	return nil
}

func (s *Server) handleUpdateTest(w http.ResponseWriter, r *http.Request) error {
	id := r.PathValue("id")
	var req testRequest
	if err := decodeJSON(r, &req); err != nil {
		return err
	}
	in, err := req.toInput()
	if err != nil {
		return err
	}
	var t *store.Test
	if err := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
		x, e := store.Tests{}.Update(ctx, sc, id, in)
		if e != nil {
			return e
		}
		t = x
		return s.recordAudit(ctx, sc, r, "test.update", id, map[string]any{"name": t.Name})
	}); err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, t)
	return nil
}

func (s *Server) handleDeleteTest(w http.ResponseWriter, r *http.Request) error {
	id := r.PathValue("id")
	if err := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
		if e := (store.Tests{}).Delete(ctx, sc, id); e != nil {
			return e
		}
		return s.recordAudit(ctx, sc, r, "test.delete", id, nil)
	}); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

// --- agents (registered via mTLS; the API manages their labels + lifecycle) ---

func (s *Server) handleListAgents(w http.ResponseWriter, r *http.Request) error {
	var agents []store.Agent
	if err := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
		a, e := store.Agents{}.List(ctx, sc)
		agents = a
		return e
	}); err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": agents})
	return nil
}

func (s *Server) handleGetAgent(w http.ResponseWriter, r *http.Request) error {
	id := r.PathValue("id")
	var a *store.Agent
	if err := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
		x, e := store.Agents{}.Get(ctx, sc, id)
		a = x
		return e
	}); err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, a)
	return nil
}

type agentPatch struct {
	Name string `json:"name"`
}

func (s *Server) handlePatchAgent(w http.ResponseWriter, r *http.Request) error {
	id := r.PathValue("id")
	var req agentPatch
	if err := decodeJSON(r, &req); err != nil {
		return err
	}
	name := strings.TrimSpace(req.Name)
	if name == "" || len(name) > 200 {
		return apierror.Validation("name is required (1–200 characters)")
	}
	var a *store.Agent
	if err := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
		x, e := store.Agents{}.Rename(ctx, sc, id, name)
		if e != nil {
			return e
		}
		a = x
		return s.recordAudit(ctx, sc, r, "agent.update", id, map[string]any{"name": name})
	}); err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, a)
	return nil
}

func (s *Server) handleDeleteAgent(w http.ResponseWriter, r *http.Request) error {
	id := r.PathValue("id")
	if err := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
		if e := (store.Agents{}).Delete(ctx, sc, id); e != nil {
			return e
		}
		return s.recordAudit(ctx, sc, r, "agent.delete", id, nil)
	}); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

// decodeJSON decodes a size-limited JSON request body, mapping malformed input
// to a 400.
func decodeJSON(r *http.Request, dst any) error {
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(dst); err != nil {
		return apierror.BadRequest("invalid JSON request body")
	}
	return nil
}
