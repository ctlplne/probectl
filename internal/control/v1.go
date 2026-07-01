// SPDX-License-Identifier: LicenseRef-probectl-TBD

package control

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/imfeelingtheagi/probectl/internal/ai"
	"github.com/imfeelingtheagi/probectl/internal/apierror"
	"github.com/imfeelingtheagi/probectl/internal/auth"
	"github.com/imfeelingtheagi/probectl/internal/canary"
	"github.com/imfeelingtheagi/probectl/internal/httpbody"
	"github.com/imfeelingtheagi/probectl/internal/store"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
	"github.com/imfeelingtheagi/probectl/internal/testspec"
	"github.com/imfeelingtheagi/probectl/internal/usage"
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
		{http.MethodGet, "/v1/tests/bundle", s.handleTestBundle, permTestRead},
		{http.MethodGet, "/v1/tests/{id}/path", s.handleGetPath, permTestRead},
		{http.MethodPost, "/v1/tests/{id}/path", s.handleDiscoverPath, permTestWrite},
		{http.MethodGet, "/v1/agents", s.handleListAgents, permAgentRead},
		{http.MethodPost, "/v1/agents/enroll-tokens", s.handleMintEnrollToken, permAgentWrite},
		{http.MethodPost, "/v1/collectors/register", s.handleRegisterCollector, permAgentWrite},
		{http.MethodPost, "/v1/agents/{id}/revoke", s.handleRevokeAgent, permAgentWrite},
		{http.MethodGet, "/v1/agents/{id}", s.handleGetAgent, permAgentRead},
		{http.MethodPatch, "/v1/agents/{id}", s.handlePatchAgent, permAgentWrite},
		{http.MethodDelete, "/v1/agents/{id}", s.handleDeleteAgent, permAgentWrite},
		{http.MethodGet, "/v1/alerts", s.handleListAlerts, permAlertRead},
		{http.MethodPost, "/v1/alerts", s.handleCreateAlert, permAlertWrite},
		{http.MethodPost, "/v1/alerts/test-channel", s.handleAlertChannelTest, permAlertWrite},
		{http.MethodGet, "/v1/alerts/active", s.handleListActiveAlerts, permAlertRead},
		{http.MethodPost, "/v1/alerts/active/silence", s.handleSilenceAlert, permAlertWrite},
		{http.MethodPost, "/v1/alerts/active/ack", s.handleAckAlert, permAlertWrite},
		{http.MethodGet, "/v1/alerts/maintenance", s.handleListMaintenanceWindows, permAlertRead},
		{http.MethodPost, "/v1/alerts/maintenance", s.handleUpsertMaintenanceWindow, permAlertWrite},
		{http.MethodPost, "/v1/alerts/maintenance/preview", s.handlePreviewMaintenanceWindows, permAlertRead},
		{http.MethodDelete, "/v1/alerts/maintenance/{id}", s.handleDeleteMaintenanceWindow, permAlertWrite},
		{http.MethodGet, "/v1/alerts/{id}", s.handleGetAlert, permAlertRead},
		{http.MethodPut, "/v1/alerts/{id}", s.handleUpdateAlert, permAlertWrite},
		{http.MethodDelete, "/v1/alerts/{id}", s.handleDeleteAlert, permAlertWrite},
		{http.MethodGet, "/v1/incidents", s.handleListIncidents, permIncidentRead},
		{http.MethodGet, "/v1/incidents/{id}", s.handleGetIncident, permIncidentRead},
		{http.MethodGet, "/v1/incidents/{id}/changes", s.handleIncidentChanges, permIncidentRead},
		{http.MethodPatch, "/v1/incidents/{id}", s.handlePatchIncident, permIncidentWrite},
		{http.MethodGet, "/v1/oncall/status", s.handleOncallStatus, permIncidentRead},
		{http.MethodPost, "/v1/oncall/test", s.handleOncallTest, permIncidentWrite},
		{http.MethodGet, "/v1/hierarchy", s.handleGetHierarchy, permOrgRead},
		{http.MethodPost, "/v1/hierarchy/orgs", s.handleCreateOrganization, permOrgWrite},
		{http.MethodPost, "/v1/hierarchy/orgs/{id}/teams", s.handleCreateTeam, permOrgWrite},
		{http.MethodPost, "/v1/hierarchy/teams/{id}/projects", s.handleCreateProject, permOrgWrite},
		{http.MethodGet, "/v1/isolation/status", s.handleIsolationStatus, permTenantRead},
		{http.MethodGet, "/v1/changes", s.handleListChanges, permChangeRead},
		{http.MethodGet, "/v1/bgp/events", s.handleListBGPEvents, ai.PermEventsRead},
		{http.MethodGet, "/v1/devices", s.handleListDevices, ai.PermMetricsRead},
		{http.MethodGet, "/v1/device/metrics", s.handleDeviceMetrics, ai.PermMetricsRead},
		{http.MethodGet, "/v1/ebpf/service-map", s.handleEBPFServiceMap, ai.PermTopologyRead},
		{http.MethodGet, "/v1/flows/top", s.handleFlowTop, permFlowRead},
		{http.MethodGet, "/v1/flows/capacity", s.handleFlowCapacity, permFlowRead},
		{http.MethodGet, "/v1/flows/anomalies", s.handleFlowAnomalies, permFlowRead},
		{http.MethodGet, "/v1/otlp/traces", s.handleOTLPTraces, permMetricsRead},
		{http.MethodGet, "/v1/otlp/logs", s.handleOTLPLogs, permMetricsRead},
		{http.MethodGet, "/v1/otlp-tokens", s.handleOTLPTokenList, permMetricsRead},
		{http.MethodPost, "/v1/otlp-tokens", s.handleOTLPTokenCreate, permMetricsWrite},
		{http.MethodDelete, "/v1/otlp-tokens/{id}", s.handleOTLPTokenRevoke, permMetricsWrite},
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
		{http.MethodGet, "/v1/inventory/views", s.handleListInventoryViews, permAgentRead},
		{http.MethodPost, "/v1/inventory/views", s.handleCreateInventoryView, permAgentWrite},
		{http.MethodGet, "/v1/inventory/views/{id}", s.handleGetInventoryView, permAgentRead},
		{http.MethodGet, "/v1/tls/posture", s.handleTLSPosture, permThreatRead},
		{http.MethodGet, "/v1/siem/status", s.handleSIEMStatus, permThreatRead},
		{http.MethodGet, "/v1/threat/detections", s.handleThreatDetections, permThreatRead},
		{http.MethodGet, "/v1/threat/intel/status", s.handleThreatIntelStatus, permThreatRead},
		{http.MethodGet, "/v1/cmdb/lookup", s.handleCMDBLookup, permCMDBRead},
		{http.MethodGet, "/v1/secrets/health", s.handleSecretsHealth, permDirectoryRead},
		{http.MethodGet, "/v1/topology", s.handleTopology, ai.PermTopologyRead},
		{http.MethodGet, "/v1/cost/summary", s.handleCostSummary, ai.PermMetricsRead},
		{http.MethodGet, "/v1/slos", s.handleSLOs, ai.PermMetricsRead},
		{http.MethodGet, "/v1/compliance", s.handleCompliance, permThreatRead},
		{http.MethodGet, "/v1/compliance/evidence", s.handleComplianceEvidence, permAuditRead},
		{http.MethodGet, "/v1/slos/openslo", s.handleSLOExport, ai.PermMetricsRead},
		{http.MethodGet, "/v1/outages", s.handleOutages, ai.PermMetricsRead},
		{http.MethodGet, "/v1/rum", s.handleRUM, ai.PermMetricsRead},
		{http.MethodGet, "/v1/carbon", s.handleCarbon, ai.PermMetricsRead},
		{http.MethodGet, "/v1/editions", s.handleEditions, permDirectoryRead},
		{http.MethodGet, "/v1/lifecycle/export", s.handleLifecycleExport, permLifecycleExp},
		{http.MethodPost, "/v1/lifecycle/subjects/export", s.handleLifecycleSubjectExport, permLifecycleExp},
		{http.MethodPost, "/v1/lifecycle/subjects/erase", s.handleLifecycleSubjectErase, permLifecycleErase},
		{http.MethodGet, "/v1/lifecycle/retention", s.handleLifecycleRetentionGet, permLifecycleErase},
		{http.MethodPut, "/v1/lifecycle/retention", s.handleLifecycleRetentionPut, permLifecycleErase},
		{http.MethodPost, "/v1/lifecycle/erase", s.handleLifecycleErase, permLifecycleErase},
		{http.MethodGet, "/v1/security/keys", s.handleKeysStatus, permSecurityKeys},
		{http.MethodGet, "/v1/fairness", s.handleFairnessSelf, permFairnessRead},
		{http.MethodGet, "/v1/diagnostics", s.handleDiagnostics, permDiagnosticsRead},
		{http.MethodGet, "/v1/diagnostics/bundle", s.handleDiagnosticsBundle, permDiagnosticsRead},
		{http.MethodGet, "/v1/remediation/proposals", s.handleRemediationList, permRemediationPropose},
		{http.MethodPost, "/v1/remediation/proposals", s.handleRemediationPropose, permRemediationPropose},
		{http.MethodGet, "/v1/remediation/proposals/{id}", s.handleRemediationGet, permRemediationPropose},
		{http.MethodPost, "/v1/remediation/proposals/{id}/approve", s.handleRemediationApprove, permRemediationApprove},
		{http.MethodPost, "/v1/remediation/proposals/{id}/reject", s.handleRemediationReject, permRemediationApprove},
		{http.MethodPost, "/v1/security/keys/rotate", s.handleKeysRotate, permSecurityKeys},
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
		{http.MethodGet, "/v1/directory/scim-tokens", s.handleSCIMTokenList, permDirectoryRead},
		{http.MethodPost, "/v1/directory/scim-tokens", s.handleSCIMTokenCreate, permDirectoryWrite},
		{http.MethodDelete, "/v1/directory/scim-tokens/{id}", s.handleSCIMTokenRevoke, permDirectoryWrite},
		{http.MethodPost, "/v1/a2a/sessions", s.handleStartA2ASession, permAgentWrite},
		{http.MethodPost, "/v1/a2a/mesh", s.handleStartA2AMesh, permAgentWrite},
		// OPS-002: staged rollout operator surface over the rollout engine.
		{http.MethodGet, "/v1/rollouts", s.handleListRollouts, permAgentRead},
		{http.MethodPost, "/v1/rollouts", s.handleCreateRollout, permAgentWrite},
		{http.MethodGet, "/v1/rollouts/{id}", s.handleGetRollout, permAgentRead},
		{http.MethodPost, "/v1/rollouts/{id}/advance", s.handleAdvanceRollout, permAgentWrite},
		{http.MethodPost, "/v1/rollouts/{id}/verify", s.handleVerifyRollout, permAgentWrite},
		{http.MethodPost, "/v1/rollouts/{id}/halt", s.handleHaltRollout, permAgentWrite},
		{http.MethodPost, "/v1/rollouts/{id}/resume", s.handleResumeRollout, permAgentWrite},
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
	// SCALE-002: cursor pagination (?after=<id>&limit=<n>) keeps the response
	// bounded instead of loading the entire tests table (mirrors /v1/agents).
	after := r.URL.Query().Get("after")
	limit := intQuery(r, "limit", store.DefaultTestPageSize)
	var tests []store.Test
	if err := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
		t, e := store.Tests{}.ListPage(ctx, sc, after, limit)
		tests = t
		return e
	}); err != nil {
		return err
	}
	resp := map[string]any{"items": tests}
	// next_cursor is the last id; absent when the page wasn't full (end of set).
	if len(tests) == limit && limit > 0 {
		resp["next_cursor"] = tests[len(tests)-1].ID
	}
	writeJSON(w, http.StatusOK, resp)
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
	if err := s.guardAllowPrivate(r, in.Params); err != nil {
		return err
	}
	// Per-tenant quota gate (S-T3): creation paths only — telemetry is never
	// quota-dropped. Allow-all unless the ee/billing checker is installed.
	if tid, terr := s.principalTenant(r); terr == nil {
		if qerr := usage.AllowCreate(r.Context(), tid, usage.MeterTests); qerr != nil {
			return apierror.Forbidden(qerr.Error()).WithCode("quota_exceeded")
		}
	}
	var created *store.Test
	if err := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
		t, e := store.Tests{}.Create(ctx, sc, in)
		if e != nil {
			return e
		}
		created = t
		data := map[string]any{"name": t.Name, "type": t.Type}
		for param := range privilegedTestParams {
			if in.Params[param] == "true" {
				data[param] = true // U-002/U-040: privileged overrides are explicit in the audit trail
			}
		}
		return s.recordAudit(ctx, sc, r, "test.create", t.ID, data)
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
	if err := s.guardAllowPrivate(r, in.Params); err != nil {
		return err
	}
	var t *store.Test
	if err := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
		x, e := store.Tests{}.Update(ctx, sc, id, in)
		if e != nil {
			return e
		}
		t = x
		data := map[string]any{"name": t.Name}
		for param := range privilegedTestParams {
			if in.Params[param] == "true" {
				data[param] = true // U-002/U-040
			}
		}
		return s.recordAudit(ctx, sc, r, "test.update", id, data)
	}); err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, t)
	return nil
}

// privilegedTestParams maps deny-by-default test params to the admin-seeded
// permission required to set them. Both are tenant-scoped by construction
// (the test row is RLS-scoped) and recorded explicitly in the audit entry by
// the callers: allow_private_targets (U-002, SSRF-guard override) and
// insecure_skip_verify (U-040, disables canary TLS verification).
var privilegedTestParams = map[string]string{
	canary.AllowPrivateParam: permTestAllowPrivate,
	"insecure_skip_verify":   permTestInsecureTLS,
}

// guardAllowPrivate enforces the privileged-param permissions (deny by
// default: no principal, or a principal without the permission, is refused).
func (s *Server) guardAllowPrivate(r *http.Request, params map[string]string) error {
	p := auth.PrincipalFrom(r.Context())
	for param, perm := range privilegedTestParams {
		if params[param] != "true" {
			continue
		}
		if p == nil || !p.Has(perm) {
			return apierror.Forbidden("setting " + param + " requires permission: " + perm)
		}
	}
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
	// SCALE-010: cursor pagination (?after=<id>&limit=<n>) keeps a fleet-scale
	// response bounded instead of loading every agent row.
	after := r.URL.Query().Get("after")
	limit := intQuery(r, "limit", store.DefaultAgentPageSize)
	var agents []store.Agent
	if err := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
		a, e := store.Agents{}.ListPage(ctx, sc, after, limit)
		agents = a
		return e
	}); err != nil {
		return err
	}
	resp := map[string]any{"items": agents}
	// next_cursor is the last id; absent when the page wasn't full (end of set).
	if len(agents) == limit && limit > 0 {
		resp["next_cursor"] = agents[len(agents)-1].ID
	}
	writeJSON(w, http.StatusOK, resp)
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

const maxJSONBody = 1 << 20

// decodeJSON decodes one size-limited JSON request body. Oversized bodies map
// to 413; malformed, unknown-field, or trailing JSON maps to 400.
func decodeJSON(r *http.Request, dst any) error {
	return decodeJSONLimit(r, maxJSONBody, dst)
}

func decodeJSONLimit(r *http.Request, maxBytes int64, dst any) error {
	if err := httpbody.DecodeHTTPJSONStrict(nil, r, maxBytes, dst); err != nil {
		if errors.Is(err, httpbody.ErrTooLarge) {
			return apierror.TooLarge("request body exceeds size cap")
		}
		return apierror.BadRequest("invalid JSON request body")
	}
	return nil
}
