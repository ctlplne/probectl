// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package control

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/ctlplne/probectl/internal/ai"
	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

const onboardingHeartbeatFreshness = 2 * time.Minute

type onboardingReadinessState string

const (
	onboardingReady   onboardingReadinessState = "ready"
	onboardingQuiet   onboardingReadinessState = "quiet"
	onboardingBlocked onboardingReadinessState = "blocked"
)

type onboardingReadiness struct {
	ID         string                   `json:"id"`
	State      onboardingReadinessState `json:"state"`
	Detail     string                   `json:"detail"`
	NextAction string                   `json:"next_action"`
}

type onboardingFinding struct {
	Title      string    `json:"title"`
	Type       string    `json:"type"`
	Target     string    `json:"target"`
	Success    bool      `json:"success"`
	ObservedAt time.Time `json:"observed_at"`
	Href       string    `json:"href"`
}

type onboardingProgressResponse struct {
	AgentEnrollTokenCreated bool                  `json:"agent_enroll_token_created"`
	AgentRegistered         bool                  `json:"agent_registered"`
	AgentConnected          bool                  `json:"agent_connected"`
	ProducerHealthy         bool                  `json:"producer_healthy"`
	FirstTestCreated        bool                  `json:"first_test_created"`
	FirstResultReceived     bool                  `json:"first_result_received"`
	FirstFindingVisible     bool                  `json:"first_finding_visible"`
	ScimTokenCreated        bool                  `json:"scim_token_created"`
	ReadinessStepsComplete  int                   `json:"readiness_steps_complete"`
	ReadinessStepsTotal     int                   `json:"readiness_steps_total"`
	FirstFinding            *onboardingFinding    `json:"first_finding,omitempty"`
	Producers               []onboardingReadiness `json:"producers"`
	Engines                 []onboardingReadiness `json:"engines"`
}

// handleOnboardingProgress serves the first-run checklist from persisted,
// tenant-scoped rows and bounded tenant-partitioned read models. It never
// accepts a tenant selector and never returns one-time token secrets.
func (s *Server) handleOnboardingProgress(w http.ResponseWriter, r *http.Request) error {
	if s.pool == nil {
		return apierror.Unavailable("onboarding progress store is not configured")
	}
	principal := auth.PrincipalFrom(r.Context())
	if principal == nil {
		return apierror.Unauthorized("authentication required")
	}
	permissionDecisions := map[string]bool{}
	var authorizationErr error
	allowed := func(permission string) bool {
		if authorizationErr != nil {
			return false
		}
		if decision, ok := permissionDecisions[permission]; ok {
			return decision
		}
		reason, err := s.decide(r.Context(), principal, permission, auth.RBACGlobal, nil)
		if err != nil {
			authorizationErr = err
			return false
		}
		decision := reason == auth.DecisionAllowed
		permissionDecisions[permission] = decision
		return decision
	}
	var out onboardingProgressResponse
	err := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
		var err error
		if out.AgentEnrollTokenCreated, err = store.NewEnrollTokens(s.pool).CreatedScoped(ctx, sc); err != nil {
			return err
		}
		producerRows, err := (store.Agents{}).ProducerReadiness(ctx, sc, time.Now().UTC().Add(-onboardingHeartbeatFreshness))
		if err != nil {
			return err
		}
		out.Producers = onboardingProducerReadiness(producerRows, allowed)
		for _, producer := range producerRows {
			out.AgentRegistered = out.AgentRegistered || producer.Registered
			out.AgentConnected = out.AgentConnected || producer.Connected
			out.ProducerHealthy = out.ProducerHealthy || producer.Healthy
		}
		if allowed(permTestRead) {
			if out.FirstTestCreated, err = (store.Tests{}).Exists(ctx, sc); err != nil {
				return err
			}
		}
		if allowed(permDirectoryRead) {
			out.ScimTokenCreated, err = store.NewScimTokens(s.pool).CreatedScoped(ctx, sc)
			if err != nil {
				return err
			}
		}

		results := []ResultView{}
		if allowed(permTestRead) && s.latestResults != nil {
			results = s.latestResults.List(sc.Tenant.String())
		}
		applyOnboardingResults(&out, results)
		out.Engines, err = s.onboardingEngineReadiness(ctx, sc, results, allowed)
		if err != nil {
			return err
		}
		return authorizationErr
	})
	if err != nil {
		return err
	}
	setOnboardingReadinessCount(&out)
	writeJSON(w, http.StatusOK, out)
	return nil
}

func onboardingProducerReadiness(rows []store.ProducerReadiness, allowed func(string) bool) []onboardingReadiness {
	out := make([]onboardingReadiness, 0, len(rows))
	for _, row := range rows {
		next := "/admin?register_collector=" + row.ID
		if row.ID == "synthetic" {
			next = "/onboarding#first-run-agent"
		}
		readiness := onboardingReadiness{ID: row.ID, State: onboardingBlocked, NextAction: next}
		switch {
		case row.Healthy:
			readiness.State = onboardingReady
			readiness.Detail = "producer heartbeat is current"
			readiness.NextAction = producerSurface(row.ID)
		case row.Connected:
			readiness.Detail = "producer heartbeat is stale"
		case row.Registered:
			readiness.Detail = "producer is registered but has not connected"
		default:
			readiness.Detail = "producer is not registered"
		}
		requiredPermission := permAgentWrite
		if row.Healthy {
			requiredPermission = producerSurfacePermission(row.ID)
		}
		if !allowed(requiredPermission) {
			readiness.Detail += "; request " + requiredPermission + " for the next action"
			readiness.NextAction = "/onboarding"
		}
		out = append(out, readiness)
	}
	return out
}

func producerSurfacePermission(id string) string {
	switch id {
	case "flow":
		return permFlowRead
	case "bgp":
		return ai.PermEventsRead
	case "device":
		return ai.PermMetricsRead
	case "ebpf":
		return ai.PermTopologyRead
	case "endpoint":
		return permAgentRead
	default:
		return permTestRead
	}
}

func producerSurface(id string) string {
	switch id {
	case "flow":
		return "/planes/flow"
	case "bgp":
		return "/planes/bgp"
	case "device":
		return "/planes/device"
	case "ebpf":
		return "/planes/ebpf"
	case "endpoint":
		return "/endpoints"
	default:
		return "/targets"
	}
}

func applyOnboardingResults(out *onboardingProgressResponse, results []ResultView) {
	out.FirstResultReceived = len(results) > 0
	if len(results) == 0 {
		return
	}
	result := results[0]
	target := result.Target
	if target == "" {
		target = result.AgentID
	}
	status := "healthy"
	if !result.Success {
		status = "failed"
	}
	typeName := strings.ToUpper(result.Type)
	out.FirstFindingVisible = true
	out.FirstFinding = &onboardingFinding{
		Title:      fmt.Sprintf("%s check %s — %s", typeName, status, target),
		Type:       result.Type,
		Target:     target,
		Success:    result.Success,
		ObservedAt: result.ObservedAt.UTC(),
		Href:       "/targets",
	}
}

func setOnboardingReadinessCount(out *onboardingProgressResponse) {
	out.ReadinessStepsTotal = 4
	for _, complete := range []bool{
		out.AgentConnected,
		out.ProducerHealthy,
		out.FirstResultReceived,
		out.FirstFindingVisible,
	} {
		if complete {
			out.ReadinessStepsComplete++
		}
	}
}

func engineReadiness(id string, wired, hasData bool, nextAction string) onboardingReadiness {
	if !wired {
		return onboardingReadiness{ID: id, State: onboardingBlocked, Detail: "engine is not configured", NextAction: "/admin"}
	}
	if !hasData {
		return onboardingReadiness{ID: id, State: onboardingQuiet, Detail: "engine is running and waiting for tenant data", NextAction: nextAction}
	}
	return onboardingReadiness{ID: id, State: onboardingReady, Detail: "engine has tenant data", NextAction: nextAction}
}

func runningEngineReadiness(id string, running bool, nextAction string) onboardingReadiness {
	if !running {
		return onboardingReadiness{ID: id, State: onboardingBlocked, Detail: "engine is not configured", NextAction: "/admin"}
	}
	return onboardingReadiness{ID: id, State: onboardingReady, Detail: "engine is running", NextAction: nextAction}
}

func authorizedEngineReadiness(readiness onboardingReadiness, allowed bool) onboardingReadiness {
	if allowed {
		return readiness
	}
	return onboardingReadiness{
		ID: readiness.ID, State: onboardingBlocked,
		Detail:     "not authorized to inspect this engine; request the matching tenant permission",
		NextAction: "/onboarding",
	}
}

// onboardingEngineReadiness is one honest, server-derived status inventory.
// Every tenant-data lookup uses an already-entered tenant scope or a
// tenant-partitioned in-memory store; no browser-supplied tenant is trusted.
func (s *Server) onboardingEngineReadiness(
	ctx context.Context,
	sc tenancy.Scope,
	results []ResultView,
	allowed func(string) bool,
) ([]onboardingReadiness, error) {
	tenant := sc.Tenant.String()
	metricsRead := allowed(ai.PermMetricsRead)
	topologyRead := allowed(ai.PermTopologyRead)
	threatRead := allowed(permThreatRead)
	directoryRead := allowed(permDirectoryRead)
	topologyHasData := false
	if topologyRead && s.topo != nil {
		graph, err := s.topo.ForTenant(tenant)
		if err != nil {
			return nil, apierror.Forbidden("tenant topology scope is invalid").Wrap(err)
		}
		snapshot := graph.Latest()
		topologyHasData = len(snapshot.Nodes) > 0 || len(snapshot.Edges) > 0
	}

	endpointHasData := false
	if allowed(permAgentRead) {
		if source, ok := s.endpointViews.(interface{ Len(string) int }); ok {
			endpointHasData = source.Len(tenant) > 0
		}
	}

	threatHasData := false
	if threatRead && s.pool != nil {
		detections, err := (store.Incidents{}).ThreatDetections(ctx, sc, 1)
		if err != nil {
			return nil, err
		}
		threatHasData = len(detections) > 0
	} else if threatRead && s.detections != nil {
		threatHasData = s.detections.Len(tenant) > 0
	}
	ndrActive := s.cfg != nil && s.cfg.NDREnabled
	siemActive := s.cfg != nil && s.cfg.SIEMEnabled
	ctActive := s.cfg != nil && s.cfg.CTEnabled
	threatIntelHasData := threatRead && s.iocStore != nil && s.iocStore.Count() > 0

	alerting := engineReadiness("alerting", s.alertingActive, s.alertingActive, "/alerts")
	if s.alertingActive {
		alerting.Detail = "alert evaluator is running"
	}
	outageData := false
	if metricsRead && s.outageEngine != nil {
		snapshot := s.outageEngine.Snapshot(tenant)
		outageData = len(snapshot.Events) > 0 || len(snapshot.Vantage) > 0
	}

	engines := []onboardingReadiness{
		authorizedEngineReadiness(engineReadiness("synthetic-results", s.latestResults != nil, len(results) > 0, "/targets"), allowed(permTestRead)),
		authorizedEngineReadiness(engineReadiness("flow-analytics", s.flowStore != nil, false, "/planes/flow"), allowed(permFlowRead)),
		authorizedEngineReadiness(engineReadiness("otlp", s.otelStore != nil, false, "/admin"), metricsRead),
		authorizedEngineReadiness(engineReadiness("device-telemetry", s.deviceOps != nil, false, "/planes/device"), metricsRead),
		authorizedEngineReadiness(engineReadiness("ebpf", s.ebpfStore != nil || s.topo != nil, topologyHasData, "/planes/ebpf"), topologyRead),
		authorizedEngineReadiness(engineReadiness("topology", s.topo != nil, topologyHasData, "/topology"), topologyRead),
		authorizedEngineReadiness(engineReadiness("cost", s.costEngine != nil, metricsRead && s.costEngine != nil && s.costEngine.Summary(tenant).TotalBytes > 0, "/cost"), metricsRead),
		authorizedEngineReadiness(engineReadiness("slo", s.sloEngine != nil, metricsRead && s.sloEngine != nil && len(s.sloEngine.Statuses(tenant)) > 0, "/slos"), metricsRead),
		authorizedEngineReadiness(alerting, allowed(permAlertRead)),
		authorizedEngineReadiness(engineReadiness("compliance", s.complianceEngine != nil, threatRead && s.complianceEngine != nil && len(s.complianceEngine.Results(tenant)) > 0, "/compliance"), threatRead),
		authorizedEngineReadiness(engineReadiness("outage", s.outageEngine != nil, outageData, "/outages"), metricsRead),
		authorizedEngineReadiness(engineReadiness("rum", s.rumEngine != nil, metricsRead && s.rumEngine != nil && len(s.rumEngine.Snapshot(tenant).Apps) > 0, "/rum"), metricsRead),
		authorizedEngineReadiness(engineReadiness("carbon", s.carbonEngine != nil, metricsRead && s.carbonEngine != nil && s.carbonEngine.Summary(tenant).TotalBytes > 0, "/carbon"), metricsRead),
		authorizedEngineReadiness(engineReadiness("tls-posture", s.tlsPostures != nil, threatRead && s.tlsPostures != nil && s.tlsPostures.Len(tenant) > 0, "/security"), threatRead),
		authorizedEngineReadiness(engineReadiness("ct-correlation", ctActive && s.tlsPostures != nil, ctActive && threatRead && s.tlsPostures != nil && s.tlsPostures.Len(tenant) > 0, "/security"), threatRead),
		authorizedEngineReadiness(engineReadiness("threat-intel", s.intelRefresher != nil, threatIntelHasData, "/security"), threatRead),
		authorizedEngineReadiness(engineReadiness("ndr", ndrActive && (s.pool != nil || s.detections != nil), threatHasData, "/security"), threatRead),
		authorizedEngineReadiness(engineReadiness("threat-detections", ndrActive || s.intelRefresher != nil, threatHasData, "/security"), threatRead),
		authorizedEngineReadiness(engineReadiness("endpoint-dem", s.endpointViews != nil, endpointHasData, "/endpoints"), allowed(permAgentRead)),
		authorizedEngineReadiness(engineReadiness("secrets", s.secretsHealth != nil, directoryRead && s.secretsHealth != nil && len(s.secretsHealth.Health()) > 0, "/admin"), directoryRead),
		authorizedEngineReadiness(engineReadiness("cmdb", s.cmdb != nil, false, "/admin"), allowed(permCMDBRead)),
		authorizedEngineReadiness(engineReadiness("outage-feeds", s.outageFeeds != nil, outageData, "/outages"), metricsRead),
		authorizedEngineReadiness(runningEngineReadiness("oncall-dispatch", s.dispatcher != nil, "/admin"), allowed(permIncidentRead)),
		authorizedEngineReadiness(runningEngineReadiness("siem-export", siemActive, "/admin"), allowed(permAuditRead)),
	}
	return engines, nil
}
