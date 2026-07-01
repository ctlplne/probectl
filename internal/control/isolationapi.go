// SPDX-License-Identifier: LicenseRef-probectl-TBD

package control

import (
	"context"
	"fmt"
	"net/http"

	"github.com/imfeelingtheagi/probectl/internal/bus"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
)

type isolationStatus struct {
	ID             string                 `json:"id"`
	Name           string                 `json:"name"`
	Status         string                 `json:"status"`
	Summary        string                 `json:"summary"`
	TenantID       string                 `json:"tenant_id"`
	EffectiveModel string                 `json:"effective_model"`
	RegistryModel  string                 `json:"registry_model"`
	Residency      string                 `json:"residency,omitempty"`
	RLS            isolationRLSStatus     `json:"rls"`
	LaneNamespace  isolationLaneStatus    `json:"lane_namespace"`
	SiloRouting    isolationRoutingStatus `json:"silo_routing"`
}

type isolationRLSStatus struct {
	DatabaseConfigured bool   `json:"database_configured"`
	Healthy            bool   `json:"healthy"`
	Enforced           bool   `json:"enforced"`
	Detail             string `json:"detail"`
}

type isolationLaneStatus struct {
	Mode         string `json:"mode"`
	Namespace    string `json:"namespace,omitempty"`
	TopicExample string `json:"topic_example"`
	TenantTagged bool   `json:"tenant_tagged"`
	Strict       bool   `json:"strict"`
}

type isolationRoutingStatus struct {
	Resolved                           bool   `json:"resolved"`
	Enabled                            bool   `json:"enabled"`
	FailClosed                         bool   `json:"fail_closed"`
	PGSchema                           string `json:"pg_schema,omitempty"`
	ClickHouseDatabase                 string `json:"clickhouse_database,omitempty"`
	ClickHouseResidencyPlaneConfigured bool   `json:"clickhouse_residency_plane_configured"`
	ObjectPrefix                       string `json:"object_prefix,omitempty"`
	Error                              string `json:"error,omitempty"`
}

// handleIsolationStatus reports only the caller tenant's effective isolation
// posture: the installed router target, the caller's own bus lane, and a
// sanitized RLS health bit. It never lists other tenants or fleet denominators.
func (s *Server) handleIsolationStatus(w http.ResponseWriter, r *http.Request) error {
	tid, err := s.principalTenant(r)
	if err != nil {
		return err
	}
	_, registryModel, residency, err := s.tenantSlugAndMeta(r.Context(), tid)
	if err != nil {
		return err
	}
	targets, routeErr := tenancy.CurrentRouter().TargetsFor(r.Context(), tid)
	status := s.buildIsolationStatus(r.Context(), tid, registryModel, residency, targets, routeErr)
	writeJSON(w, http.StatusOK, status)
	return nil
}

func (s *Server) buildIsolationStatus(ctx context.Context, tenantID, registryModel, residency string, targets tenancy.Targets, routeErr error) isolationStatus {
	if registryModel == "" {
		registryModel = string(tenancy.IsolationPooled)
	}
	effective := string(targets.Model)
	if effective == "" {
		effective = registryModel
	}
	if effective == "" {
		effective = string(tenancy.IsolationPooled)
	}
	if targets.Residency != "" {
		residency = targets.Residency
	}
	rls := s.isolationRLSHealth(ctx)
	lane, laneErr := isolationLaneForTargets(targets)
	routing := isolationRoutingStatus{
		Resolved:                           routeErr == nil && laneErr == nil,
		Enabled:                            effective == string(tenancy.IsolationSiloed) || effective == string(tenancy.IsolationHybrid),
		FailClosed:                         true,
		PGSchema:                           targets.PGSchema,
		ClickHouseDatabase:                 targets.CHDatabase,
		ClickHouseResidencyPlaneConfigured: targets.CHBaseURL != "",
		ObjectPrefix:                       targets.ObjectPrefix,
	}
	if routeErr != nil {
		routing.Error = "isolation router could not resolve this tenant"
		s.log.Warn("isolation status router resolution failed", "tenant_id", tenantID, "error", routeErr.Error())
	} else if laneErr != nil {
		routing.Error = "isolation router returned an invalid bus namespace for this tenant"
		s.log.Warn("isolation status bus namespace invalid", "tenant_id", tenantID, "namespace", targets.BusNamespace, "error", laneErr.Error())
	}
	state := "healthy"
	if !rls.Healthy || !routing.Resolved {
		state = "degraded"
	}
	if !rls.DatabaseConfigured {
		state = "unknown"
	}
	summary := fmt.Sprintf("%s isolation; RLS %s; bus lane %s", effective, healthWord(rls), lane.Mode)
	return isolationStatus{
		ID:             "isolation",
		Name:           "Isolation posture",
		Status:         state,
		Summary:        summary,
		TenantID:       tenantID,
		EffectiveModel: effective,
		RegistryModel:  registryModel,
		Residency:      residency,
		RLS:            rls,
		LaneNamespace:  lane,
		SiloRouting:    routing,
	}
}

func (s *Server) isolationRLSHealth(ctx context.Context) isolationRLSStatus {
	if s.pool == nil {
		return isolationRLSStatus{
			DatabaseConfigured: false,
			Healthy:            false,
			Enforced:           false,
			Detail:             "postgres is not configured on this process",
		}
	}
	if err := tenancy.AssertIsolationPosture(ctx, s.pool); err != nil {
		s.log.Warn("tenant isolation posture check failed", "error", err.Error())
		return isolationRLSStatus{
			DatabaseConfigured: true,
			Healthy:            false,
			Enforced:           false,
			Detail:             "runtime isolation posture check failed; see control-plane logs",
		}
	}
	return isolationRLSStatus{
		DatabaseConfigured: true,
		Healthy:            true,
		Enforced:           true,
		Detail:             "app role is constrained and tenant-owned tables force row-level security",
	}
}

func isolationLaneForTargets(targets tenancy.Targets) (isolationLaneStatus, error) {
	topic, err := bus.TopicFor(targets.BusNamespace, bus.NetworkResultsTopic)
	if err != nil {
		return isolationLaneStatus{
			Mode:         "invalid",
			Namespace:    targets.BusNamespace,
			TopicExample: bus.NetworkResultsTopic,
			TenantTagged: true,
			Strict:       true,
		}, err
	}
	mode := "shared_tenant_tagged"
	if targets.BusNamespace != "" {
		mode = "tenant_namespaced"
	}
	return isolationLaneStatus{
		Mode:         mode,
		Namespace:    targets.BusNamespace,
		TopicExample: topic,
		TenantTagged: true,
		Strict:       targets.BusNamespace != "",
	}, nil
}

func healthWord(rls isolationRLSStatus) string {
	if !rls.DatabaseConfigured {
		return "unknown"
	}
	if rls.Healthy {
		return "healthy"
	}
	return "unhealthy"
}
