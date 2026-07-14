// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package control

import (
	"context"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/imfeelingtheagi/probectl/internal/apierror"
	"github.com/imfeelingtheagi/probectl/internal/bus"
	"github.com/imfeelingtheagi/probectl/internal/endpoint"
	resultv1 "github.com/imfeelingtheagi/probectl/internal/gen/probectl/result/v1"
	"github.com/imfeelingtheagi/probectl/internal/pipeline"
)

// Endpoint DEM read model (S-FE4 surface for S37): a consumer on
// probectl.endpoint.results retains each endpoint's latest DEM state in the
// snapshot store, and GET /v1/endpoints serves the caller's tenant partition.
// Privacy is upstream and absolute — fields the agent withheld are absent in
// the results and therefore absent here; nothing re-derives them.

// EndpointViewConsumer feeds the snapshot store from the endpoint result topic
// (its own consumer group, independent of the S37 TSDB pipeline).
type EndpointViewConsumer struct {
	bus       bus.Bus
	store     endpointCacheRecorder
	log       *slog.Logger
	nsTenants map[string]string
	binding   pipeline.TenantBinding
	strict    bool
}

type endpointCacheRecorder interface {
	RecordCache(tenant, agent string, view endpoint.ResultView)
}

// NewEndpointViewConsumer builds the consumer.
func NewEndpointViewConsumer(b bus.Bus, store endpointCacheRecorder, log *slog.Logger) *EndpointViewConsumer {
	if log == nil {
		log = slog.Default()
	}
	return &EndpointViewConsumer{bus: b, store: store, log: log}
}

// WithTenantBinding verifies shared-lane endpoint claims against the agent
// registry before the derived view sees them.
func (cs *EndpointViewConsumer) WithTenantBinding(binding pipeline.TenantBinding) *EndpointViewConsumer {
	cs.binding = binding
	return cs
}

// WithStrictTenantLanes refuses shared endpoint lanes in regulated/provider profiles.
func (cs *EndpointViewConsumer) WithStrictTenantLanes(strict bool) *EndpointViewConsumer {
	cs.strict = strict
	return cs
}

// WithNamespaceTenants subscribes endpoint views to each siloed tenant's lane.
func (cs *EndpointViewConsumer) WithNamespaceTenants(ns map[string]string) *EndpointViewConsumer {
	cs.nsTenants = ns
	return cs
}

// LaneFanoutEnabled satisfies pipeline.LaneFanout (CORRECT-005 coverage gate).
func (cs *EndpointViewConsumer) LaneFanoutEnabled() bool { return true }

// Run consumes until ctx is done. Malformed messages are dropped (untrusted
// input never wedges the consumer).
func (cs *EndpointViewConsumer) Run(ctx context.Context) error {
	// Pure in-RAM view → per-replica fan-in for coherence (ARCH-003).
	return pipeline.RunLanes(ctx, cs.bus, bus.EndpointResultsTopic, viewGroup("endpoint-view"), cs.nsTenants, cs.handleLane)
}

func (cs *EndpointViewConsumer) handleLane(ctx context.Context, msg bus.Message, laneTenant string) error {
	var r resultv1.Result
	if err := proto.Unmarshal(msg.Value, &r); err != nil {
		cs.log.Warn("skipping malformed endpoint result", "error", err)
		return nil
	}
	if !verifyEndpointResult(ctx, cs.binding, cs.strict, laneTenant, &r, cs.log) {
		return nil
	}
	cs.store.RecordCache(r.GetTenantId(), r.GetAgentId(), endpoint.ResultView{
		Type:       r.GetCanaryType(),
		Target:     r.GetServerAddress(),
		Success:    r.GetSuccess(),
		Error:      r.GetErrorMessage(),
		Metrics:    r.GetMetrics(),
		Attributes: r.GetAttributes(),
		ObservedAt: time.Unix(0, r.GetStartTimeUnixNano()),
	})
	return nil
}

// EndpointEventConsumer is the shared durable leg. It writes endpoint events
// to ClickHouse with bounded retry, then dead-letters the original protobuf on
// exhaustion. A DLQ failure returns the write error so the bus offset remains
// uncommitted (the same no-silent-loss contract as the TSDB result pipeline).
type EndpointEventConsumer struct {
	bus       bus.Bus
	store     *endpoint.Repository
	log       *slog.Logger
	nsTenants map[string]string
	binding   pipeline.TenantBinding
	strict    bool
	retries   int
	baseDelay time.Duration
}

// NewEndpointEventConsumer builds the durable endpoint consumer.
func NewEndpointEventConsumer(b bus.Bus, store *endpoint.Repository, log *slog.Logger) *EndpointEventConsumer {
	if log == nil {
		log = slog.Default()
	}
	return &EndpointEventConsumer{bus: b, store: store, log: log, retries: 3, baseDelay: 50 * time.Millisecond}
}

// WithNamespaceTenants subscribes every siloed endpoint lane.
func (cs *EndpointEventConsumer) WithNamespaceTenants(tenants map[string]string) *EndpointEventConsumer {
	cs.nsTenants = tenants
	return cs
}

// WithTenantBinding installs registry-backed endpoint tenant verification.
func (cs *EndpointEventConsumer) WithTenantBinding(binding pipeline.TenantBinding) *EndpointEventConsumer {
	cs.binding = binding
	return cs
}

// WithStrictTenantLanes refuses shared endpoint lanes when enabled.
func (cs *EndpointEventConsumer) WithStrictTenantLanes(strict bool) *EndpointEventConsumer {
	cs.strict = strict
	return cs
}

// LaneFanoutEnabled satisfies the namespaced-lane coverage gate.
func (*EndpointEventConsumer) LaneFanoutEnabled() bool { return true }

// Run consumes until cancellation using one shared durable consumer group.
func (cs *EndpointEventConsumer) Run(ctx context.Context) error {
	return pipeline.RunLanes(ctx, cs.bus, bus.EndpointResultsTopic, "endpoint-events", cs.nsTenants, cs.handleLane)
}

func (cs *EndpointEventConsumer) handleLane(ctx context.Context, msg bus.Message, laneTenant string) error {
	var result resultv1.Result
	if err := proto.Unmarshal(msg.Value, &result); err != nil {
		cs.log.Warn("skipping malformed endpoint result", "error", err)
		return nil
	}
	if !verifyEndpointResult(ctx, cs.binding, cs.strict, laneTenant, &result, cs.log) {
		return nil
	}
	view := endpoint.ResultView{
		Type: result.GetCanaryType(), Target: result.GetServerAddress(), Success: result.GetSuccess(),
		Error: result.GetErrorMessage(), Metrics: result.GetMetrics(), Attributes: result.GetAttributes(),
		ObservedAt: time.Unix(0, result.GetStartTimeUnixNano()),
	}
	var writeErr error
	for attempt := 0; attempt <= cs.retries; attempt++ {
		writeErr = cs.store.Persist(ctx, result.GetTenantId(), result.GetAgentId(), view)
		if writeErr == nil {
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if attempt < cs.retries {
			delay := cs.baseDelay << attempt
			delay += time.Duration(rand.Int64N(int64(delay)/2 + 1))
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			case <-timer.C:
			}
		}
	}
	if err := cs.bus.Publish(ctx, bus.DeadLetterResultsTopic, msg.Key, msg.Value); err != nil {
		cs.log.Error("ENDPOINT EVENT LOST: durable store and DLQ failed",
			"tenant_id", result.GetTenantId(), "agent_id", result.GetAgentId(),
			"write_error", writeErr.Error(), "dlq_error", err.Error())
		return fmt.Errorf("endpoint durable write: %w", writeErr)
	}
	cs.log.Error("endpoint event durable write exhausted retries; dead-lettered",
		"tenant_id", result.GetTenantId(), "agent_id", result.GetAgentId(), "error", writeErr.Error())
	return nil
}

func verifyEndpointResult(ctx context.Context, binding pipeline.TenantBinding, strict bool, laneTenant string, result *resultv1.Result, log *slog.Logger) bool {
	tenant, overwritten, err := pipeline.VerifyBatchTenantStrict(ctx, binding, laneTenant, strict,
		[]pipeline.Identity{{Tenant: result.GetTenantId(), Agent: result.GetAgentId()}})
	if err != nil {
		log.Error("REJECTED endpoint result: tenant verification failed",
			"claimed_tenant", result.GetTenantId(), "agent_id", result.GetAgentId(),
			"lane_tenant", laneTenant, "error", err.Error())
		return false
	}
	if overwritten {
		log.Warn("endpoint result tenant overwritten by authoritative lane",
			"claimed_tenant", result.GetTenantId(), "lane_tenant", tenant)
	}
	result.TenantId = tenant
	return true
}

// WithEndpointViews attaches the snapshot store backing GET /v1/endpoints.
// nil is a no-op (the endpoint reports collector_running=false). Returns the
// server for chaining.
func (s *Server) WithEndpointViews(es endpoint.ViewReader) *Server {
	if es != nil {
		s.endpointViews = es
	}
	return s
}

// handleListEndpoints serves GET /v1/endpoints — the tenant's DEM fleet:
// per-endpoint WiFi/gateway/last-mile health and the slowdown attribution,
// impaired endpoints first. collector_running=false distinguishes an unwired
// consumer from an empty fleet.
func (s *Server) handleListEndpoints(w http.ResponseWriter, r *http.Request) error {
	tid, err := s.principalTenant(r)
	if err != nil {
		return err
	}
	if s.endpointViews == nil {
		writeJSON(w, http.StatusOK, map[string]any{"items": []endpoint.View{}, "collector_running": false})
		return nil
	}
	filter, ferr := (endpoint.ListFilter{
		Query: r.URL.Query().Get("q"),
		Cause: r.URL.Query().Get("cause"),
	}).Normalize()
	if ferr != nil {
		return apierror.Validation(ferr.Error())
	}
	items, ferr := s.endpointViews.ListFilteredContext(r.Context(), tid, filter)
	if ferr != nil {
		s.log.Warn("endpoint durable read failed", "tenant_id", tid, "error", ferr)
		return apierror.Unavailable("endpoint inventory store unavailable")
	}
	if items == nil {
		items = []endpoint.View{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "collector_running": true})
	return nil
}
