// SPDX-License-Identifier: LicenseRef-probectl-TBD

package control

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/imfeelingtheagi/probectl/internal/apierror"
	"github.com/imfeelingtheagi/probectl/internal/bus"
	"github.com/imfeelingtheagi/probectl/internal/endpoint"
	resultv1 "github.com/imfeelingtheagi/probectl/internal/gen/probectl/result/v1"
)

// Endpoint DEM read model (S-FE4 surface for S37): a consumer on
// probectl.endpoint.results retains each endpoint's latest DEM state in the
// snapshot store, and GET /v1/endpoints serves the caller's tenant partition.
// Privacy is upstream and absolute — fields the agent withheld are absent in
// the results and therefore absent here; nothing re-derives them.

// EndpointViewConsumer feeds the snapshot store from the endpoint result topic
// (its own consumer group, independent of the S37 TSDB pipeline).
type EndpointViewConsumer struct {
	bus   bus.Bus
	store *endpoint.SnapshotStore
	log   *slog.Logger
}

// NewEndpointViewConsumer builds the consumer.
func NewEndpointViewConsumer(b bus.Bus, store *endpoint.SnapshotStore, log *slog.Logger) *EndpointViewConsumer {
	if log == nil {
		log = slog.Default()
	}
	return &EndpointViewConsumer{bus: b, store: store, log: log}
}

// Run consumes until ctx is done. Malformed messages are dropped (untrusted
// input never wedges the consumer).
func (cs *EndpointViewConsumer) Run(ctx context.Context) error {
	// Pure in-RAM view → per-replica fan-in for coherence (ARCH-003).
	return cs.bus.Subscribe(ctx, bus.EndpointResultsTopic, viewGroup("endpoint-view"),
		func(_ context.Context, msg bus.Message) error {
			var r resultv1.Result
			if err := proto.Unmarshal(msg.Value, &r); err != nil {
				cs.log.Warn("skipping malformed endpoint result", "error", err)
				return nil
			}
			cs.store.Record(r.GetTenantId(), r.GetAgentId(), endpoint.ResultView{
				Type:       r.GetCanaryType(),
				Target:     r.GetServerAddress(),
				Success:    r.GetSuccess(),
				Error:      r.GetErrorMessage(),
				Metrics:    r.GetMetrics(),
				Attributes: r.GetAttributes(),
				ObservedAt: time.Unix(0, r.GetStartTimeUnixNano()),
			})
			return nil
		})
}

// WithEndpointViews attaches the snapshot store backing GET /v1/endpoints.
// nil is a no-op (the endpoint reports collector_running=false). Returns the
// server for chaining.
func (s *Server) WithEndpointViews(es *endpoint.SnapshotStore) *Server {
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
	items, ferr := s.endpointViews.ListFiltered(tid, endpoint.ListFilter{
		Query: r.URL.Query().Get("q"),
		Cause: r.URL.Query().Get("cause"),
	})
	if ferr != nil {
		return apierror.Validation(ferr.Error())
	}
	if items == nil {
		items = []endpoint.View{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "collector_running": true})
	return nil
}
