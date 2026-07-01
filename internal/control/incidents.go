// SPDX-License-Identifier: LicenseRef-probectl-TBD

package control

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/protobuf/proto"

	"github.com/imfeelingtheagi/probectl/internal/alert"
	"github.com/imfeelingtheagi/probectl/internal/apierror"
	"github.com/imfeelingtheagi/probectl/internal/bus"
	bgpv1 "github.com/imfeelingtheagi/probectl/internal/gen/probectl/bgp/v1"
	"github.com/imfeelingtheagi/probectl/internal/incident"
	"github.com/imfeelingtheagi/probectl/internal/pipeline"
	"github.com/imfeelingtheagi/probectl/internal/store"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
)

// pgIncidentStore implements incident.Store over Postgres, scoping every
// operation to the signal's tenant through the RLS choke point.
type pgIncidentStore struct {
	pool *pgxpool.Pool
}

type pgIncidentTxStore struct {
	scope tenancy.Scope
}

func (p pgIncidentStore) OpenIncidents(ctx context.Context, tenant string) ([]*incident.Incident, error) {
	var out []*incident.Incident
	err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenant)), p.pool,
		func(c context.Context, sc tenancy.Scope) error {
			rs, e := store.Incidents{}.OpenIncidents(c, sc)
			for i := range rs {
				v := rs[i]
				out = append(out, &v)
			}
			return e
		})
	return out, err
}

func (p pgIncidentTxStore) OpenIncidents(ctx context.Context, tenant string) ([]*incident.Incident, error) {
	if err := p.requireTenant(tenant); err != nil {
		return nil, err
	}
	rs, err := store.Incidents{}.OpenIncidents(ctx, p.scope)
	if err != nil {
		return nil, err
	}
	out := make([]*incident.Incident, 0, len(rs))
	for i := range rs {
		v := rs[i]
		out = append(out, &v)
	}
	return out, nil
}

func (p pgIncidentStore) Create(ctx context.Context, inc *incident.Incident) (*incident.Incident, error) {
	var created *incident.Incident
	err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(inc.TenantID)), p.pool,
		func(c context.Context, sc tenancy.Scope) error {
			x, e := store.Incidents{}.Create(c, sc, *inc)
			created = x
			return e
		})
	return created, err
}

func (p pgIncidentTxStore) Create(ctx context.Context, inc *incident.Incident) (*incident.Incident, error) {
	if inc == nil {
		return nil, fmt.Errorf("incident transaction store: nil incident")
	}
	if err := p.requireTenant(inc.TenantID); err != nil {
		return nil, err
	}
	return store.Incidents{}.Create(ctx, p.scope, *inc)
}

func (p pgIncidentStore) AppendSignal(ctx context.Context, tenant, incidentID string, sig incident.Signal) (*incident.Incident, error) {
	var updated *incident.Incident
	err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenant)), p.pool,
		func(c context.Context, sc tenancy.Scope) error {
			x, e := store.Incidents{}.AppendSignal(c, sc, incidentID, sig)
			updated = x
			return e
		})
	return updated, err
}

func (p pgIncidentTxStore) AppendSignal(ctx context.Context, tenant, incidentID string, sig incident.Signal) (*incident.Incident, error) {
	if err := p.requireTenant(tenant); err != nil {
		return nil, err
	}
	return store.Incidents{}.AppendSignal(ctx, p.scope, incidentID, sig)
}

func (p pgIncidentTxStore) requireTenant(tenant string) error {
	if tenant != p.scope.Tenant.String() {
		return fmt.Errorf("incident transaction store: tenant mismatch %q != %q", tenant, p.scope.Tenant.String())
	}
	return nil
}

func (p pgIncidentStore) WithTenantCorrelationLock(ctx context.Context, tenant string, fn func(context.Context, incident.Store) error) error {
	return tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenant)), p.pool,
		func(c context.Context, sc tenancy.Scope) error {
			if _, err := sc.Q.Exec(c,
				`SELECT pg_advisory_xact_lock(hashtextextended('incident:'||$1::text, 0))`,
				tenant); err != nil {
				return fmt.Errorf("lock incident correlation: %w", err)
			}
			return fn(c, pgIncidentTxStore{scope: sc})
		})
}

// BuildCorrelator constructs the Postgres-backed incident correlator. Optional
// incident.Options (e.g. incident.WithObserver for S33 on-call/ITSM dispatch) are
// passed through.
func BuildCorrelator(pool *pgxpool.Pool, window time.Duration, log *slog.Logger, opts ...incident.Option) *incident.Correlator {
	return incident.NewCorrelator(pgIncidentStore{pool: pool}, window, log, opts...)
}

// --- signal mappers (plane-native event → generic Signal) ---

// AlertSink returns an alert sink that correlates each fired/resolved alert into
// an incident. A correlation failure is logged, never fatal.
func AlertSink(c *incident.Correlator, log *slog.Logger) func(context.Context, alert.Alert) {
	return func(ctx context.Context, a alert.Alert) {
		if _, err := c.Ingest(ctx, signalFromAlert(a)); err != nil {
			log.Warn("correlate alert into incident failed", "rule", a.RuleName, "error", err)
		}
	}
}

func signalFromAlert(a alert.Alert) incident.Signal {
	return incident.Signal{
		TenantID:   a.TenantID,
		Plane:      "network",
		Kind:       "alert." + string(a.State),
		Severity:   incident.Severity(a.Severity),
		Title:      fmt.Sprintf("%s %s", a.RuleName, a.State),
		Summary:    a.Reason,
		Target:     a.Labels["server_address"],
		OccurredAt: a.At,
		Attributes: map[string]string{
			"metric":  a.Metric,
			"rule_id": a.RuleID,
			"value":   strconv.FormatFloat(a.Value, 'g', -1, 64),
		},
	}
}

func signalFromBGPEvent(e *bgpv1.BGPEvent) incident.Signal {
	occurred := time.Now()
	if ns := e.GetDetectedAtUnixNano(); ns > 0 {
		occurred = time.Unix(0, ns)
	}
	return incident.Signal{
		TenantID:   e.GetTenantId(),
		Plane:      "bgp",
		Kind:       "bgp." + bgpKind(e.GetEventType()),
		Severity:   bgpSeverity(e.GetSeverity()),
		Title:      e.GetMessage(),
		Target:     e.GetPrefix(),
		Prefix:     e.GetPrefix(),
		OccurredAt: occurred,
		Attributes: map[string]string{
			"collector":      e.GetCollector(),
			"new_origin_asn": strconv.FormatUint(uint64(e.GetNewOriginAsn()), 10),
			"rpki_status":    e.GetRpkiStatus().String(),
		},
	}
}

func bgpKind(t bgpv1.EventType) string {
	switch t {
	case bgpv1.EventType_EVENT_TYPE_ORIGIN_CHANGE:
		return "origin_change"
	case bgpv1.EventType_EVENT_TYPE_POSSIBLE_HIJACK:
		return "possible_hijack"
	case bgpv1.EventType_EVENT_TYPE_POSSIBLE_LEAK:
		return "possible_leak"
	case bgpv1.EventType_EVENT_TYPE_RPKI_INVALID:
		return "rpki_invalid"
	default:
		return "unknown"
	}
}

func bgpSeverity(s bgpv1.Severity) incident.Severity {
	switch s {
	case bgpv1.Severity_SEVERITY_CRITICAL:
		return incident.SeverityCritical
	case bgpv1.Severity_SEVERITY_WARNING:
		return incident.SeverityWarning
	default:
		return incident.SeverityInfo
	}
}

// BGPIncidentConsumer subscribes to probectl.bgp.events and correlates each event
// into an incident (the BGP plane feeding the unified timeline).
type BGPIncidentConsumer struct {
	bus        bus.Bus
	correlator *incident.Correlator
	log        *slog.Logger
	nsTenants  map[string]string
}

// NewBGPIncidentConsumer builds the consumer.
func NewBGPIncidentConsumer(b bus.Bus, c *incident.Correlator, log *slog.Logger) *BGPIncidentConsumer {
	if log == nil {
		log = slog.Default()
	}
	return &BGPIncidentConsumer{bus: b, correlator: c, log: log}
}

// WithNamespaceTenants subscribes BGP incident correlation to siloed tenant lanes.
func (cs *BGPIncidentConsumer) WithNamespaceTenants(ns map[string]string) *BGPIncidentConsumer {
	cs.nsTenants = ns
	return cs
}

// LaneFanoutEnabled satisfies pipeline.LaneFanout (CORRECT-005 coverage gate).
func (cs *BGPIncidentConsumer) LaneFanoutEnabled() bool { return true }

// Run subscribes until ctx is canceled.
func (cs *BGPIncidentConsumer) Run(ctx context.Context) error {
	return pipeline.RunLanes(ctx, cs.bus, bus.BGPEventsTopic, "incident-correlator", cs.nsTenants, cs.handleLane)
}

func (cs *BGPIncidentConsumer) handleLane(ctx context.Context, msg bus.Message, laneTenant string) error {
	var ev bgpv1.BGPEvent
	if err := proto.Unmarshal(msg.Value, &ev); err != nil {
		cs.log.Warn("skipping malformed bgp event", "error", err)
		return nil
	}
	if _, err := bindBGPEventAuthenticatedTenant(&ev, msg, laneTenant); err != nil {
		cs.log.Error("REJECTED bgp event: tenant envelope rejected (RED-005, fail closed)",
			"key_tenant", string(msg.Key), "lane_tenant", laneTenant, "payload_tenant", ev.GetTenantId(), "error", err.Error())
		return nil
	}
	if _, err := cs.correlator.Ingest(ctx, signalFromBGPEvent(&ev)); err != nil {
		cs.log.Warn("correlate bgp event into incident failed", "error", err)
		return fmt.Errorf("bgp incident correlation: %w", err)
	}
	return nil
}

// --- /v1/incidents handlers ---

func (s *Server) handleListIncidents(w http.ResponseWriter, r *http.Request) error {
	var incs []incident.Incident
	if err := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
		x, e := store.Incidents{}.List(ctx, sc)
		incs = x
		return e
	}); err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": incs})
	return nil
}

func (s *Server) handleGetIncident(w http.ResponseWriter, r *http.Request) error {
	id := r.PathValue("id")
	var inc *incident.Incident
	if err := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
		x, e := store.Incidents{}.Get(ctx, sc, id)
		inc = x
		return e
	}); err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, inc)
	return nil
}

type incidentPatch struct {
	Status string `json:"status"`
}

func (s *Server) handlePatchIncident(w http.ResponseWriter, r *http.Request) error {
	id := r.PathValue("id")
	var req incidentPatch
	if err := decodeJSON(r, &req); err != nil {
		return err
	}
	if req.Status != string(incident.StatusResolved) {
		return apierror.Validation("status must be \"resolved\"")
	}
	var inc *incident.Incident
	if err := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
		x, e := store.Incidents{}.Resolve(ctx, sc, id)
		if e != nil {
			return e
		}
		inc = x
		return s.recordAudit(ctx, sc, r, "incident.resolve", id, nil)
	}); err != nil {
		return err
	}
	// Sync the resolution to on-call/ITSM connectors (S33). Source "api" matches no
	// connector, so every linked system is resolved (the inbound path uses the
	// provider name as the source to avoid echoing back to its origin).
	if inc != nil && s.dispatcher != nil {
		s.dispatcher.Resolved(r.Context(), *inc, "api")
	}
	writeJSON(w, http.StatusOK, inc)
	return nil
}
