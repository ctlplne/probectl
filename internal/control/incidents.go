// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/protobuf/proto"

	"github.com/ctlplne/probectl/internal/alert"
	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/bus"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/entity"
	bgpv1 "github.com/ctlplne/probectl/internal/gen/probectl/bgp/v1"
	"github.com/ctlplne/probectl/internal/incident"
	"github.com/ctlplne/probectl/internal/path"
	"github.com/ctlplne/probectl/internal/pipeline"
	"github.com/ctlplne/probectl/internal/siem"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// pgIncidentStore implements incident.Store over Postgres, scoping every
// operation to the signal's tenant through the RLS choke point.
type pgIncidentStore struct {
	pool *pgxpool.Pool
}

type pgIncidentTxStore struct {
	scope tenancy.Scope
}

// ClaimFaultReceipt runs inside the tenant's advisory-locked correlation
// transaction. A completed claim returns its original incident, including
// after that incident is resolved. The unique key is scoped by tenant and the
// mTLS-derived agent; conflicting reuse of one UUID is rejected.
func (p pgIncidentTxStore) ClaimFaultReceipt(ctx context.Context,
	source incident.AuthenticatedIdentitySource, observationID string,
	sig incident.Signal) (*incident.Incident, error) {
	if err := p.requireTenant(source.TenantID()); err != nil {
		return nil, err
	}
	// The preliminary RPC identity lookup is outside this transaction. Lock
	// the exact issued sender row here, before a receipt or incident write, so
	// concurrent revocation serializes with the fault. An old observation
	// cannot be authenticated by a certificate issued after it occurred.
	var issued int
	err := p.scope.Q.QueryRow(ctx, `SELECT 1 FROM agent_identities i
		WHERE i.tenant_id=$1 AND i.agent_id=$2 AND i.serial=$3
		  AND i.spiffe_id=$4 AND i.revoked_at IS NULL
		  AND i.issued_at<=$5 AND i.not_after>$5
		  AND i.not_after>statement_timestamp()
		  AND NOT EXISTS (SELECT 1 FROM agent_identities revoked
		      WHERE revoked.tenant_id=i.tenant_id AND revoked.agent_id=i.agent_id
		        AND revoked.revoked_at IS NOT NULL
		        AND revoked.revoked_by IS DISTINCT FROM 'entity_registry_delete')
		FOR SHARE OF i`, source.TenantID(), source.AgentID(),
		source.CertificateSerial(),
		crypto.EntitySPIFFEID(source.TenantID(), source.AgentID()),
		sig.OccurredAt).Scan(&issued)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, incident.ErrFaultIdentityInactive
	}
	if err != nil {
		return nil, fmt.Errorf("check entity fault sender: %w", err)
	}
	// A sender certificate proves an agent, not authority over every source
	// name it can put in an RPC. Require a current operator assignment for
	// this exact source at both observation and ingest time. Hold its rows
	// through correlation so a concurrent removal cannot authorize a fault.
	var assigned int
	err = p.scope.Q.QueryRow(ctx, `SELECT 1 FROM entity_source_contexts m
		JOIN entity_agent_contexts a ON
		 (a.tenant_id,a.agent_id,a.context_id)=(m.tenant_id,m.agent_id,m.context_id)
		WHERE m.tenant_id=$1 AND m.agent_id=$2
		  AND m.source_kind=$3 AND m.source_ref=$4
		  AND m.assigned_at<=$5 AND m.assigned_at<=statement_timestamp()
		  AND (m.expires_at IS NULL OR
		       (m.expires_at>$5 AND m.expires_at>statement_timestamp()))
		  AND a.assigned_at<=$5 AND a.assigned_at<=statement_timestamp()
		  AND (a.expires_at IS NULL OR
		       (a.expires_at>$5 AND a.expires_at>statement_timestamp()))
		FOR SHARE OF m,a`, source.TenantID(), source.AgentID(),
		source.SourceKind(), source.SourceRef(), sig.OccurredAt).Scan(&assigned)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, incident.ErrFaultSourceInactive
	}
	if err != nil {
		return nil, fmt.Errorf("check entity fault source: %w", err)
	}
	tag, err := p.scope.Q.Exec(ctx,
		`INSERT INTO entity_fault_receipts
		 (tenant_id,agent_id,observation_id,source_kind,source_ref,payload_fingerprint)
		 VALUES ($1,$2,$3::uuid,$4,$5,$6)
		 ON CONFLICT (tenant_id,agent_id,observation_id) DO NOTHING`,
		source.TenantID(), source.AgentID(), observationID,
		source.SourceKind(), source.SourceRef(), sig.Fingerprint())
	if err != nil {
		return nil, fmt.Errorf("claim entity fault receipt: %w", err)
	}
	if tag.RowsAffected() == 1 {
		return nil, nil
	}
	var kind, ref, fingerprint string
	var incidentID *string
	if err := p.scope.Q.QueryRow(ctx,
		`SELECT source_kind,source_ref,payload_fingerprint,incident_id::text
		 FROM entity_fault_receipts
		 WHERE tenant_id=$1 AND agent_id=$2 AND observation_id=$3::uuid`,
		source.TenantID(), source.AgentID(), observationID).
		Scan(&kind, &ref, &fingerprint, &incidentID); err != nil {
		return nil, fmt.Errorf("read entity fault receipt: %w", err)
	}
	if kind != source.SourceKind() || ref != source.SourceRef() ||
		fingerprint != sig.Fingerprint() {
		return nil, incident.ErrFaultObservationConflict
	}
	if incidentID == nil {
		return nil, errors.New("entity fault receipt has no committed incident")
	}
	return (store.Incidents{}).Get(ctx, p.scope, *incidentID)
}

func (p pgIncidentTxStore) CompleteFaultReceipt(ctx context.Context,
	source incident.AuthenticatedIdentitySource, observationID, incidentID string) error {
	if err := p.requireTenant(source.TenantID()); err != nil {
		return err
	}
	tag, err := p.scope.Q.Exec(ctx,
		`UPDATE entity_fault_receipts SET incident_id=$4::uuid
		 WHERE tenant_id=$1 AND agent_id=$2 AND observation_id=$3::uuid
		   AND incident_id IS NULL`,
		source.TenantID(), source.AgentID(), observationID, incidentID)
	if err != nil {
		return fmt.Errorf("complete entity fault receipt: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return errors.New("entity fault receipt was not completed exactly once")
	}
	return nil
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

func (p pgIncidentStore) ActiveCorrelationOverrides(ctx context.Context, tenant string, sig incident.Signal) ([]incident.CorrelationOverride, error) {
	var out []incident.CorrelationOverride
	err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenant)), p.pool,
		func(c context.Context, sc tenancy.Scope) error {
			x, e := (store.Incidents{}).ActiveCorrelationOverrides(c, sc, sig)
			out = x
			return e
		})
	return out, err
}

func (p pgIncidentTxStore) ActiveCorrelationOverrides(ctx context.Context, tenant string, sig incident.Signal) ([]incident.CorrelationOverride, error) {
	if err := p.requireTenant(tenant); err != nil {
		return nil, err
	}
	return (store.Incidents{}).ActiveCorrelationOverrides(ctx, p.scope, sig)
}

func (p pgIncidentTxStore) requireTenant(tenant string) error {
	if tenant != p.scope.Tenant.String() {
		return fmt.Errorf("incident transaction store: tenant mismatch %q != %q", tenant, p.scope.Tenant.String())
	}
	return nil
}

// ResolveSignalIdentity runs under the incident advisory lock and the same
// FORCE-RLS transaction as correlation. Only an mTLS-authenticated source may
// enter this path; the source assignment, exact SVID serial and current
// evidence are all rechecked here. A missing/ambiguous address retains only
// its verified routing context, which suppresses raw RFC1918 matching.
func (p pgIncidentTxStore) ResolveSignalIdentity(ctx context.Context,
	source incident.AuthenticatedIdentitySource, sig incident.Signal) (incident.IdentityResolution, error) {
	if err := p.requireTenant(source.TenantID()); err != nil {
		return incident.IdentityResolution{}, err
	}
	if err := p.requireTenant(sig.TenantID); err != nil {
		return incident.IdentityResolution{}, err
	}
	key, err := (entity.SourceKey{AgentID: source.AgentID(),
		Kind: entity.SourceKind(source.SourceKind()), SourceRef: source.SourceRef()}).Normalize()
	if err != nil {
		return incident.IdentityResolution{}, err
	}
	var contextID string
	err = p.scope.Q.QueryRow(ctx, `SELECT m.context_id::text
		FROM entity_source_contexts m
		JOIN entity_agent_contexts a ON
		 (a.tenant_id,a.agent_id,a.context_id)=(m.tenant_id,m.agent_id,m.context_id)
		JOIN agent_identities sender ON
		 (sender.tenant_id,sender.agent_id)=(m.tenant_id,m.agent_id)
		WHERE m.tenant_id=$1 AND m.agent_id=$2
		  AND m.source_kind=$3 AND m.source_ref=$4
		  AND sender.serial=$5 AND sender.spiffe_id=$6
		  AND sender.revoked_at IS NULL
		  AND sender.issued_at<= $7 AND sender.not_after>$7
		  AND sender.not_after>statement_timestamp()
		  AND m.assigned_at<= $7 AND m.assigned_at<=statement_timestamp()
		  AND (m.expires_at IS NULL OR
		       (m.expires_at>$7 AND m.expires_at>statement_timestamp()))
		  AND a.assigned_at<= $7 AND a.assigned_at<=statement_timestamp()
		  AND (a.expires_at IS NULL OR
		       (a.expires_at>$7 AND a.expires_at>statement_timestamp()))
		  AND NOT EXISTS (SELECT 1 FROM agent_identities revoked
		      WHERE revoked.tenant_id=m.tenant_id AND revoked.agent_id=m.agent_id
		        AND revoked.revoked_at IS NOT NULL
		        AND revoked.revoked_by IS DISTINCT FROM 'entity_registry_delete')
		FOR SHARE OF m,a,sender`, sig.TenantID, key.AgentID,
		string(key.Kind), key.SourceRef, source.CertificateSerial(),
		crypto.EntitySPIFFEID(sig.TenantID, key.AgentID), sig.OccurredAt).Scan(&contextID)
	if err == pgx.ErrNoRows {
		return incident.IdentityResolution{}, nil
	}
	if err != nil {
		return incident.IdentityResolution{}, err
	}
	identity := incident.IdentityResolution{ContextID: contextID}
	host := path.TargetHost(sig.Target)
	alias, err := (entity.AliasKey{Kind: entity.AddressAlias, Value: host}).Normalize()
	if err != nil {
		return identity, nil // a prefix/DNS target has no address join
	}
	resolution, err := store.ResolveAliasInScope(ctx, p.scope,
		entity.Scope{TenantID: sig.TenantID, ContextID: contextID}, alias)
	if err != nil {
		return identity, err
	}
	if resolution.Status == entity.Resolved {
		// A unique address elsewhere in this VRF is not proof that this
		// authenticated producer observed that device. Require a current row
		// from this exact source and evidence SVID before using the canonical
		// ID for correlation. The broader alias resolver already proved that
		// the address has exactly one current entity in this tenant/context.
		// The source check shares the resolver's parent-device projection and
		// current independent-support rules, then locks that exact evidence
		// row through the correlation commit. A stale reanchored or inferred
		// row cannot borrow another sender's current address claim.
		fromSender, err := store.CurrentSourceAddressInScope(ctx, p.scope,
			entity.Scope{TenantID: sig.TenantID, ContextID: contextID}, alias,
			key, source.CertificateSerial(), resolution.EntityID, sig.OccurredAt)
		if err != nil {
			return identity, err
		}
		if fromSender {
			identity.EntityID = resolution.EntityID
		}
	}
	return identity, nil
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
	target := a.Labels["server_address"]
	plane := "network"
	if a.Metric == alert.TrapMetric {
		plane = "device"
		if target == "" {
			// Authenticated trap alerts identify their source in the device label.
			// Keep that address as the tenant-scoped correlation target.
			target = a.Labels["device"]
		}
	}
	if a.Metric == alert.QueryMetric {
		plane = "flow"
		target = "query:" + a.RuleID + ":" + a.Labels["query_group"]
	}
	attributes := map[string]string{
		"metric": a.Metric, "rule_id": a.RuleID,
		"value": strconv.FormatFloat(a.Value, 'g', -1, 64),
	}
	if a.Metric == alert.QueryMetric {
		attributes["query_group"] = a.Labels["query_group"]
		attributes["query_view_id"] = a.Labels["query_view_id"]
	}
	return incident.Signal{
		TenantID:   a.TenantID,
		Plane:      plane,
		Kind:       "alert." + string(a.State),
		Severity:   incident.Severity(a.Severity),
		Title:      fmt.Sprintf("%s %s", a.RuleName, a.State),
		Summary:    a.Reason,
		Target:     target,
		OccurredAt: a.At,
		Attributes: attributes,
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
		Attributes: bgpSignalAttributes(e),
	}
}

// bgpSignalAttributes carries the detection context the analyzer produced
// onto the tenant's event read model (DPR-057): confidence, the configured
// expected origins, the previous origin and the observed path used to be
// visible only inside the title text.
func bgpSignalAttributes(e *bgpv1.BGPEvent) map[string]string {
	attrs := map[string]string{
		"collector":      e.GetCollector(),
		"new_origin_asn": strconv.FormatUint(uint64(e.GetNewOriginAsn()), 10),
		"rpki_status":    e.GetRpkiStatus().String(),
		"confidence":     strconv.FormatFloat(e.GetConfidence(), 'f', 2, 64),
	}
	if asn := e.GetOldOriginAsn(); asn != 0 {
		attrs["old_origin_asn"] = strconv.FormatUint(uint64(asn), 10)
	}
	if origins := e.GetExpectedOrigins(); len(origins) > 0 {
		attrs["expected_origins"] = joinASNs(origins)
	}
	if path := e.GetNewAsPath(); len(path) > 0 {
		attrs["new_as_path"] = joinASNs(path)
	}
	if asn := e.GetPeerAsn(); asn != 0 {
		attrs["peer_asn"] = strconv.FormatUint(uint64(asn), 10)
	}
	if addr := e.GetPeerAddress(); addr != "" {
		attrs["peer_address"] = addr
	}
	return attrs
}

func joinASNs(asns []uint32) string {
	parts := make([]string, 0, len(asns))
	for _, a := range asns {
		parts = append(parts, strconv.FormatUint(uint64(a), 10))
	}
	return strings.Join(parts, ",")
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
	case bgpv1.EventType_EVENT_TYPE_ROUTE_OBSERVATION:
		return "route_observation"
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
	siem       *siem.Forwarder // DPR-079: routing signals are exported like every other threat-plane signal
	log        *slog.Logger
	nsTenants  map[string]string
	// strictLane (RTP-02, WIRE-001, AUTHZ-11): refuse BGP events on the shared
	// pooled lane, where the tenant is carried only by the forgeable message
	// key. The namespaced lane is the authoritative path. fail closed.
	strictLane bool
}

// NewBGPIncidentConsumer builds the consumer.
func NewBGPIncidentConsumer(b bus.Bus, c *incident.Correlator, log *slog.Logger) *BGPIncidentConsumer {
	if log == nil {
		log = slog.Default()
	}
	return &BGPIncidentConsumer{bus: b, correlator: c, log: log}
}

// WithNamespaceTenants subscribes BGP incident correlation to siloed tenant lanes.
// WithSIEM forwards every routing signal (possible_hijack, possible_leak,
// rpki_invalid, origin_change) to the SIEM (DPR-079). Before this the journey's
// "export the incident to your SIEM" held for NDR, IOC, TLS and segmentation
// signals but a BGP hijack — the headline routing threat — never left the
// incident timeline. nil disables it.
func (cs *BGPIncidentConsumer) WithSIEM(fw *siem.Forwarder) *BGPIncidentConsumer {
	cs.siem = fw
	return cs
}

func (cs *BGPIncidentConsumer) WithNamespaceTenants(ns map[string]string) *BGPIncidentConsumer {
	cs.nsTenants = ns
	return cs
}

// WithStrictTenantLanes refuses BGP events on the shared pooled lane (RTP-02,
// WIRE-001, AUTHZ-11), requiring the tenant-namespaced lane.
func (cs *BGPIncidentConsumer) WithStrictTenantLanes(strict bool) *BGPIncidentConsumer {
	cs.strictLane = strict
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
	if _, err := bindBGPEventAuthenticatedTenant(&ev, msg, laneTenant, cs.strictLane); err != nil {
		cs.log.Error("REJECTED bgp event: tenant envelope rejected (RED-005/AUTHZ-11, fail closed)",
			"key_tenant", string(msg.Key), "lane_tenant", laneTenant, "payload_tenant", ev.GetTenantId(), "error", err.Error())
		return nil
	}
	if ev.GetEventType() == bgpv1.EventType_EVENT_TYPE_ROUTE_OBSERVATION {
		// ING-17: a plain route announcement (origin unchanged from baseline) is an
		// observation, not a detection. It must never open an incident or page the
		// SIEM (docs/guardrails.md G7-9: detection is a scored, tunable signal — not
		// noise). Genuine routing anomalies (origin_change, possible_hijack,
		// possible_leak, rpki_invalid) still forward and correlate below.
		return nil
	}
	sig := signalFromBGPEvent(&ev)
	if cs.siem != nil {
		if err := cs.siem.Enqueue(ctx, signalToSIEM(sig)); err != nil {
			cs.log.Warn("bgp: forward routing signal to siem failed", "error", err, "tenant_id", sig.TenantID, "kind", sig.Kind)
		}
	}
	if _, err := cs.correlator.Ingest(ctx, sig); err != nil {
		cs.log.Warn("correlate bgp event into incident failed", "error", err)
		return fmt.Errorf("bgp incident correlation: %w", err)
	}
	return nil
}

// --- /v1/incidents handlers ---

func (s *Server) handleListIncidents(w http.ResponseWriter, r *http.Request) error {
	var incs []incident.Incident
	truncated := false
	if err := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
		x, more, e := store.Incidents{}.List(ctx, sc, store.DefaultIncidentListLimit)
		incs, truncated = x, more
		return e
	}); err != nil {
		return err
	}
	// DPR-151: say when the list is the FIRST N rather than all of them. A
	// correlation surface that silently stops at a bound reports a complete
	// picture of a tenant's incidents that is not complete.
	writeJSON(w, http.StatusOK, map[string]any{
		"items":               incs,
		"correlation_running": s.correlationActive,
		"effective_limit":     store.DefaultIncidentListLimit,
		"truncated":           truncated,
	})
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
	if req.Status != string(incident.StatusResolved) && req.Status != string(incident.StatusOpen) {
		return apierror.Validation("status must be \"resolved\" or \"open\"")
	}
	var inc *incident.Incident
	action := "incident.resolve"
	if req.Status == string(incident.StatusOpen) {
		action = "incident.reopen"
	}
	if err := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
		var x *incident.Incident
		var e error
		if req.Status == string(incident.StatusOpen) {
			x, e = (store.Incidents{}).Reopen(ctx, sc, id)
		} else {
			x, e = (store.Incidents{}).Resolve(ctx, sc, id)
		}
		if e != nil {
			return e
		}
		inc = x
		return s.recordAudit(ctx, sc, r, action, id, nil)
	}); err != nil {
		return err
	}
	// Sync the resolution to on-call/ITSM connectors (S33). Source "api" matches no
	// connector, so every linked system is resolved (the inbound path uses the
	// provider name as the source to avoid echoing back to its origin).
	if inc != nil && s.dispatcher != nil {
		if inc.Status == incident.StatusOpen {
			s.dispatcher.Reopened(r.Context(), *inc)
		} else {
			s.dispatcher.Resolved(r.Context(), *inc, "api")
		}
	}
	writeJSON(w, http.StatusOK, inc)
	return nil
}

type incidentUngroupRequest struct {
	SignalID string `json:"signal_id"`
	Reason   string `json:"reason"`
}

// handleCreateIncidentCorrelationOverride detaches one signal shape from its
// current incident. The original evidence remains; a new independent incident
// is created and later matching signals exclude the source until reversal.
func (s *Server) handleCreateIncidentCorrelationOverride(w http.ResponseWriter, r *http.Request) error {
	incidentID := r.PathValue("id")
	var req incidentUngroupRequest
	if err := decodeJSON(r, &req); err != nil {
		return err
	}
	req.SignalID = strings.TrimSpace(req.SignalID)
	req.Reason = strings.TrimSpace(req.Reason)
	if req.SignalID == "" {
		return apierror.Validation("signal_id is required")
	}
	if req.Reason == "" || len(req.Reason) > 500 {
		return apierror.Validation("reason must be between 1 and 500 bytes")
	}
	var override *incident.CorrelationOverride
	var detached *incident.Incident
	if err := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
		var err error
		override, detached, err = (store.Incidents{}).CreateUngroupOverride(
			ctx, sc, incidentID, req.SignalID, req.Reason, auditActor(r))
		if err != nil {
			return err
		}
		return s.recordAudit(ctx, sc, r, "incident.correlation_override_create", override.ID, map[string]any{
			"source_incident_id":   incidentID,
			"source_signal_id":     req.SignalID,
			"detached_incident_id": detached.ID,
			"scope":                "exact_plane_kind_target_prefix",
		})
	}); err != nil {
		return err
	}
	writeJSON(w, http.StatusCreated, map[string]any{"override": override, "detached_incident": detached})
	return nil
}

type incidentOverrideReverseRequest struct {
	Reason string `json:"reason"`
}

func (s *Server) handleReverseIncidentCorrelationOverride(w http.ResponseWriter, r *http.Request) error {
	incidentID := r.PathValue("id")
	overrideID := r.PathValue("override_id")
	var req incidentOverrideReverseRequest
	if err := decodeJSON(r, &req); err != nil {
		return err
	}
	req.Reason = strings.TrimSpace(req.Reason)
	if req.Reason == "" || len(req.Reason) > 500 {
		return apierror.Validation("reason must be between 1 and 500 bytes")
	}
	var override *incident.CorrelationOverride
	if err := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
		var err error
		override, err = (store.Incidents{}).ReverseCorrelationOverride(
			ctx, sc, incidentID, overrideID, auditActor(r), req.Reason)
		if err != nil {
			return err
		}
		return s.recordAudit(ctx, sc, r, "incident.correlation_override_reverse", override.ID, map[string]any{
			"source_incident_id":   incidentID,
			"detached_incident_id": override.DetachedIncidentID,
		})
	}); err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, override)
	return nil
}
