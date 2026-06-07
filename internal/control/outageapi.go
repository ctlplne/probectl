package control

// Collective internet-outage view wiring (S47a, F19): public outage feeds
// (IODA / Cloudflare Radar — OPT-IN, shared, ingested once) joined with the
// customer's own vantage points (the synthetic-result stream) and served,
// tenant-correlated, at /v1/outages. probectl does not own a global probe
// fleet — coverage is the customer's vantages + open data, said plainly.

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/imfeelingtheagi/probectl/internal/bus"
	"github.com/imfeelingtheagi/probectl/internal/config"
	resultv1 "github.com/imfeelingtheagi/probectl/internal/gen/probectl/result/v1"
	"github.com/imfeelingtheagi/probectl/internal/incident"
	"github.com/imfeelingtheagi/probectl/internal/opendata"
	"github.com/imfeelingtheagi/probectl/internal/outage"
)

// BuildOutageFeeds builds the shared external-event store + refresher.
// Returns (nil, nil, false) unless feeds are EXPLICITLY enabled — enabling
// them makes outbound fetches to public APIs (sovereignty / no-phone-home:
// OFF by default, guardrail 2). The Radar feed additionally needs a token
// and is omitted (logged) without one.
func BuildOutageFeeds(cfg *config.Config, log *slog.Logger) (*outage.Store, *outage.Refresher, bool) {
	if cfg == nil || !cfg.OutageFeedsEnabled {
		return nil, nil, false
	}
	feeds := outage.NewFeeds(cfg.OutageFeeds, cfg.OutageRadarToken, nil) // nil → hardened-TLS default client
	if cfg.OutageRadarToken == "" {
		log.Info("outage feeds: cloudflare_radar omitted (no PROBECTL_OUTAGE_RADAR_TOKEN)")
	}
	if len(feeds) == 0 {
		log.Warn("outage feeds enabled but none could be built", "feeds", cfg.OutageFeeds)
		return nil, nil, false
	}
	store := outage.NewStore(cfg.OutageRetention)
	refresher := outage.NewRefresher(store, feeds, cfg.OutageRefresh, cfg.OutageRetention, log)
	log.Info("outage feeds enabled", "feeds", len(feeds), "refresh", cfg.OutageRefresh)
	return store, refresher, true
}

// BuildOutage builds the per-tenant vantage/correlation engine. store may be
// nil (feeds disabled — the customer's own vantage detection still works);
// enricher may be nil (scope resolution off, reported honestly). Local-only:
// the engine itself makes no outbound calls.
func BuildOutage(cfg *config.Config, store *outage.Store, enricher *opendata.Enricher, log *slog.Logger) (*outage.Engine, bool) {
	if cfg == nil || !cfg.OutageEnabled {
		return nil, false
	}
	var resolve outage.Resolver
	if enricher != nil {
		resolve = enricherResolver(enricher)
	} else if log != nil {
		log.Info("outage view: scope resolution off (no IP enricher) — vantage detection and impact correlation degraded")
	}
	return outage.NewEngine(store, resolve), true
}

// enricherResolver adapts the S15 open-data enricher into the outage scope
// join: ASN preferred, country fallback. Lookups are cached by the enricher.
func enricherResolver(en *opendata.Enricher) outage.Resolver {
	return func(ip string) (outage.Scope, bool) {
		if ip == "" {
			return outage.Scope{}, false
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		e, err := en.Enrich(ctx, ip)
		if err != nil {
			return outage.Scope{}, false
		}
		if e.ASN != 0 {
			return outage.Scope{Kind: outage.ScopeASN, Code: fmt.Sprintf("AS%d", e.ASN), Name: e.ASName}, true
		}
		if e.CountryCode != "" {
			return outage.Scope{Kind: outage.ScopeCountry, Code: e.CountryCode}, true
		}
		return outage.Scope{}, false
	}
}

// WithOutage attaches the engine backing /v1/outages. nil is a no-op (the
// endpoint reports outage_running=false).
func (s *Server) WithOutage(e *outage.Engine) *Server {
	if e != nil {
		s.outageEngine = e
	}
	return s
}

// WithOutageFeeds attaches the feed refresher so /v1/outages can report
// per-feed health + AUP provenance. nil is a no-op (feeds_enabled=false).
func (s *Server) WithOutageFeeds(r *outage.Refresher) *Server {
	if r != nil {
		s.outageFeeds = r
	}
	return s
}

// handleOutages serves GET /v1/outages — the collective view for the
// CALLER's tenant: shared external events annotated with this tenant's
// affected tests, the tenant's own vantage detections, feed health/AUP, and
// the coverage notes that keep the view honest.
func (s *Server) handleOutages(w http.ResponseWriter, r *http.Request) error {
	tid, err := s.principalTenant(r)
	if err != nil {
		return err
	}
	if s.outageEngine == nil {
		writeJSON(w, http.StatusOK, map[string]any{"outage_running": false})
		return nil
	}
	snap := s.outageEngine.Snapshot(tid)
	feedsEnabled := s.outageFeeds != nil
	resp := map[string]any{
		"outage_running":   true,
		"feeds_enabled":    feedsEnabled,
		"scope_resolution": snap.ScopeResolution,
		"events":           snap.Events,
		"vantage_events":   snap.Vantage,
		"coverage_notes":   outageCoverageNotes(feedsEnabled, snap.ScopeResolution),
	}
	if feedsEnabled {
		resp["feeds"] = s.outageFeeds.Health()
	}
	writeJSON(w, http.StatusOK, resp)
	return nil
}

// outageCoverageNotes states what the view can and cannot see (the S47a
// watch-out: never overclaim coverage vs a vendor-owned global fleet).
func outageCoverageNotes(feedsEnabled, scopeResolution bool) []string {
	notes := []string{
		"coverage = your vantage points + public open-data feeds — probectl does not operate a global probe fleet",
	}
	if !feedsEnabled {
		notes = append(notes, "external feeds are disabled (PROBECTL_OUTAGE_FEEDS_ENABLED) — the view shows only your own vantage detections")
	}
	if !scopeResolution {
		notes = append(notes, "IP→ASN/geo enrichment is off (PROBECTL_FLOW_ENRICH_ASN) — vantage detection and impact correlation are unavailable")
	}
	return notes
}

// OutageConsumer feeds the engine from the synthetic-result stream: every
// result is one vantage observation; signals (vantage-detected outages,
// external-outage correlations) land in the incident pipeline.
type OutageConsumer struct {
	engine     *outage.Engine
	bus        bus.Bus
	correlator *incident.Correlator
	log        *slog.Logger
}

// NewOutageConsumer builds the consumer over a non-nil engine.
func NewOutageConsumer(b bus.Bus, e *outage.Engine, c *incident.Correlator, log *slog.Logger) *OutageConsumer {
	if log == nil {
		log = slog.Default()
	}
	return &OutageConsumer{engine: e, bus: b, correlator: c, log: log}
}

// Run subscribes to the network-results topic (own consumer group) until ctx
// ends.
func (oc *OutageConsumer) Run(ctx context.Context) error {
	return oc.bus.Subscribe(ctx, bus.NetworkResultsTopic, "outage-vantage", oc.handle)
}

func (oc *OutageConsumer) handle(ctx context.Context, msg bus.Message) error {
	var r resultv1.Result
	if err := proto.Unmarshal(msg.Value, &r); err != nil {
		oc.log.Warn("outage: skipping malformed result", "error", err)
		return nil
	}
	return oc.SinkResult(ctx, &r)
}

// SinkResult observes one DECODED result (shared immutable — never mutated).
func (oc *OutageConsumer) SinkResult(ctx context.Context, r *resultv1.Result) error {
	tenant := r.GetTenantId()
	if tenant == "" {
		return nil // unscoped records are dropped (guardrail 1)
	}
	peer := r.GetAttributes()["network.peer.address"]
	if peer == "" {
		peer = peerHost(r.GetServerAddress())
	}
	sigs := oc.engine.Observe(tenant, r.GetCanaryType(), r.GetServerAddress(), peer,
		r.GetSuccess(), time.Unix(0, r.GetStartTimeUnixNano()))
	for _, sig := range sigs {
		if oc.correlator != nil {
			if _, err := oc.correlator.Ingest(ctx, sig); err != nil {
				oc.log.Warn("outage: correlate signal failed", "error", err)
			}
		}
		oc.log.Info("outage signal raised",
			"tenant_id", sig.TenantID, "kind", sig.Kind, "target", sig.Target,
			"scope", sig.Attributes["outage.scope"])
	}
	return nil
}
