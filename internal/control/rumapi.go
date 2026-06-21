// SPDX-License-Identifier: LicenseRef-probectl-TBD

package control

// RUM convergence wiring (S47b, F20): the beacon ingest (mounted OUTSIDE the
// session-authenticated /v1 surface) treats the app key as a public routing key:
// it binds the beacon to the KEY's tenant, never the payload's, and may be
// paired with an origin allow-list. The consumer joins real-user views with
// synthetic outcomes, and GET /v1/rum serves the tenant-scoped convergence
// view. The privacy contract (consent, redaction, no-IP) is enforced
// server-side in internal/rum before anything is published or stored.

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/imfeelingtheagi/probectl/internal/apierror"
	"github.com/imfeelingtheagi/probectl/internal/bus"
	"github.com/imfeelingtheagi/probectl/internal/config"
	resultv1 "github.com/imfeelingtheagi/probectl/internal/gen/probectl/result/v1"
	"github.com/imfeelingtheagi/probectl/internal/incident"
	"github.com/imfeelingtheagi/probectl/internal/rum"
)

// RUMApp is one registered application: the app key's verified binding.
type RUMApp struct {
	Tenant string
	App    string
	// AllowedOrigins, when non-empty, fail-closes beacon POSTs for this public
	// app key unless the request carries an allowed Origin. The same list scopes
	// CORS reflection. Empty => default wildcard ("*"). Still no credentials on
	// either path, and the app key is never treated as a secret.
	AllowedOrigins []string
}

// BuildRUM parses the app-key registry from config. Returns ok=false when
// disabled; a malformed registry entry is a startup ERROR (fail closed — a
// mis-bound key could file beacons under the wrong tenant).
func BuildRUM(cfg *config.Config, log *slog.Logger) (*rum.Engine, map[string]RUMApp, bool, error) {
	if cfg == nil || !cfg.RUMEnabled {
		return nil, nil, false, nil
	}
	if len(cfg.RUMApps) == 0 {
		return nil, nil, false, fmt.Errorf("rum: PROBECTL_RUM_ENABLED is set but PROBECTL_RUM_APPS is empty")
	}
	apps := make(map[string]RUMApp, len(cfg.RUMApps))
	for key, val := range cfg.RUMApps {
		key = strings.TrimSpace(key)
		if key == "" {
			return nil, nil, false, fmt.Errorf("rum: app entry %q must be key=tenant/app", val)
		}
		parsed, err := parseRUMAppConfig(val)
		if err != nil {
			return nil, nil, false, err
		}
		if rumOriginsRequired(cfg.DeploymentProfile) && len(parsed.AllowedOrigins) == 0 {
			return nil, nil, false, fmt.Errorf("rum: app entry %q must set ;origins= under PROBECTL_DEPLOYMENT_PROFILE=%s", val, cfg.DeploymentProfile)
		}
		apps[key] = parsed
	}
	if log != nil {
		log.Info("rum ingest enabled", "apps", len(apps), "rate_per_min", cfg.RUMRatePerMin)
	}
	return rum.NewEngine(), apps, true, nil
}

func rumOriginsRequired(profile string) bool {
	return profile == "multi-tenant" || profile == "regulated"
}

func parseRUMAppConfig(raw string) (RUMApp, error) {
	binding, optsRaw, _ := strings.Cut(strings.TrimSpace(raw), ";")
	tenant, app, _ := strings.Cut(strings.TrimSpace(binding), "/")
	if tenant == "" {
		return RUMApp{}, fmt.Errorf("rum: app entry %q must be key=tenant/app", raw)
	}
	out := RUMApp{Tenant: tenant, App: strings.TrimSpace(app)}
	for optsRaw != "" {
		opt := optsRaw
		if next, rest, ok := strings.Cut(optsRaw, ";"); ok {
			opt, optsRaw = next, rest
		} else {
			optsRaw = ""
		}
		opt = strings.TrimSpace(opt)
		if opt == "" {
			continue
		}
		name, val, ok := strings.Cut(opt, "=")
		if !ok {
			return RUMApp{}, fmt.Errorf("rum: app entry %q option %q must be name=value", raw, opt)
		}
		switch strings.TrimSpace(name) {
		case "origins":
			origins, err := parseRUMAllowedOrigins(val)
			if err != nil {
				return RUMApp{}, fmt.Errorf("rum: app entry %q has invalid origins: %w", raw, err)
			}
			out.AllowedOrigins = origins
		default:
			return RUMApp{}, fmt.Errorf("rum: app entry %q has unknown option %q", raw, name)
		}
	}
	return out, nil
}

func parseRUMAllowedOrigins(raw string) ([]string, error) {
	parts := strings.Split(raw, "|")
	origins := make([]string, 0, len(parts))
	seen := map[string]bool{}
	for _, part := range parts {
		norm, ok := normalizeRUMOrigin(strings.TrimSpace(part))
		if !ok {
			return nil, fmt.Errorf("origin %q must be an https origin with no path/query/fragment; http is only allowed for loopback dev origins", part)
		}
		if !seen[norm] {
			origins = append(origins, norm)
			seen[norm] = true
		}
	}
	if len(origins) == 0 {
		return nil, fmt.Errorf("at least one origin is required")
	}
	return origins, nil
}

func normalizeRUMOrigin(raw string) (string, bool) {
	if raw == "" {
		return "", false
	}
	u, err := url.Parse(raw)
	if err != nil || u.User != nil || u.Host == "" || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return "", false
	}
	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return "", false
	}
	if scheme != "https" {
		if scheme != "http" || !rumLoopbackOrigin(host) {
			return "", false
		}
	}
	port := u.Port()
	if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
		port = ""
	}
	hostport := host
	if strings.Contains(host, ":") {
		hostport = "[" + host + "]"
	}
	if port != "" {
		hostport += ":" + port
	}
	return scheme + "://" + hostport, true
}

func rumLoopbackOrigin(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// RUMPublisher publishes one validated, redacted beacon (as a canonical
// result) to the bus. main wires it to the RUM events topic.
type RUMPublisher func(ctx context.Context, tenant string, payload []byte) error

// WithRUM attaches the engine + key registry + publisher backing the beacon
// ingest and /v1/rum. Any nil leaves the surface off (the ingest answers 503,
// the view reports rum_running=false).
func (s *Server) WithRUM(e *rum.Engine, apps map[string]RUMApp, publish RUMPublisher, ratePerMin int) *Server {
	if e != nil && len(apps) > 0 {
		s.rumEngine = e
		s.rumApps = apps
		s.rumPublish = publish
		s.rumLimiter = newKeyLimiter(ratePerMin)
	}
	return s
}

// rumCORS sets the beacon CORS surface: browsers post cross-origin, the
// endpoint is write-only and credential-less, so a wildcard origin is safe and
// the default. SEC-005: when allowed is non-empty (an app-key's operator-set
// allow-list) the request Origin is echoed only if it is on the list — an
// off-list Origin is NOT reflected, so the browser blocks the response. There
// are never any credentials on either path.
func rumCORS(w http.ResponseWriter, reqOrigin string, allowed []string) {
	if len(allowed) == 0 {
		w.Header().Set("Access-Control-Allow-Origin", "*")
	} else if rumOriginAllowed(reqOrigin, allowed) {
		w.Header().Set("Access-Control-Allow-Origin", reqOrigin)
		w.Header().Add("Vary", "Origin")
	}
	// Off-list (or no Origin) with an allow-list: no Allow-Origin header, and
	// handleRUMBeacon rejects the POST before publish.
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	w.Header().Set("Access-Control-Max-Age", "86400")
}

func rumOriginAllowed(reqOrigin string, allowed []string) bool {
	norm, ok := normalizeRUMOrigin(reqOrigin)
	if !ok {
		return false
	}
	for _, origin := range allowed {
		if norm == origin {
			return true
		}
	}
	return false
}

// rumAllowedOriginsFor returns the allow-list for the app key carried in the
// (already-read) request body, or nil when the key is unknown / has no list.
func (s *Server) rumAllowedOriginsFor(key string) []string {
	if app, ok := s.rumApps[key]; ok {
		return app.AllowedOrigins
	}
	return nil
}

// handleRUMPreflight answers the CORS preflight for JSON beacons. The app key is
// not available at preflight (it rides in the body), so preflight uses the
// wildcard unless a single global default is configured; per-key allow-lists are
// enforced on the actual beacon POST (SEC-005).
func (s *Server) handleRUMPreflight(w http.ResponseWriter, _ *http.Request) error {
	rumCORS(w, "", nil)
	w.WriteHeader(http.StatusNoContent)
	return nil
}

// handleRUMBeacon ingests one beacon: public app-key routing (tenant bound from
// the server registry), optional origin allow-list, per-key rate limit, size
// cap, strict privacy-gated parse, then publish to the bus. Rejections are
// counted per tenant and served at /v1/rum (privacy honesty), and the response
// never echoes payload content.
func (s *Server) handleRUMBeacon(w http.ResponseWriter, r *http.Request) error {
	if s.rumEngine == nil || s.rumPublish == nil {
		rumCORS(w, r.Header.Get("Origin"), nil)
		return apierror.Unavailable("rum ingest is not enabled")
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, rum.MaxBeaconBytes+1))
	if err != nil {
		rumCORS(w, r.Header.Get("Origin"), nil)
		return apierror.BadRequest("cannot read request body")
	}
	if len(body) > rum.MaxBeaconBytes {
		rumCORS(w, r.Header.Get("Origin"), nil)
		http.Error(w, `{"error":{"code":"too_large","message":"beacon exceeds size cap"}}`, http.StatusRequestEntityTooLarge)
		return nil
	}

	// Resolve the app key FIRST (leniently — even a beacon that will fail the
	// strict parse attributes its rejection to the right tenant). SEC-005: the
	// CORS reflection is now scoped to this app key's allow-list (if any).
	key := rum.PeekKey(body)
	reqOrigin := r.Header.Get("Origin")
	rumCORS(w, reqOrigin, s.rumAllowedOriginsFor(key))
	app, ok := s.rumApps[key]
	if !ok {
		return apierror.Unauthorized("unknown app key")
	}
	if len(app.AllowedOrigins) > 0 && !rumOriginAllowed(reqOrigin, app.AllowedOrigins) {
		s.rumEngine.RecordReject(app.Tenant, rum.RejectBadField)
		return apierror.Forbidden("rum origin not allowed")
	}
	if !s.rumLimiter.allow(key) {
		w.Header().Set("Retry-After", "60")
		http.Error(w, `{"error":{"code":"rate_limited","message":"beacon rate exceeded"}}`, http.StatusTooManyRequests)
		return nil
	}

	beacon, reason, err := rum.ParseBeacon(body)
	if err != nil {
		s.rumEngine.RecordReject(app.Tenant, reason)
		return apierror.BadRequest("beacon rejected: " + string(reason))
	}
	res := rum.ToResult(app.Tenant, app.App, beacon, time.Now().UnixNano())
	raw, err := proto.Marshal(res)
	if err != nil {
		return apierror.Internal("cannot encode beacon")
	}
	if err := s.rumPublish(r.Context(), app.Tenant, raw); err != nil {
		return apierror.Unavailable("beacon bus unavailable")
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"accepted": true})
	return nil
}

// handleRUM serves GET /v1/rum — the CALLER-tenant's convergence view.
func (s *Server) handleRUM(w http.ResponseWriter, r *http.Request) error {
	tid, err := s.principalTenant(r)
	if err != nil {
		return err
	}
	if s.rumEngine == nil {
		writeJSON(w, http.StatusOK, map[string]any{"rum_running": false})
		return nil
	}
	snap := s.rumEngine.Snapshot(tid)
	writeJSON(w, http.StatusOK, map[string]any{
		"rum_running":    true,
		"apps":           snap.Apps,
		"privacy":        snap.Privacy,
		"coverage_notes": []string{"RUM reflects pages instrumented with the probectl beacon and users who consented — uninstrumented apps and opted-out users are invisible, and absence of RUM data is not proof of health"},
	})
	return nil
}

// keyLimiter is a per-app-key token bucket (one chatty site must not starve
// the rest of the tenant's apps — or the control plane).
type keyLimiter struct {
	mu      sync.Mutex
	perMin  int
	buckets map[string]*keyBucket
	now     func() time.Time
}

type keyBucket struct {
	tokens float64
	last   time.Time
}

func newKeyLimiter(perMin int) *keyLimiter {
	return &keyLimiter{perMin: perMin, buckets: map[string]*keyBucket{}, now: time.Now}
}

func (l *keyLimiter) allow(key string) bool {
	if l == nil || l.perMin <= 0 {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	capacity := float64(l.perMin)
	now := l.now()
	b, ok := l.buckets[key]
	if !ok {
		if len(l.buckets) > 4096 { // bounded: unknown keys never get this far,
			l.buckets = map[string]*keyBucket{} // but stay safe anyway
		}
		b = &keyBucket{tokens: capacity, last: now}
		l.buckets[key] = b
	}
	b.tokens += now.Sub(b.last).Seconds() * (capacity / 60.0)
	if b.tokens > capacity {
		b.tokens = capacity
	}
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// RUMConsumer joins the two planes: real-user views from the RUM topic and
// synthetic outcomes from the network-results topic. Verdict-transition
// signals land in the incident pipeline, tenant-scoped.
type RUMConsumer struct {
	engine     *rum.Engine
	bus        bus.Bus
	correlator *incident.Correlator
	log        *slog.Logger
}

// NewRUMConsumer builds the consumer over a non-nil engine.
func NewRUMConsumer(b bus.Bus, e *rum.Engine, c *incident.Correlator, log *slog.Logger) *RUMConsumer {
	if log == nil {
		log = slog.Default()
	}
	return &RUMConsumer{engine: e, bus: b, correlator: c, log: log}
}

// RunViews consumes ONLY the RUM beacon topic — production mode when the
// synthetic results arrive via the decode-once ResultFan (SCALE-013).
func (rc *RUMConsumer) RunViews(ctx context.Context) error {
	return rc.bus.Subscribe(ctx, bus.RUMEventsTopic, "rum-views", rc.handleRUMEvent)
}

// Run subscribes to both topics (own consumer groups) until ctx ends.
func (rc *RUMConsumer) Run(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	errs := make(chan error, 2)
	var wg sync.WaitGroup
	for _, sub := range []struct {
		topic, group string
		handle       func(context.Context, bus.Message) error
	}{
		{bus.RUMEventsTopic, "rum-views", rc.handleRUMEvent},
		{bus.NetworkResultsTopic, "rum-synthetic", rc.handleSynthetic},
	} {
		wg.Add(1)
		go func(topic, group string, h func(context.Context, bus.Message) error) {
			defer wg.Done()
			if err := rc.bus.Subscribe(ctx, topic, group, h); err != nil && ctx.Err() == nil {
				errs <- err
				cancel()
			}
		}(sub.topic, sub.group, sub.handle)
	}
	wg.Wait()
	close(errs)
	return <-errs
}

func (rc *RUMConsumer) handleRUMEvent(ctx context.Context, msg bus.Message) error {
	var r resultv1.Result
	if err := proto.Unmarshal(msg.Value, &r); err != nil {
		rc.log.Warn("rum: skipping malformed event", "error", err)
		return nil
	}
	rc.ingest(ctx, rc.engine.ObserveRUM(&r))
	return nil
}

// webFacing are the synthetic types whose targets real users also reach.
func webFacing(canaryType string) bool {
	switch canaryType {
	case "http", "https", "browser":
		return true
	default:
		return false
	}
}

func (rc *RUMConsumer) handleSynthetic(ctx context.Context, msg bus.Message) error {
	var r resultv1.Result
	if err := proto.Unmarshal(msg.Value, &r); err != nil {
		return nil // the result pipeline owns malformed-result logging
	}
	return rc.SinkResult(ctx, &r)
}

// SinkResult ingests one DECODED synthetic result (shared immutable).
func (rc *RUMConsumer) SinkResult(ctx context.Context, r *resultv1.Result) error {
	tenant := r.GetTenantId()
	if tenant == "" || !webFacing(r.GetCanaryType()) {
		return nil // unscoped dropped (guardrail 1); non-web types irrelevant here
	}
	host := strings.ToLower(peerHost(r.GetServerAddress()))
	rc.ingest(ctx, rc.engine.ObserveSynthetic(tenant, host, r.GetSuccess(),
		time.Unix(0, r.GetStartTimeUnixNano())))
	return nil
}

func (rc *RUMConsumer) ingest(ctx context.Context, sigs []incident.Signal) {
	for _, sig := range sigs {
		if rc.correlator != nil {
			if _, err := rc.correlator.Ingest(ctx, sig); err != nil {
				rc.log.Warn("rum: correlate signal failed", "error", err)
			}
		}
		rc.log.Info("rum convergence signal raised",
			"tenant_id", sig.TenantID, "kind", sig.Kind,
			"app", sig.Attributes["rum.app"], "host", sig.Attributes["rum.host"],
			"verdict", sig.Attributes["rum.verdict"])
	}
}
