package control

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/imfeelingtheagi/probectl/internal/ai"
	"github.com/imfeelingtheagi/probectl/internal/ai/author"
	"github.com/imfeelingtheagi/probectl/internal/audit"
	"github.com/imfeelingtheagi/probectl/internal/auth"
	"github.com/imfeelingtheagi/probectl/internal/carbon"
	"github.com/imfeelingtheagi/probectl/internal/cluster"
	"github.com/imfeelingtheagi/probectl/internal/cmdb"
	"github.com/imfeelingtheagi/probectl/internal/compliance"
	"github.com/imfeelingtheagi/probectl/internal/config"
	"github.com/imfeelingtheagi/probectl/internal/cost"
	"github.com/imfeelingtheagi/probectl/internal/crypto"
	"github.com/imfeelingtheagi/probectl/internal/endpoint"
	"github.com/imfeelingtheagi/probectl/internal/enroll"
	"github.com/imfeelingtheagi/probectl/internal/fairness"
	"github.com/imfeelingtheagi/probectl/internal/license"
	"github.com/imfeelingtheagi/probectl/internal/notify"
	"github.com/imfeelingtheagi/probectl/internal/outage"
	"github.com/imfeelingtheagi/probectl/internal/path"
	"github.com/imfeelingtheagi/probectl/internal/promapi"
	"github.com/imfeelingtheagi/probectl/internal/remediation"
	"github.com/imfeelingtheagi/probectl/internal/rum"
	"github.com/imfeelingtheagi/probectl/internal/slo"
	"github.com/imfeelingtheagi/probectl/internal/store"
	"github.com/imfeelingtheagi/probectl/internal/store/flowstore"
	"github.com/imfeelingtheagi/probectl/internal/store/otelstore"
	"github.com/imfeelingtheagi/probectl/internal/store/pathstore"
	"github.com/imfeelingtheagi/probectl/internal/store/tsdb"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
	"github.com/imfeelingtheagi/probectl/internal/tenantcrypto"
	"github.com/imfeelingtheagi/probectl/internal/tenantlife"
	"github.com/imfeelingtheagi/probectl/internal/threat"
	"github.com/imfeelingtheagi/probectl/internal/topology"
)

// Discoverer runs a path discovery. The default is path.Run; tests inject a fake.
type Discoverer func(ctx context.Context, cfg path.Config) (*path.Path, error)

// Server is the probectl control-plane HTTP API server. It is stateless: all
// durable state lives in the datastores, so instances are interchangeable.
type Server struct {
	cfg       *config.Config
	log       *slog.Logger
	pinger    store.Pinger
	pool      *pgxpool.Pool
	pathStore pathstore.Store
	discover  Discoverer
	http      *http.Server

	// Identity & access (S18). sessions + authn are nil when pool is nil (unit
	// tests of operational endpoints); providers is always set (the SSO seam).
	sessions  *auth.Manager
	authn     *auth.Authenticator
	providers auth.ProviderFactory
	// authLimiter throttles the auth endpoints per IP + per account (U-024).
	authLimiter *auth.Limiter
	// enrollSvc issues agent SVIDs (Sprint 11); nil = enrollment unconfigured.
	enrollSvc *enroll.Service
	// revokePush feeds the live handshake deny-list (Sprint 12, WIRE-003).
	revokePush func(serials, spiffeIDs []string)

	// AI assistant (S24). The RCA analyzer over the S23 query engine; always set
	// (built-in air-gapped model + incidents evidence when a pool is present).
	analyzer *ai.Analyzer

	// AI test authoring + auto-discovery (S26). Always set (heuristic by default,
	// model-backed when configured).
	authorEngine *author.Engine

	// ABAC policy cache (S31). nil when pool is nil (operational-only tests). The
	// per-request deny-override check (requirePermission) reads tenant policies here.
	abac *abacCache

	// On-call/ITSM dispatcher (S33). nil unless connectors are configured; set via
	// WithDispatcher so the inbound status-sync webhook + the resolve handler can
	// sync the operator's tooling.
	dispatcher *notify.Dispatcher

	// Flow analytics store (S38). Defaults to in-memory; main attaches the
	// configured store (ClickHouse in production) via WithFlowStore.
	flowStore flowstore.Store
	otelStore otelstore.Store

	// Prometheus-compatible surfaces (S40): the metrics writer, queried locally
	// when it can snapshot (memory mode) or proxied upstream (prometheus mode).
	// Set via WithTSDB; nil answers 503 on the Grafana/federate/write endpoints.
	tsdbWriter   tsdb.Writer
	promUpstream *promapi.Upstream

	// CMDB resolver (S40). nil unless a provider is configured (endpoints answer
	// 503); set via WithCMDB.
	cmdb *cmdb.Resolver

	// Active-alert state sources (S-FE1), keyed by tenant ID — each tenant's
	// evaluator engine. Set via WithAlertState; a missing tenant fails closed
	// (empty list / 503 on actions).
	alertState map[string]AlertStateSource

	// TLS/cert posture inventory (S-FE2): the store the TLS consumer maintains.
	// Set via WithTLSPosture; nil reports collector_running=false.
	tlsPostures *threat.PostureStore

	// Threat detections (S-FE3): IOC/NDR matches recorded by the threat
	// consumers. Set via WithDetections; nil reports detections_running=false.
	detections *threat.DetectionStore

	// Endpoint DEM views (S-FE4): the snapshot store the endpoint-view consumer
	// maintains. Set via WithEndpointViews; nil reports collector_running=false.
	endpointViews *endpoint.SnapshotStore

	// Latest synthetic results (S-FE5): newest full result per (type, target,
	// agent). Set via WithLatestResults; nil reports collector_running=false.
	latestResults *LatestResults

	// Secret-backend health (S41): the secrets resolver's operational
	// snapshot. Set via WithSecrets; nil reports resolver_running=false.
	secretsHealth SecretsHealthSource

	// Topology graph + what-if (S43): the dependency-graph store. Set via
	// WithTopology; nil reports topology_running=false.
	topo topology.Store

	// FinOps cost engine (S44). Set via WithCost; nil reports
	// cost_running=false.
	costEngine *cost.Engine

	// SLO engine (S45). Set via WithSLO; nil reports slo_running=false.
	sloEngine *slo.Engine

	// Compliance validator (S46). Set via WithCompliance; nil reports
	// compliance_running=false.
	complianceEngine *compliance.Engine

	// Collective internet-outage view (S47a). Set via WithOutage /
	// WithOutageFeeds; nil engine reports outage_running=false, nil feeds
	// reports feeds_enabled=false.
	outageEngine *outage.Engine
	outageFeeds  *outage.Refresher

	// RUM convergence (S47b). Set via WithRUM; nil engine = ingest answers
	// 503 and /v1/rum reports rum_running=false. rumApps maps app keys to
	// their VERIFIED (tenant, app) binding; rumPublish writes accepted
	// beacons to the bus; rumLimiter rate-bounds each key.
	rumEngine  *rum.Engine
	rumApps    map[string]RUMApp
	rumPublish RUMPublisher
	rumLimiter *keyLimiter

	// Carbon/power estimation (S48). Set via WithCarbon; nil reports
	// carbon_running=false.
	carbonEngine *carbon.Engine

	// Editions / license (S-T0). Set via WithLicense; nil = Community
	// (default-open). Read by /v1/editions; ee/ feature gating happens at
	// the main.go Build* seams, never in handlers.
	license *license.Manager

	// Provider/management plane (S-T1, ee/). A plain http.Handler so core
	// never imports ee/: the licensed build attaches it at the main.go attach
	// seam; nil (community / unlicensed) leaves /provider/* a plain 404 — the
	// hidden-unlicensed UX. The handler owns its own authn (operator sessions,
	// a privilege domain distinct from tenant users) and its own audit stream.
	providerPlane http.Handler

	// Tenant lifecycle source (S-T1): requirePermission rejects users of
	// suspended/offboarded tenants. nil skips the check (unit tests / dev).
	tenantStatus TenantStatusSource

	// Tenant lifecycle engine (S-T5, core): export / retention / verifiable
	// erasure. Set via WithTenantLife; nil answers 503 not wired.
	tenantLife *tenantlife.Engine

	// Per-tenant key management (S-T6, ee-backed): set via WithKeyManager at
	// the attach seam; nil = the /v1/security/keys surface hides (404).
	keyManager tenantcrypto.KeyManager

	// Fairness gate (S-T7, core): per-tenant ingest bounds + query-cost
	// guards. Set via WithFairness; nil = no enforcement (small/dev
	// deployments), self-view reports enforcing=false.
	fairnessGate *fairness.Gate

	// Cluster manager (S-EE2, multi-region HA): the split-brain write fence +
	// region/health status. Set via WithCluster; nil = single-region (writes
	// always allowed, no cluster status).
	cluster *cluster.Manager

	// Guarded remediation (S-EE5, ee-backed): the AI-proposes/human-approves
	// workflow. Set via WithRemediation; nil = the `remediation` feature is
	// unlicensed and the surface 404s. probectl NEVER executes.
	remediation remediation.Service

	// startedAt is the process start (S-EE4): the support bundle reports uptime.
	startedAt time.Time

	// draining flips true at the start of a graceful shutdown so /readyz reports 503
	// and the load balancer drains this replica before it exits (S34 zero-downtime).
	draining atomic.Bool
}

// WithProviderPlane mounts the provider/management plane (S-T1) under
// /provider/. The handler is opaque to core (it lives in ee/ and is attached
// only by a licensed build at the main.go seam); nil is a no-op, leaving
// /provider/* 404 — commercial surfaces stay hidden when unlicensed.
func (s *Server) WithProviderPlane(h http.Handler) *Server {
	if h != nil {
		s.providerPlane = h
	}
	return s
}

// SessionManager exposes the tenant session manager for the ee/ attach seam
// (the provider plane's tenant-consent leg resolves tenant sessions through
// it). nil when no database is configured.
func (s *Server) SessionManager() *auth.Manager { return s.sessions }

// PermissionLoader exposes the tenant RBAC loader for the ee/ attach seam.
// nil when no database is configured.
func (s *Server) PermissionLoader() auth.PermissionLoader {
	if s.pool == nil {
		return nil
	}
	return permLoader{pool: s.pool}
}

// WithCMDB attaches the CMDB resolver (S40) backing /v1/cmdb/* and the
// incident/agent CI-correlation endpoints. nil is a no-op (the feature stays
// off and the endpoints answer 503). Returns the server for chaining.
func (s *Server) WithCMDB(r *cmdb.Resolver) *Server {
	if r != nil {
		s.cmdb = r
	}
	return s
}

// WithDispatcher attaches the on-call/ITSM dispatcher (S33) so the inbound
// status-sync webhook and the incident-resolve handler can mirror the operator's
// tooling. nil is a no-op (the feature stays off). Returns the server for chaining.
func (s *Server) WithDispatcher(d *notify.Dispatcher) *Server {
	s.dispatcher = d
	return s
}

// WithOTelStore attaches the OTLP traces+logs store (ARCH-001, Sprint 22)
// backing /v1/otlp/*.
func (s *Server) WithOTelStore(st otelstore.Store) *Server {
	if st != nil {
		s.otelStore = st
	}
	return s
}

// WithFlowStore attaches the flow-analytics store (S38) backing /v1/flows/*.
// nil is a no-op (the in-memory default from New stays). Returns the server
// for chaining.
func (s *Server) WithFlowStore(fs flowstore.Store) *Server {
	if fs != nil {
		s.flowStore = fs
	}
	return s
}

// New builds a Server. pinger backs the readiness probe and pool backs the
// tenant-scoped /v1 resource handlers (both typically the same *store.DB); pool
// may be nil in unit tests that only exercise the operational endpoints or
// request validation. pathStore and discover back the path-viz API; a nil
// pathStore defaults to an in-memory store and a nil discover to path.Run.
func New(cfg *config.Config, log *slog.Logger, pinger store.Pinger, pool *pgxpool.Pool, pathStore pathstore.Store, discover Discoverer) *Server {
	if pathStore == nil {
		pathStore = pathstore.NewMemory()
	}
	if discover == nil {
		discover = path.Run
	}
	s := &Server{cfg: cfg, log: log, pinger: pinger, pool: pool, pathStore: pathStore, discover: discover,
		flowStore: flowstore.NewMemory(), otelStore: otelstore.NewMemory(), startedAt: time.Now()}

	// Identity & access (S18). The SSO provider factory is always present; the
	// session manager + authenticator need a DB (nil in operational-only tests).
	s.providers = newOIDCFactory(cfg)
	s.authLimiter = s.newAuthLimiter(cfg)
	if pool != nil {
		s.sessions = auth.NewManager(store.NewSessions(pool), cfg.SessionTTL, cfg.CookieSecure())
		s.authn = auth.NewAuthenticator(s.sessions, permLoader{pool: pool})
		// ABAC policy cache (S31): the per-request deny-override check reads from here.
		s.abac = newABACCache(pool)
	}

	// Dev auth actually serving must be unmissable (RED-001/SEC-001): an
	// error-level log, an audit event on the default tenant's tamper-evident
	// chain (best-effort), and the process flag DevModeActive() for
	// self-telemetry. main has already enforced build-tag + ack + loopback.
	if cfg.AuthMode == "dev" && DevModeAvailable() {
		devModeActive.Store(true)
		log.Error("DEV AUTH ACTIVE: every request receives an all-permissions principal with NO authentication — " +
			"local evaluation ONLY (this required a -tags devauth build, PROBECTL_DEV_AUTH_ACK, and a loopback bind)")
		if pool != nil {
			go func() {
				_ = tenancy.InTenant(tenancy.WithTenant(context.Background(), tenancy.DefaultTenantID), pool,
					func(ctx context.Context, sc tenancy.Scope) error {
						_, err := audit.TenantAppend(ctx, sc, "system", "auth.dev_mode_active", "control-plane",
							map[string]any{"ack": "i-understand", "bind": cfg.HTTPAddr})
						return err
					})
			}()
		}
	}

	// THE external-AI egress gate (AIRCA-001/005): one instance — consent,
	// redaction, audit — shared by RCA, test authoring, and (via
	// NewMCPServer) the MCP surface. No second construction site.
	egressGate := buildEgressGate(cfg, log, pool)

	// AI assistant (S24): RCA analyzer over the S23 query engine, grounded in the
	// tenant-scoped incident store and synthesized by the configured model.
	s.analyzer = buildAnalyzerWithGate(cfg, log, pool, egressGate)

	// AI test authoring (S26): heuristic by default, model-backed when configured —
	// the model path rides the egress gate (AIRCA-005).
	s.authorEngine = buildAuthor(cfg, log, egressGate)

	s.http = &http.Server{
		Addr:         cfg.HTTPAddr,
		Handler:      s.routes(),
		ReadTimeout:  cfg.ReadTimeout,
		WriteTimeout: cfg.WriteTimeout,
		IdleTimeout:  cfg.IdleTimeout,
		ErrorLog:     slog.NewLogLogger(log.Handler(), slog.LevelError),
	}
	return s
}

// Handler returns the fully wired HTTP handler (used by httptest in unit tests).
func (s *Server) Handler() http.Handler { return s.http.Handler }

func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /healthz", apiHandler(s.handleHealthz))
	mux.Handle("GET /readyz", apiHandler(s.handleReadyz))
	mux.Handle("GET /version", apiHandler(s.handleVersion))
	mux.Handle("GET /openapi.json", apiHandler(s.handleOpenAPI))
	mux.Handle("GET /.well-known/security.txt", apiHandler(s.handleSecurityTxt))

	// White-label brand (S-T4) — public + pre-auth BY DESIGN: the login
	// surface renders the tenant's brand before any session exists. Resolved
	// by Host (custom domains) or the caller's session tenant; community/
	// unlicensed deployments answer the default probectl brand.
	mux.Handle("GET /branding", apiHandler(s.handleBranding))

	// SSO login endpoints (S18) — public: they establish the session that the
	// rest of the API requires.
	mux.Handle("GET /auth/login", s.throttleAuth(s.handleLogin))
	mux.Handle("GET /auth/callback", s.throttleAuth(s.handleCallback))
	mux.Handle("POST /auth/logout", apiHandler(s.handleLogout))

	// Agent enrollment (Sprint 11) — PRE-IDENTITY by design, so it mounts
	// OFF /v1 (the /v1 surface ≡ the RBAC'd route table; this is a bootstrap
	// surface like /auth): /enroll/agent is authenticated by the one-time
	// join token, /enroll/agent/rotate by proof of the current SVID. Both
	// ride the U-024 per-IP throttle.
	mux.Handle("POST /enroll/agent", s.throttleAuth(s.handleAgentEnroll))
	mux.Handle("POST /enroll/agent/rotate", s.throttleAuth(s.handleAgentRotate))

	// Change-event ingest (S29) — NOT session-authenticated: it authenticates each
	// delivery itself by verifying the provider's HMAC/token signature, then binds
	// the event to the credential's tenant (never the payload). Mounted off /v1 (an
	// ingest surface, like the OTLP receiver), so it bypasses the session-RBAC chain.
	mux.Handle("POST /ingest/changes/{provider}/{id}", apiHandler(s.handleChangeWebhook))

	// ITSM/on-call status-sync ingest (S33) — same model as the change webhook: it
	// verifies the connector's HMAC/token signature, binds to the credential's
	// tenant, and resolves the linked incident (then loop-protected cross-sync).
	mux.Handle("POST /ingest/itsm/{provider}/{id}", apiHandler(s.handleITSMWebhook))

	// RUM beacon ingest (S47b) — same model again: each beacon authenticates
	// itself via its app key (in the body — sendBeacon cannot set headers) and
	// is bound to the KEY's tenant, never the payload's. Consent + redaction
	// are enforced before anything is published. OPTIONS serves the CORS
	// preflight (browsers post cross-origin; write-only, credential-less).
	mux.Handle("POST /ingest/rum", apiHandler(s.handleRUMBeacon))
	mux.Handle("OPTIONS /ingest/rum", apiHandler(s.handleRUMPreflight))

	// SCIM 2.0 (S31) — an IdP provisioning surface mounted off /v1; each request is
	// authenticated by a per-tenant SCIM bearer token (pre-tenant, like sessions),
	// and responses use the SCIM media type + error envelope. Deprovision revokes a
	// user's sessions/tokens immediately.
	mux.Handle("GET /scim/v2/ServiceProviderConfig", s.scim(s.scimServiceProviderConfig))
	mux.Handle("POST /scim/v2/Users", s.scim(s.scimCreateUser))
	mux.Handle("GET /scim/v2/Users", s.scim(s.scimListUsers))
	mux.Handle("GET /scim/v2/Users/{id}", s.scim(s.scimGetUser))
	mux.Handle("PUT /scim/v2/Users/{id}", s.scim(s.scimPutUser))
	mux.Handle("PATCH /scim/v2/Users/{id}", s.scim(s.scimPatchUser))
	mux.Handle("DELETE /scim/v2/Users/{id}", s.scim(s.scimDeleteUser))
	mux.Handle("POST /scim/v2/Groups", s.scim(s.scimCreateGroup))
	mux.Handle("GET /scim/v2/Groups", s.scim(s.scimListGroups))
	mux.Handle("GET /scim/v2/Groups/{id}", s.scim(s.scimGetGroup))
	mux.Handle("PATCH /scim/v2/Groups/{id}", s.scim(s.scimPatchGroup))
	mux.Handle("DELETE /scim/v2/Groups/{id}", s.scim(s.scimDeleteGroup))

	// Versioned resource routes (S9). One table → routing + the
	// OpenAPI-matches-handlers check + per-route RBAC enforcement (S18): the
	// tenant boundary is checked first (the principal carries one tenant), then
	// the route's required permission.
	for _, rt := range s.apiRoutes() {
		mux.Handle(rt.Method+" "+rt.Pattern, s.requirePermission(rt.Permission, rt.Handler))
	}

	// Provider/management plane (S-T1) — dispatched per-request so the ee/
	// handler can be attached AFTER New (the main.go seam). It performs its
	// OWN operator authn (a distinct privilege domain; tenant sessions and the
	// dev principal mean nothing here) and writes the separate provider audit
	// stream. Unattached (community / unlicensed) = a plain 404,
	// indistinguishable from any unknown path: unlicensed surfaces stay hidden.
	mux.Handle("/provider/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.providerPlane == nil {
			http.NotFound(w, r)
			return
		}
		s.providerPlane.ServeHTTP(w, r)
	}))

	// Outermost first: security headers, request context (id + logger), access
	// logging, panic recovery, then authentication closest to the mux so every
	// handler sees a resolved principal in its context.
	return chain(mux,
		securityHeaders(s.cfg),
		requestContext(s.log),
		accessLog,
		recoverer,
		s.authenticate,
		s.writeFence, // S-EE2: fence mutating requests during a failover / split-brain
	)
}

// Run starts the server and blocks until ctx is canceled, then gracefully drains
// in-flight requests within the configured ShutdownTimeout.
func (s *Server) Run(ctx context.Context) error {
	tlsEnabled := s.cfg.TLSEnabled()
	if !tlsEnabled {
		// WIRE-004: TLS is the DEFAULT. A plaintext listener is allowed only
		// bound to loopback (local dev) or with the explicit, loud opt-in
		// (PROBECTL_ALLOW_PLAINTEXT_HTTP — the behind-TLS-ingress posture).
		if err := plaintextAllowed(s.cfg.HTTPAddr, s.cfg.AllowPlaintextHTTP); err != nil {
			return err
		}
		s.log.Warn("PLAINTEXT HTTP listener (no TLS on this process) — acceptable ONLY behind a TLS-terminating ingress or on loopback",
			"addr", s.cfg.HTTPAddr, "opt_in", s.cfg.AllowPlaintextHTTP)
	}
	if tlsEnabled {
		// Apply the hardened TLS config (the only crypto routes through
		// internal/crypto; control imports no crypto package directly).
		if err := crypto.ConfigureServerTLS(s.http, s.cfg.TLSCertFile, s.cfg.TLSKeyFile); err != nil {
			return fmt.Errorf("configure tls: %w", err)
		}
	}

	errCh := make(chan error, 1)
	go func() {
		s.log.Info("control-plane listening", "addr", s.cfg.HTTPAddr, "tls", tlsEnabled)
		var err error
		if tlsEnabled {
			// Certificates live in TLSConfig, so the file arguments are empty.
			// The server listens HTTPS only — plaintext is refused.
			err = s.http.ListenAndServeTLS("", "")
		} else {
			err = s.http.ListenAndServe()
		}
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
			return
		}
		errCh <- nil
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		// Flip readiness to draining FIRST so the load balancer stops routing new
		// requests here, then drain in-flight requests within the timeout (S34).
		s.draining.Store(true)
		s.log.Info("draining and shutting down", "timeout", s.cfg.ShutdownTimeout.String())
		shutdownCtx, cancel := context.WithTimeout(context.Background(), s.cfg.ShutdownTimeout)
		defer cancel()
		return s.http.Shutdown(shutdownCtx)
	}
}

// plaintextAllowed decides whether a non-TLS control listener may start
// (WIRE-004): loopback binds are fine (local dev); anything else needs the
// explicit PROBECTL_ALLOW_PLAINTEXT_HTTP opt-in. Default = refuse.
func plaintextAllowed(addr string, optIn bool) error {
	if optIn || loopbackAddr(addr) {
		return nil
	}
	return fmt.Errorf("refusing to serve the control API over PLAINTEXT on %q: configure TLS "+
		"(PROBECTL_TLS_CERT_FILE/KEY_FILE), bind loopback, or set PROBECTL_ALLOW_PLAINTEXT_HTTP=true "+
		"ONLY behind a TLS-terminating ingress (WIRE-004)", addr)
}

// loopbackAddr reports whether addr binds only the loopback interface.
func loopbackAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	switch host {
	case "localhost", "127.0.0.1", "::1", "[::1]":
		return true
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	return ip != nil && ip.IsLoopback()
}
