package control

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sync/atomic"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/imfeelingtheagi/probectl/internal/ai"
	"github.com/imfeelingtheagi/probectl/internal/ai/author"
	"github.com/imfeelingtheagi/probectl/internal/auth"
	"github.com/imfeelingtheagi/probectl/internal/config"
	"github.com/imfeelingtheagi/probectl/internal/crypto"
	"github.com/imfeelingtheagi/probectl/internal/notify"
	"github.com/imfeelingtheagi/probectl/internal/path"
	"github.com/imfeelingtheagi/probectl/internal/store"
	"github.com/imfeelingtheagi/probectl/internal/store/pathstore"
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

	// draining flips true at the start of a graceful shutdown so /readyz reports 503
	// and the load balancer drains this replica before it exits (S34 zero-downtime).
	draining atomic.Bool
}

// WithDispatcher attaches the on-call/ITSM dispatcher (S33) so the inbound
// status-sync webhook and the incident-resolve handler can mirror the operator's
// tooling. nil is a no-op (the feature stays off). Returns the server for chaining.
func (s *Server) WithDispatcher(d *notify.Dispatcher) *Server {
	s.dispatcher = d
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
	s := &Server{cfg: cfg, log: log, pinger: pinger, pool: pool, pathStore: pathStore, discover: discover}

	// Identity & access (S18). The SSO provider factory is always present; the
	// session manager + authenticator need a DB (nil in operational-only tests).
	s.providers = newOIDCFactory(cfg)
	if pool != nil {
		s.sessions = auth.NewManager(store.NewSessions(pool), cfg.SessionTTL, cfg.TLSEnabled())
		s.authn = auth.NewAuthenticator(s.sessions, permLoader{pool: pool})
		// ABAC policy cache (S31): the per-request deny-override check reads from here.
		s.abac = newABACCache(pool)
	}

	// AI assistant (S24): RCA analyzer over the S23 query engine, grounded in the
	// tenant-scoped incident store and synthesized by the configured model.
	s.analyzer = buildAnalyzer(cfg, log, pool)

	// AI test authoring (S26): heuristic by default, model-backed when configured.
	s.authorEngine = buildAuthor(cfg, log)

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

	// SSO login endpoints (S18) — public: they establish the session that the
	// rest of the API requires.
	mux.Handle("GET /auth/login", apiHandler(s.handleLogin))
	mux.Handle("GET /auth/callback", apiHandler(s.handleCallback))
	mux.Handle("POST /auth/logout", apiHandler(s.handleLogout))

	// Change-event ingest (S29) — NOT session-authenticated: it authenticates each
	// delivery itself by verifying the provider's HMAC/token signature, then binds
	// the event to the credential's tenant (never the payload). Mounted off /v1 (an
	// ingest surface, like the OTLP receiver), so it bypasses the session-RBAC chain.
	mux.Handle("POST /ingest/changes/{provider}/{id}", apiHandler(s.handleChangeWebhook))

	// ITSM/on-call status-sync ingest (S33) — same model as the change webhook: it
	// verifies the connector's HMAC/token signature, binds to the credential's
	// tenant, and resolves the linked incident (then loop-protected cross-sync).
	mux.Handle("POST /ingest/itsm/{provider}/{id}", apiHandler(s.handleITSMWebhook))

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

	// Outermost first: security headers, request context (id + logger), access
	// logging, panic recovery, then authentication closest to the mux so every
	// handler sees a resolved principal in its context.
	return chain(mux,
		securityHeaders(s.cfg),
		requestContext(s.log),
		accessLog,
		recoverer,
		s.authenticate,
	)
}

// Run starts the server and blocks until ctx is canceled, then gracefully drains
// in-flight requests within the configured ShutdownTimeout.
func (s *Server) Run(ctx context.Context) error {
	tlsEnabled := s.cfg.TLSEnabled()
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
