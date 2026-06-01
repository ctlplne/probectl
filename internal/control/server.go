package control

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/imfeelingtheagi/netctl/internal/auth"
	"github.com/imfeelingtheagi/netctl/internal/config"
	"github.com/imfeelingtheagi/netctl/internal/crypto"
	"github.com/imfeelingtheagi/netctl/internal/path"
	"github.com/imfeelingtheagi/netctl/internal/store"
	"github.com/imfeelingtheagi/netctl/internal/store/pathstore"
)

// Discoverer runs a path discovery. The default is path.Run; tests inject a fake.
type Discoverer func(ctx context.Context, cfg path.Config) (*path.Path, error)

// Server is the netctl control-plane HTTP API server. It is stateless: all
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
	}

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

	// SSO login endpoints (S18) — public: they establish the session that the
	// rest of the API requires.
	mux.Handle("GET /auth/login", apiHandler(s.handleLogin))
	mux.Handle("GET /auth/callback", apiHandler(s.handleCallback))
	mux.Handle("POST /auth/logout", apiHandler(s.handleLogout))

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
		s.log.Info("shutting down", "timeout", s.cfg.ShutdownTimeout.String())
		shutdownCtx, cancel := context.WithTimeout(context.Background(), s.cfg.ShutdownTimeout)
		defer cancel()
		return s.http.Shutdown(shutdownCtx)
	}
}
