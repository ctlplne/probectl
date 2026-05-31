package control

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/imfeelingtheagi/netctl/internal/config"
	"github.com/imfeelingtheagi/netctl/internal/crypto"
	"github.com/imfeelingtheagi/netctl/internal/store"
)

// Server is the netctl control-plane HTTP API server. It is stateless: all
// durable state lives in the datastores, so instances are interchangeable.
type Server struct {
	cfg    *config.Config
	log    *slog.Logger
	pinger store.Pinger
	http   *http.Server
}

// New builds a Server. pinger backs the readiness probe (typically *store.DB);
// it may be nil in tests that do not exercise readiness against a database.
func New(cfg *config.Config, log *slog.Logger, pinger store.Pinger) *Server {
	s := &Server{cfg: cfg, log: log, pinger: pinger}
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

	// Outermost first: security headers, then request context (id + logger),
	// then access logging, with panic recovery closest to the handler.
	return chain(mux,
		securityHeaders(s.cfg),
		requestContext(s.log),
		accessLog,
		recoverer,
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
