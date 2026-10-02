// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package otlp

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"

	"golang.org/x/sync/errgroup"
)

// HTTP connection-timeout defaults for the OTLP/HTTP receiver. Every one is
// non-zero so a slow or idle unauthenticated client cannot pin a connection
// open (docs/guardrails.md G7-12): ReadTimeout caps the whole request and so a
// trickled body, WriteTimeout the response, IdleTimeout a kept-alive connection
// between requests, ReadHeaderTimeout the request line + headers. They are set
// well above a legitimate large-but-timely OTLP batch — the body is already
// bounded by MaxRecvBytes (default 4 MiB) — so normal uploads still complete.
const (
	defaultHTTPReadHeaderTimeout = 10 * time.Second
	defaultHTTPReadTimeout       = 30 * time.Second
	defaultHTTPWriteTimeout      = 30 * time.Second
	defaultHTTPIdleTimeout       = 60 * time.Second
)

// ServerConfig configures the bundled OTLP receiver listeners.
type ServerConfig struct {
	GRPCAddr     string // e.g. ":4317" (empty disables the gRPC receiver)
	HTTPAddr     string // e.g. ":4318" (empty disables the HTTP receiver)
	MaxRecvBytes int    // 0 => default (4 MiB)
	Freshness    *FreshnessVerifier

	// HTTP/1.1 connection timeouts for the OTLP/HTTP receiver. A zero value
	// takes the sane non-zero default above; callers (and tests) may shorten
	// them. They bound slow and idle clients so an unauthenticated peer cannot
	// hold a connection open (docs/guardrails.md G7-12).
	ReadHeaderTimeout time.Duration
	ReadTimeout       time.Duration
	WriteTimeout      time.Duration
	IdleTimeout       time.Duration
}

// Server runs the OTLP/gRPC and OTLP/HTTP receivers on TLS listeners. It is the
// inbound OTLP surface: TLS-only, authenticated, tenant-scoped, untrusted input
// (docs/guardrails.md G7-12).
type Server struct {
	cfg   ServerConfig
	tls   *tls.Config
	auth  Authenticator
	sinks Sinks
	log   *slog.Logger
}

// NewServer validates the receiver configuration and returns a runnable Server.
// Sinks for ALL THREE signals are required (ARCH-001).
func NewServer(cfg ServerConfig, tlsCfg *tls.Config, auth Authenticator, sinks Sinks, log *slog.Logger) (*Server, error) {
	if tlsCfg == nil {
		return nil, errors.New("otlp: TLS config required (the receiver is TLS-only)")
	}
	if auth == nil {
		return nil, errors.New("otlp: authenticator is required")
	}
	if err := sinks.validate(); err != nil {
		return nil, err
	}
	if cfg.GRPCAddr == "" && cfg.HTTPAddr == "" {
		return nil, errors.New("otlp: a gRPC or HTTP address is required")
	}
	if log == nil {
		log = slog.Default()
	}
	return &Server{cfg: cfg, tls: tlsCfg, auth: auth, sinks: sinks, log: log}, nil
}

// Run starts the configured listeners and blocks until ctx is canceled or a
// listener fails.
func (s *Server) Run(ctx context.Context) error {
	g, gctx := errgroup.WithContext(ctx)

	if s.cfg.GRPCAddr != "" {
		grpcSrv, err := NewGRPCServerWithFreshness(s.tls, s.auth, s.sinks, s.cfg.MaxRecvBytes, s.cfg.Freshness)
		if err != nil {
			return err
		}
		lis, err := net.Listen("tcp", s.cfg.GRPCAddr)
		if err != nil {
			return fmt.Errorf("otlp: grpc listen %q: %w", s.cfg.GRPCAddr, err)
		}
		s.log.Info("otlp grpc receiver listening", "addr", s.cfg.GRPCAddr)
		g.Go(func() error { return grpcSrv.Serve(lis) })
		g.Go(func() error {
			<-gctx.Done()
			grpcSrv.GracefulStop()
			return nil
		})
	}

	if s.cfg.HTTPAddr != "" {
		mux := http.NewServeMux()
		// The standard OTLP/HTTP paths — exactly what an OTel Collector's
		// otlphttp exporter posts to (ARCH-006).
		mux.Handle("/v1/metrics", MetricsHTTPHandlerWithFreshness(s.auth, s.sinks.Metrics, int64(s.cfg.MaxRecvBytes), s.cfg.Freshness))
		mux.Handle("/v1/traces", TracesHTTPHandlerWithFreshness(s.auth, s.sinks.Traces, int64(s.cfg.MaxRecvBytes), s.cfg.Freshness))
		mux.Handle("/v1/logs", LogsHTTPHandlerWithFreshness(s.auth, s.sinks.Logs, int64(s.cfg.MaxRecvBytes), s.cfg.Freshness))
		httpSrv := s.newHTTPServer(mux)
		s.log.Info("otlp http receiver listening", "addr", s.cfg.HTTPAddr)
		g.Go(func() error {
			if err := httpSrv.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
				return err
			}
			return nil
		})
		g.Go(func() error {
			<-gctx.Done()
			sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			return httpSrv.Shutdown(sctx)
		})
	}

	return g.Wait()
}

// newHTTPServer builds the OTLP/HTTP server with every connection timeout set to
// a non-zero value. A server left with only ReadHeaderTimeout lets a slow or
// idle unauthenticated client hold a connection open indefinitely (a trickled
// body, or an idle keep-alive after a 401); ReadTimeout, WriteTimeout and
// IdleTimeout close those out (docs/guardrails.md G7-12). A zero in the config
// takes the sane default; tests may shorten them to probe the behavior.
func (s *Server) newHTTPServer(handler http.Handler) *http.Server {
	readHeaderTimeout := s.cfg.ReadHeaderTimeout
	if readHeaderTimeout <= 0 {
		readHeaderTimeout = defaultHTTPReadHeaderTimeout
	}
	readTimeout := s.cfg.ReadTimeout
	if readTimeout <= 0 {
		readTimeout = defaultHTTPReadTimeout
	}
	writeTimeout := s.cfg.WriteTimeout
	if writeTimeout <= 0 {
		writeTimeout = defaultHTTPWriteTimeout
	}
	idleTimeout := s.cfg.IdleTimeout
	if idleTimeout <= 0 {
		idleTimeout = defaultHTTPIdleTimeout
	}
	return &http.Server{
		Addr:              s.cfg.HTTPAddr,
		Handler:           handler,
		TLSConfig:         s.tls,
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
	}
}
