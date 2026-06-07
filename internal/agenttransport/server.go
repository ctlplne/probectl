package agenttransport

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"

	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/imfeelingtheagi/probectl/internal/a2a"
	"github.com/imfeelingtheagi/probectl/internal/bus"
	"github.com/imfeelingtheagi/probectl/internal/crypto"
	agentv1 "github.com/imfeelingtheagi/probectl/internal/gen/probectl/agent/v1"
	"github.com/imfeelingtheagi/probectl/internal/lifecycle"
	"github.com/imfeelingtheagi/probectl/internal/version"
)

// Server is the control-plane's agent-transport gRPC server. All connections are
// mTLS; non-mTLS clients are rejected at the TLS layer.
type Server struct {
	grpc        *grpc.Server
	log         *slog.Logger
	cancel      context.CancelFunc
	svc         *service
	revocations *crypto.RevocationList
}

// New builds the agent-transport server with mTLS from the given cert/key/CA
// files (the TLS policy is owned by internal/crypto). Accepted results are
// published to b (the result bus); a nil bus accepts and counts results without
// publishing. broker coordinates agent-to-agent sessions; a nil broker disables
// coordination (PollCoordination returns no task).
func New(certFile, keyFile, caFile string, pool *pgxpool.Pool, b bus.Bus, broker *a2a.Broker, log *slog.Logger) (*Server, error) {
	// The registry-driven revocation deny-list is checked at the handshake
	// (U-038): a compromised agent cert is refused before its short-lived cert
	// expires. Starts empty (no effect); the control plane refreshes it from
	// the agent registry via RevocationList().
	revocations := crypto.NewRevocationList()
	tlsConfig, err := crypto.ServerMTLSConfigRevocable(certFile, keyFile, caFile, revocations)
	if err != nil {
		return nil, fmt.Errorf("agent transport tls: %w", err)
	}
	// srvCtx is canceled on shutdown so long-lived streaming handlers wind down
	// and GracefulStop can complete.
	srvCtx, cancel := context.WithCancel(context.Background())
	svc := &service{
		pool: pool, bus: b, broker: broker, log: log, shutdown: srvCtx.Done(),
		compat: lifecycle.DefaultPolicy(), controlVersion: version.Get().Version,
		freshness: newNonceCache(DefaultFreshnessWindow),
	}
	gs := grpc.NewServer(grpc.Creds(credentials.NewTLS(tlsConfig)))
	agentv1.RegisterAgentServiceServer(gs, svc)
	return &Server{grpc: gs, log: log, cancel: cancel, svc: svc, revocations: revocations}, nil
}

// RevocationList is the registry-driven mTLS deny-list (U-038). The control
// plane refreshes it from the agent registry (Replace) when an operator
// revokes an agent; a revoked serial or SPIFFE id is then refused at the
// handshake on every subsequent connection — no wait for cert expiry.
func (s *Server) RevocationList() *crypto.RevocationList { return s.revocations }

// WithVersionPolicy sets the agent↔control version-skew policy (S34). The default
// is the N/N-1 window with no explicit floor. Returns the server for chaining.
func (s *Server) WithVersionPolicy(p lifecycle.Policy) *Server {
	s.svc.compat = p
	return s
}

// WithControlVersion overrides the control-plane version the skew check compares
// against (defaults to version.Get().Version). Mainly for tests + version-pinned
// deployments. Returns the server for chaining.
func (s *Server) WithControlVersion(v string) *Server {
	s.svc.controlVersion = v
	return s
}

// AcceptedResults returns the total number of results accepted via StreamResults
// (self-observability; also used by tests).
func (s *Server) AcceptedResults() uint64 { return s.svc.accepted.Load() }

// Serve listens on addr and serves until ctx is canceled.
func (s *Server) Serve(ctx context.Context, addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("agent grpc listen: %w", err)
	}
	return s.ServeListener(ctx, ln)
}

// ServeListener serves on a provided listener until ctx is canceled, then
// gracefully drains in-flight RPCs.
func (s *Server) ServeListener(ctx context.Context, ln net.Listener) error {
	errCh := make(chan error, 1)
	go func() {
		s.log.Info("agent gRPC listening", "addr", ln.Addr().String(), "mtls", true)
		errCh <- s.grpc.Serve(ln)
	}()
	select {
	case err := <-errCh:
		if errors.Is(err, grpc.ErrServerStopped) {
			return nil
		}
		return err
	case <-ctx.Done():
		s.cancel() // signal streaming handlers to wind down
		s.grpc.GracefulStop()
		return nil
	}
}
