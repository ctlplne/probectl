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

	"github.com/imfeelingtheagi/netctl/internal/crypto"
	agentv1 "github.com/imfeelingtheagi/netctl/internal/gen/netctl/agent/v1"
)

// Server is the control-plane's agent-transport gRPC server. All connections are
// mTLS; non-mTLS clients are rejected at the TLS layer.
type Server struct {
	grpc   *grpc.Server
	log    *slog.Logger
	cancel context.CancelFunc
}

// New builds the agent-transport server with mTLS from the given cert/key/CA
// files (the TLS policy is owned by internal/crypto).
func New(certFile, keyFile, caFile string, pool *pgxpool.Pool, log *slog.Logger) (*Server, error) {
	tlsConfig, err := crypto.ServerMTLSConfig(certFile, keyFile, caFile)
	if err != nil {
		return nil, fmt.Errorf("agent transport tls: %w", err)
	}
	// srvCtx is canceled on shutdown so long-lived streaming handlers wind down
	// and GracefulStop can complete.
	srvCtx, cancel := context.WithCancel(context.Background())
	gs := grpc.NewServer(grpc.Creds(credentials.NewTLS(tlsConfig)))
	agentv1.RegisterAgentServiceServer(gs, &service{pool: pool, log: log, shutdown: srvCtx.Done()})
	return &Server{grpc: gs, log: log, cancel: cancel}, nil
}

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
