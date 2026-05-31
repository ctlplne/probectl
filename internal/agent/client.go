package agent

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/imfeelingtheagi/netctl/internal/crypto"
	agentv1 "github.com/imfeelingtheagi/netctl/internal/gen/netctl/agent/v1"
)

// Client is the agent's mTLS gRPC connection to the control plane.
type Client struct {
	conn *grpc.ClientConn
	svc  agentv1.AgentServiceClient
}

// Dial connects to the control plane over mTLS (TLS policy from internal/crypto).
func Dial(addr, certFile, keyFile, caFile, serverName string) (*Client, error) {
	cfg, err := crypto.ClientMTLSConfig(certFile, keyFile, caFile)
	if err != nil {
		return nil, err
	}
	if serverName != "" {
		cfg.ServerName = serverName
	}
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(credentials.NewTLS(cfg)))
	if err != nil {
		return nil, err
	}
	return &Client{conn: conn, svc: agentv1.NewAgentServiceClient(conn)}, nil
}

// Register announces the agent to the control plane.
func (c *Client) Register(ctx context.Context, req *agentv1.RegisterRequest) (*agentv1.RegisterResponse, error) {
	return c.svc.Register(ctx, req)
}

// Heartbeat reports liveness.
func (c *Client) Heartbeat(ctx context.Context, req *agentv1.HeartbeatRequest) error {
	_, err := c.svc.Heartbeat(ctx, req)
	return err
}

// StreamResults opens a client stream for forwarding buffered results.
func (c *Client) StreamResults(ctx context.Context) (grpc.ClientStreamingClient[agentv1.StreamResultsRequest, agentv1.StreamResultsResponse], error) {
	return c.svc.StreamResults(ctx)
}

// Close closes the connection.
func (c *Client) Close() error { return c.conn.Close() }
