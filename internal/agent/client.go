// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package agent

import (
	"context"
	"crypto/tls"
	"fmt"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/proto"

	"github.com/ctlplne/probectl/internal/agenttransport"
	"github.com/ctlplne/probectl/internal/crypto"
	agentv1 "github.com/ctlplne/probectl/internal/gen/probectl/agent/v1"
	resultv1 "github.com/ctlplne/probectl/internal/gen/probectl/result/v1"
)

// Client is the agent's mTLS gRPC connection to the control plane.
type Client struct {
	conn *grpc.ClientConn
	svc  agentv1.AgentServiceClient
}

// Dial connects to the control plane over mTLS (TLS policy from internal/crypto).
// The client certificate is loaded through a rotating identity (S41): when
// trustctl renews the agent's cert/key in place, the next handshake — including
// gRPC's automatic reconnects — presents the renewed certificate without an
// agent restart.
func Dial(addr, certFile, keyFile, caFile, serverName string) (*Client, error) {
	cfg, _, err := crypto.ClientMTLSConfigRotating(certFile, keyFile, caFile, "")
	if err != nil {
		return nil, err
	}
	if serverName != "" {
		cfg.ServerName = serverName
	}
	return dialWithTLS(addr, cfg)
}

func dialWithTLS(addr string, cfg *tls.Config) (*Client, error) {
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

// Heartbeat reports liveness and the central test-set version the agent runs;
// the reply's config_stale asks it to pull now (G9).
func (c *Client) Heartbeat(ctx context.Context, req *agentv1.HeartbeatRequest) (*agentv1.HeartbeatResponse, error) {
	return c.svc.Heartbeat(ctx, req)
}

// maxTestBundleBytes bounds a pulled test bundle (the control plane caps a
// tenant's distributable set well below this).
const maxTestBundleBytes = 16 << 20

// FetchTestBundle pulls the tenant's signed central test set (G9). The tenant
// is the one in this client's certificate; the request carries only the
// version the agent already runs.
func (c *Client) FetchTestBundle(ctx context.Context, knownVersion uint64) (*agentv1.FetchTestBundleResponse, error) {
	return c.svc.FetchTestBundle(ctx, &agentv1.FetchTestBundleRequest{KnownVersion: knownVersion},
		grpc.MaxCallRecvMsgSize(maxTestBundleBytes))
}

func (c *Client) fetchInstantTest(ctx context.Context) ([]byte, error) {
	response, err := c.svc.FetchTestBundle(ctx, &agentv1.FetchTestBundleRequest{InstantOnly: true},
		grpc.MaxCallRecvMsgSize(maxTestBundleBytes))
	if err != nil {
		return nil, err
	}
	return response.GetSignedInstantAssignment(), nil
}

func (c *Client) reportInstantTest(ctx context.Context, result *agentv1.ReportInstantTestResultRequest) error {
	_, err := c.svc.ReportInstantTestResult(ctx, result)
	return err
}

type resultStream interface {
	Send(*agentv1.StreamResultsRequest) error
	CloseAndRecv() (*agentv1.StreamResultsResponse, error)
}

type resultStreamer interface {
	StreamResults(context.Context) (resultStream, error)
}

// StreamResults opens a client stream for forwarding buffered results. The
// stream envelope carries a fresh timestamp + nonce inside the mTLS channel
// (Sprint 12, WIRE-006) — the server refuses stale/replayed envelopes.
func (c *Client) StreamResults(ctx context.Context) (resultStream, error) {
	ctx, err := agenttransport.FreshnessMetadata(ctx)
	if err != nil {
		return nil, err
	}
	return c.svc.StreamResults(ctx)
}

// SendEndpointResults sends one sampled batch after the caller has negotiated
// endpoint ingress in Register. The server derives identity from the certificate.
func (c *Client) SendEndpointResults(ctx context.Context, results []*resultv1.Result) error {
	ctx, err := agenttransport.FreshnessMetadata(ctx)
	if err != nil {
		return err
	}
	ctx = metadata.AppendToOutgoingContext(ctx, agenttransport.EndpointResultsMetadataKey, agenttransport.EndpointResultsCapability)
	stream, err := c.svc.StreamResults(ctx)
	if err != nil {
		return err
	}
	// Older replicas wait for a normal result frame, so the caller's deadline
	// expires without sending endpoint data into their general result lane.
	header, err := stream.Header()
	if err != nil {
		return err
	}
	accepted := header.Get(agenttransport.EndpointResultsMetadataKey)
	if len(accepted) != 1 || accepted[0] != agenttransport.EndpointResultsCapability {
		return fmt.Errorf("control plane did not negotiate endpoint result routing")
	}
	for _, result := range results {
		payload, err := proto.Marshal(result)
		if err != nil {
			return err
		}
		if err := stream.Send(&agentv1.StreamResultsRequest{
			Type: agenttransport.EndpointResultsCapability, Payload: payload,
			ObservedUnixNanos: result.GetStartTimeUnixNano(),
		}); err != nil {
			_, receiveErr := stream.CloseAndRecv()
			if receiveErr != nil {
				return receiveErr
			}
			return err
		}
	}
	ack, err := stream.CloseAndRecv()
	if err != nil {
		return err
	}
	if ack.GetAccepted() != uint64(len(results)) {
		return fmt.Errorf("endpoint stream acknowledged %d of %d results", ack.GetAccepted(), len(results))
	}
	return nil
}

// PollCoordination asks the control plane for the next agent-to-agent task.
func (c *Client) PollCoordination(ctx context.Context) (*agentv1.PollCoordinationResponse, error) {
	return c.svc.PollCoordination(ctx, &agentv1.PollCoordinationRequest{})
}

// ReportEndpoint announces a responder's listen endpoint for a session.
func (c *Client) ReportEndpoint(ctx context.Context, sessionID, host string, port uint32) error {
	_, err := c.svc.ReportEndpoint(ctx, &agentv1.ReportEndpointRequest{SessionId: sessionID, Host: host, Port: port})
	return err
}

// Close closes the connection.
func (c *Client) Close() error { return c.conn.Close() }
