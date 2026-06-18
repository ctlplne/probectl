// SPDX-License-Identifier: LicenseRef-probectl-TBD

package agenttransport

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"log/slog"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/imfeelingtheagi/probectl/internal/bus"
	"github.com/imfeelingtheagi/probectl/internal/crypto"
	agentv1 "github.com/imfeelingtheagi/probectl/internal/gen/probectl/agent/v1"
	resultv1 "github.com/imfeelingtheagi/probectl/internal/gen/probectl/result/v1"
)

func TestStreamResultsRefusesAckWhenMemoryPublishDropped(t *testing.T) {
	ctx := contextWithAgentIdentity(t, "tenant-a", "agent-a")
	payload, err := proto.Marshal(&resultv1.Result{
		CanaryType:        "icmp",
		ServerAddress:     "192.0.2.10",
		StartTimeUnixNano: 1,
		DurationNano:      int64(time.Millisecond),
		Success:           true,
	})
	if err != nil {
		t.Fatal(err)
	}

	stream := &streamResultsTestStream{
		ctx:  ctx,
		reqs: []*agentv1.StreamResultsRequest{{Payload: payload}},
	}
	svc := &service{
		bus: dropPublishBus{},
		log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	err = svc.StreamResults(stream)
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("StreamResults error = %v, want Unavailable", err)
	}
	if stream.ack != nil {
		t.Fatalf("StreamResults sent ACK after dropped memory publish: %+v", stream.ack)
	}
}

type dropPublishBus struct{}

func (dropPublishBus) Publish(context.Context, string, []byte, []byte) error {
	return bus.ErrMemoryDropped
}
func (dropPublishBus) Subscribe(context.Context, string, string, bus.Handler) error { return nil }
func (dropPublishBus) Close() error                                                 { return nil }

type streamResultsTestStream struct {
	grpc.ServerStream
	ctx  context.Context
	reqs []*agentv1.StreamResultsRequest
	ack  *agentv1.StreamResultsResponse
}

func (s *streamResultsTestStream) Context() context.Context { return s.ctx }

func (s *streamResultsTestStream) Recv() (*agentv1.StreamResultsRequest, error) {
	if len(s.reqs) == 0 {
		return nil, io.EOF
	}
	req := s.reqs[0]
	s.reqs = s.reqs[1:]
	return req, nil
}

func (s *streamResultsTestStream) SendAndClose(resp *agentv1.StreamResultsResponse) error {
	s.ack = resp
	return nil
}

func contextWithAgentIdentity(t *testing.T, tenantID, agentID string) context.Context {
	t.Helper()
	ca, err := crypto.GenerateCA("transport-ca", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	certPEM, _, err := ca.IssueClientCert(agentID, crypto.AgentSPIFFEID(tenantID, agentID), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	leaf := leafFromPEM(t, certPEM)
	return peer.NewContext(context.Background(), &peer.Peer{
		AuthInfo: credentials.TLSInfo{State: tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}}},
	})
}
