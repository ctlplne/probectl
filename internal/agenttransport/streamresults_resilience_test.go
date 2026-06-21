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

func TestStreamResultsRestampsPayloadIdentityFromMTLS(t *testing.T) {
	ctx := contextWithAgentIdentity(t, "tenant-a", "agent-a")
	payload, err := proto.Marshal(&resultv1.Result{
		TenantId:          "tenant-b",
		AgentId:           "evil-agent",
		CanaryType:        "icmp",
		ServerAddress:     "192.0.2.20",
		StartTimeUnixNano: 1,
		DurationNano:      int64(time.Millisecond),
		Success:           true,
	})
	if err != nil {
		t.Fatal(err)
	}

	capture := &captureFlushBus{}
	stream := &streamResultsTestStream{
		ctx:  ctx,
		reqs: []*agentv1.StreamResultsRequest{{Payload: payload}},
	}
	svc := &service{
		bus: capture,
		log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	if err := svc.StreamResults(stream); err != nil {
		t.Fatalf("StreamResults: %v", err)
	}
	if stream.ack == nil || stream.ack.GetAccepted() != 1 {
		t.Fatalf("StreamResults ack = %+v, want accepted=1", stream.ack)
	}
	if !capture.flushed {
		t.Fatal("StreamResults acked before exercising the bus durability barrier")
	}
	if capture.topic != bus.NetworkResultsTopic {
		t.Fatalf("topic = %q, want %q", capture.topic, bus.NetworkResultsTopic)
	}
	if got, want := string(capture.key), string(bus.TenantKey("tenant-a", "agent-a")); got != want {
		t.Fatalf("bus key = %q, want authoritative tenant/agent key %q", got, want)
	}

	var published resultv1.Result
	if err := proto.Unmarshal(capture.value, &published); err != nil {
		t.Fatal(err)
	}
	if published.GetTenantId() != "tenant-a" || published.GetAgentId() != "agent-a" {
		t.Fatalf("published identity = %s/%s, want tenant-a/agent-a", published.GetTenantId(), published.GetAgentId())
	}
	if published.GetResultId() == "" {
		t.Fatal("published result_id is empty; older-agent payloads must be deterministically stamped after identity rewrite")
	}
}

type dropPublishBus struct{}

func (dropPublishBus) Publish(context.Context, string, []byte, []byte) error {
	return bus.ErrMemoryDropped
}
func (dropPublishBus) Subscribe(context.Context, string, string, bus.Handler) error { return nil }
func (dropPublishBus) Close() error                                                 { return nil }

type captureFlushBus struct {
	topic   string
	key     []byte
	value   []byte
	flushed bool
}

func (b *captureFlushBus) Publish(_ context.Context, topic string, key, value []byte) error {
	b.topic = topic
	b.key = append([]byte(nil), key...)
	b.value = append([]byte(nil), value...)
	return nil
}

func (b *captureFlushBus) Subscribe(context.Context, string, string, bus.Handler) error { return nil }
func (b *captureFlushBus) Close() error                                                 { return nil }
func (b *captureFlushBus) Flush(context.Context) error {
	b.flushed = true
	return nil
}

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
