// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package otlp

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"

	colmetricspb "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	resultv1 "github.com/ctlplne/probectl/internal/gen/probectl/result/v1"
)

// rawProtoCodec marshals a fixed byte slice as the request body while reporting
// Name() == "proto", so the server decodes it with its real proto codec. The
// bytes below are a truncated protobuf (field 1, LEN, declared length with no
// content), which fails to unmarshal into an ExportMetricsServiceRequest. If the
// gRPC runtime decodes the body, the client sees codes.Internal ("error
// unmarshalling request"); if auth runs first, the body is never decoded.
type rawProtoCodec struct{ out []byte }

func (rawProtoCodec) Name() string                  { return "proto" }
func (c rawProtoCodec) Marshal(any) ([]byte, error) { return c.out, nil }
func (rawProtoCodec) Unmarshal([]byte, any) error   { return nil }

// undecodableBody is a protobuf tag for field 1 (resource_metrics), wire type 2
// (length-delimited), claiming 255 content bytes but carrying none — a truncated
// message that proto.Unmarshal always rejects.
var undecodableBody = []byte{0x0a, 0xff, 0x01}

// testServerTLS returns a TLS config with a fresh self-signed cert so the
// TLS-only receiver (newGRPCServer) can run in-process; clients skip verification.
func testServerTLS(t *testing.T) *tls.Config {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		MinVersion:   tls.VersionTLS12,
	}
}

// startRealReceiver stands up the production gRPC receiver (newGRPCServer, which
// now wires the pre-decode auth tap handle) over a TLS bufconn listener and
// returns a dialed client connection.
func startRealReceiver(t *testing.T, auth Authenticator, sink Sink) *grpc.ClientConn {
	t.Helper()
	srv, err := newGRPCServer(testServerTLS(t), auth, testSinks(sink), 1<<20)
	if err != nil {
		t.Fatalf("newGRPCServer: %v", err)
	}
	lis := bufconn.Listen(1 << 20)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)

	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})),
	)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// TestGRPCReceiverAuthenticatesBeforeDecode is the ING-14 regression: the OTLP
// gRPC receiver must authenticate the caller BEFORE the request body is
// decompressed or proto-decoded, so an unauthenticated peer cannot force decode
// work (a decompression bomb). An unauthenticated call carrying an undecodable
// body must be rejected with codes.Unauthenticated — if the body were decoded
// first the client would instead see codes.Internal (a decode error), which is
// what the pre-fix receiver returns.
func TestGRPCReceiverAuthenticatesBeforeDecode(t *testing.T) {
	var (
		mu  sync.Mutex
		got []string
	)
	sink := SinkFunc(func(_ context.Context, tenant string, _ *colmetricspb.ExportMetricsServiceRequest) error {
		mu.Lock()
		got = append(got, tenant)
		mu.Unlock()
		return nil
	})
	auth := NewTokenAuthenticator(map[string]string{"good": "tenant-a"})
	conn := startRealReceiver(t, auth, sink)
	client := colmetricspb.NewMetricsServiceClient(conn)

	withTok := func(tok string) context.Context {
		if tok == "" {
			return context.Background()
		}
		return metadata.AppendToOutgoingContext(context.Background(), "authorization", "Bearer "+tok)
	}

	// Unauthenticated + undecodable body: rejection must precede decode, so the
	// code is Unauthenticated (not an Internal unmarshal error).
	_, err := client.Export(withTok(""), &colmetricspb.ExportMetricsServiceRequest{},
		grpc.ForceCodec(rawProtoCodec{out: undecodableBody}))
	if got := status.Code(err); got != codes.Unauthenticated {
		t.Errorf("unauthenticated undecodable push: code = %v, want Unauthenticated "+
			"(a decode error means the body was decoded before auth — ING-14)", got)
	}

	// A present-but-invalid token is still unauthenticated; its (here gzip-
	// compressed) body must not be decompressed/decoded before the rejection.
	_, err = client.Export(withTok("nope"), &colmetricspb.ExportMetricsServiceRequest{},
		grpc.ForceCodec(rawProtoCodec{out: undecodableBody}), grpc.UseCompressor("gzip"))
	if got := status.Code(err); got != codes.Unauthenticated {
		t.Errorf("invalid-token gzip undecodable push: code = %v, want Unauthenticated "+
			"(a decode/decompress error means the body was processed before auth — ING-14)", got)
	}

	// An authenticated push still works end to end and reaches the sink.
	valid := metricsRequest(resultResourceMetrics(&resultv1.Result{TenantId: "tenant-a"}))
	if _, err := client.Export(withTok("good"), valid); err != nil {
		t.Errorf("authenticated push rejected: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(got) != 1 || got[0] != "tenant-a" {
		t.Errorf("sink received %v, want exactly [tenant-a]", got)
	}
}
