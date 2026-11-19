// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package otlp_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"testing"
	"time"

	collogspb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	coltracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	logspb "go.opentelemetry.io/proto/otlp/logs/v1"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/otel"
	"github.com/ctlplne/probectl/internal/store/otelstore"
	"github.com/ctlplne/probectl/internal/testsupport/shipped"
)

type wireTenant struct {
	id, cookie string
	token      struct{ ID, Token string }
}

type wireSignalPair struct {
	mark, traceID, spanID string
	traces                *coltracepb.ExportTraceServiceRequest
	logs                  *collogspb.ExportLogsServiceRequest
}

func TestShippedOTLPTransportsPersistBothTenants(t *testing.T) {
	reserved, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	grpcAddr := reserved.Addr().String()
	if err := reserved.Close(); err != nil {
		t.Fatal(err)
	}
	stack := shipped.Start(t, shipped.Options{
		Name: "otlpwire", TenantBand: 3, Env: map[string]string{"PROBECTL_OTLP_GRPC_ADDR": grpcAddr},
	})
	operator := stack.OnboardOperator(t, "root@msp-otlp-wire.example")
	tls, err := crypto.HardenedClientTLSConfigWithCAFile(stack.CAFile)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := grpc.NewClient(grpcAddr, grpc.WithTransportCredentials(credentials.NewTLS(tls)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	service := "wire-otlp-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	tenants := [2]wireTenant{}
	signals := [2][2]wireSignalPair{}
	for i, email := range []string{"ada@acme.example", "bob@globex.example"} {
		tenant := &tenants[i]
		slug := service + "-" + strconv.Itoa(i)
		var result struct{ ID string }
		stack.MustCLI(t, map[string]string{"PROBECTL_API_TOKEN": operator}, &result, "provider", "create-tenant", "--body",
			fmt.Sprintf(`{"slug":%q,"name":%q,"isolation_model":"pooled"}`, slug, slug))
		tenant.id, tenant.cookie = result.ID, stack.SignIn(t, result.ID, email, slug)
		code, body := stack.Do(t, tenant.cookie, http.MethodPost, "/v1/otlp-tokens", map[string]string{"name": "wire-receipt"})
		if code != http.StatusCreated || json.Unmarshal(body, &tenant.token) != nil || tenant.token.ID == "" || tenant.token.Token == "" {
			t.Fatalf("tenant %s could not mint an ingest credential: status %d", tenant.id, code)
		}
		signals[i] = [2]wireSignalPair{
			newWireSignalPair(t, service, slug+"-http", ""),
			newWireSignalPair(t, service, slug+"-grpc", tenant.id),
		}
		sendOTLPHTTPPair(t, stack, tenant.token.Token, signals[i][0], http.StatusOK)
		sendOTLPGRPCPair(t, conn, tenant.token.Token, signals[i][1], codes.OK)
	}
	for i, tenant := range tenants {
		sibling := tenants[1-i]
		refused := newWireSignalPair(t, service, "wrong-owner-"+strconv.Itoa(i), sibling.id)
		sendOTLPHTTPPair(t, stack, tenant.token.Token, refused, http.StatusForbidden)
		sendOTLPGRPCPair(t, conn, tenant.token.Token, refused, codes.PermissionDenied)

		for _, owned := range signals[i] {
			shipped.Await(t, "persisted trace and log for "+owned.mark, 45*time.Second, func() bool {
				spans, logs := readWireSignalPair(t, stack, tenant.cookie, service, owned.traceID)
				if len(spans) == 0 || len(logs) == 0 {
					return false
				}
				checkWireSignalPair(t, tenant.id, owned, spans, logs)
				return true
			})
		}
		checkWireSignalIsolation(t, stack, conn, tenant, sibling, service, signals[i], refused)
	}

	stack.RestartControl(t, "control-restarted-otlp", nil)
	var clients [2]string
	for i, tenant := range tenants {
		clients[i] = stack.APIToken(t, tenant.cookie, "metrics.read")
	}
	for i, tenant := range tenants {
		for _, owned := range signals[i] {
			spans, logs := readWireSignalPair(t, stack, tenant.cookie, service, owned.traceID)
			checkWireSignalPair(t, tenant.id, owned, spans, logs)
		}
		signal := signals[i][1]
		spans, logs := readWireSignalPairCLI(t, stack, clients[i], service, signal.traceID)
		checkWireSignalPair(t, tenant.id, signal, spans, logs)
		spans, logs = readWireSignalPairCLI(t, stack, clients[1-i], service, signal.traceID)
		if len(spans) != 0 || len(logs) != 0 {
			t.Fatal("CLI disclosed its sibling's exact trace or log")
		}
	}
}

func newWireSignalPair(t *testing.T, service, mark, tenant string) wireSignalPair {
	t.Helper()
	traceID, err := crypto.Random(16)
	if err != nil {
		t.Fatal(err)
	}
	spanID, err := crypto.Random(8)
	if err != nil {
		t.Fatal(err)
	}
	resource := &resourcepb.Resource{Attributes: []*commonpb.KeyValue{{Key: "service.name", Value: wireString(service)}}}
	if tenant != "" {
		resource.Attributes = append(resource.Attributes, &commonpb.KeyValue{Key: otel.AttrTenantID, Value: wireString(tenant)})
	}
	now := uint64(time.Now().UnixNano())
	return wireSignalPair{
		mark: mark, traceID: hex.EncodeToString(traceID), spanID: hex.EncodeToString(spanID),
		traces: &coltracepb.ExportTraceServiceRequest{ResourceSpans: []*tracepb.ResourceSpans{{
			Resource: resource,
			ScopeSpans: []*tracepb.ScopeSpans{{Spans: []*tracepb.Span{{
				TraceId: traceID, SpanId: spanID, Name: mark, Kind: tracepb.Span_SPAN_KIND_SERVER,
				StartTimeUnixNano: now - uint64(time.Millisecond), EndTimeUnixNano: now,
			}}}},
		}}},
		logs: &collogspb.ExportLogsServiceRequest{ResourceLogs: []*logspb.ResourceLogs{{
			Resource: resource,
			ScopeLogs: []*logspb.ScopeLogs{{LogRecords: []*logspb.LogRecord{{
				TraceId: traceID, SpanId: spanID, TimeUnixNano: now,
				SeverityText: "INFO", SeverityNumber: logspb.SeverityNumber_SEVERITY_NUMBER_INFO, Body: wireString(mark),
			}}}},
		}}},
	}
}

func wireString(value string) *commonpb.AnyValue {
	return &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: value}}
}

func sendOTLPHTTPPair(t *testing.T, stack *shipped.Stack, token string, pair wireSignalPair, want int) {
	t.Helper()
	for _, signal := range []struct {
		path string
		body proto.Message
	}{{"traces", pair.traces}, {"logs", pair.logs}} {
		raw, err := proto.Marshal(signal.body)
		if err != nil {
			t.Fatal(err)
		}
		req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, stack.OTLPURL+"/v1/"+signal.path, bytes.NewReader(raw))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/x-protobuf")
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := stack.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != want {
			t.Fatalf("OTLP/HTTP %s returned %d, want %d", signal.path, resp.StatusCode, want)
		}
	}
}

func sendOTLPGRPCPair(t *testing.T, conn *grpc.ClientConn, token string, pair wireSignalPair, want codes.Code) {
	t.Helper()
	ctx, cancel := context.WithTimeout(metadata.AppendToOutgoingContext(t.Context(), "authorization", "Bearer "+token), 15*time.Second)
	defer cancel()
	_, traceErr := coltracepb.NewTraceServiceClient(conn).Export(ctx, pair.traces, grpc.WaitForReady(true))
	_, logsErr := collogspb.NewLogsServiceClient(conn).Export(ctx, pair.logs, grpc.WaitForReady(true))
	if status.Code(traceErr) != want || status.Code(logsErr) != want {
		t.Fatalf("OTLP/gRPC trace and log returned %v and %v, want %v", traceErr, logsErr, want)
	}
}

func readWireSignalPair(t *testing.T, stack *shipped.Stack, cookie, service, traceID string) ([]otelstore.Span, []otelstore.LogRecord) {
	t.Helper()
	query := url.Values{"service": []string{service}, "trace_id": []string{traceID}}.Encode()
	var traces struct{ Spans []otelstore.Span }
	var logs struct{ Logs []otelstore.LogRecord }
	for _, signal := range []struct {
		path string
		out  any
	}{{"traces", &traces}, {"logs", &logs}} {
		code, body := stack.Do(t, cookie, http.MethodGet, "/v1/otlp/"+signal.path+"?"+query, nil)
		if code != http.StatusOK || json.Unmarshal(body, signal.out) != nil {
			t.Fatalf("OTLP %s read failed with status %d", signal.path, code)
		}
	}
	return traces.Spans, logs.Logs
}

func readWireSignalPairCLI(t *testing.T, stack *shipped.Stack, token, service, traceID string) ([]otelstore.Span, []otelstore.LogRecord) {
	t.Helper()
	env := map[string]string{"PROBECTL_API_TOKEN": token}
	var traces struct{ Spans []otelstore.Span }
	var logs struct{ Logs []otelstore.LogRecord }
	stack.MustCLI(t, env, &traces, "otlp", "traces", "--query", "service="+service, "--query", "trace_id="+traceID)
	stack.MustCLI(t, env, &logs, "otlp", "logs", "--query", "service="+service, "--query", "trace_id="+traceID)
	return traces.Spans, logs.Logs
}

func checkWireSignalPair(t *testing.T, tenant string, want wireSignalPair, spans []otelstore.Span, logs []otelstore.LogRecord) {
	t.Helper()
	if len(spans) != 1 || spans[0].TenantID != tenant || spans[0].TraceID != want.traceID ||
		spans[0].SpanID != want.spanID || spans[0].Name != want.mark || spans[0].Duration != time.Millisecond {
		t.Fatalf("expected one exact retained span for %s, got %+v", want.mark, spans)
	}
	if len(logs) != 1 || logs[0].TenantID != tenant || logs[0].TraceID != want.traceID ||
		logs[0].SpanID != want.spanID || logs[0].Body != want.mark || logs[0].SeverityText != "INFO" {
		t.Fatalf("expected one exact retained log for %s, got %+v", want.mark, logs)
	}
}

func checkWireSignalIsolation(t *testing.T, stack *shipped.Stack, conn *grpc.ClientConn, tenant, sibling wireTenant, service string, owned [2]wireSignalPair, refused wireSignalPair) {
	t.Helper()
	for _, signal := range owned {
		spans, logs := readWireSignalPair(t, stack, sibling.cookie, service, signal.traceID)
		if len(spans) != 0 || len(logs) != 0 {
			t.Fatal("tenant read disclosed its sibling's exact trace or log")
		}
	}
	for _, reader := range []wireTenant{tenant, sibling} {
		spans, logs := readWireSignalPair(t, stack, reader.cookie, service, refused.traceID)
		if len(spans) != 0 || len(logs) != 0 {
			t.Fatal("a rejected tenant assignment reached the OTLP stores")
		}
	}
	foreignToken := "/v1/otlp-tokens/" + tenant.token.ID
	if code, _ := stack.Do(t, sibling.cookie, http.MethodDelete, foreignToken, nil); code != http.StatusNotFound {
		t.Fatalf("sibling token revoke returned %d, want 404", code)
	}
	if code, _ := stack.Do(t, tenant.cookie, http.MethodDelete, foreignToken, nil); code != http.StatusNoContent {
		t.Fatalf("owned token revoke returned %d, want 204", code)
	}
	after := newWireSignalPair(t, service, "revoked-"+tenant.id, tenant.id)
	sendOTLPHTTPPair(t, stack, tenant.token.Token, after, http.StatusUnauthorized)
	sendOTLPGRPCPair(t, conn, tenant.token.Token, after, codes.Unauthenticated)
}
