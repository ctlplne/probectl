// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package otlp

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	collogspb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	coltracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	logspb "go.opentelemetry.io/proto/otlp/logs/v1"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/ctlplne/probectl/internal/otel"
)

// --- helpers: tenant-stamped trace/log requests (the signals.go side has no
// generated builders like convert.go's MetricsRequest, so build them here) ---

func tenantResource(tenant string) *resourcepb.Resource {
	return &resourcepb.Resource{Attributes: []*commonpb.KeyValue{{
		Key:   otel.AttrTenantID,
		Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: tenant}},
	}}}
}

func stringKV(key, value string) *commonpb.KeyValue {
	return &commonpb.KeyValue{
		Key:   key,
		Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: value}},
	}
}

// traceReq builds a one-ResourceSpans request. tenant=="" leaves the Resource
// nil (to exercise the stamp-an-unset-resource path).
func traceReq(tenant string) *coltracepb.ExportTraceServiceRequest {
	rs := &tracepb.ResourceSpans{}
	if tenant != "" {
		rs.Resource = tenantResource(tenant)
	}
	return &coltracepb.ExportTraceServiceRequest{ResourceSpans: []*tracepb.ResourceSpans{rs}}
}

func logReq(tenant string) *collogspb.ExportLogsServiceRequest {
	rl := &logspb.ResourceLogs{}
	if tenant != "" {
		rl.Resource = tenantResource(tenant)
	}
	return &collogspb.ExportLogsServiceRequest{ResourceLogs: []*logspb.ResourceLogs{rl}}
}

func mustMarshal(t *testing.T, m proto.Message) []byte {
	t.Helper()
	b, err := proto.Marshal(m)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

func TestResourceTenantOfAndStampResource(t *testing.T) {
	if got := resourceTenantOf(tenantResource("t-a")); got != "t-a" {
		t.Errorf("resourceTenantOf = %q, want t-a", got)
	}
	if got := resourceTenantOf(&resourcepb.Resource{}); got != "" {
		t.Errorf("resourceTenantOf(empty) = %q, want empty", got)
	}

	// stamp an empty resource
	r := &resourcepb.Resource{}
	stampResource(r, "t-a")
	if got := resourceTenantOf(r); got != "t-a" {
		t.Errorf("after stamp = %q, want t-a", got)
	}

	// U-082: an EMPTY-valued tenant attr must be overwritten IN PLACE, not
	// shadowed by an appended one.
	r2 := &resourcepb.Resource{Attributes: []*commonpb.KeyValue{{
		Key:   otel.AttrTenantID,
		Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: ""}},
	}}}
	stampResource(r2, "t-b")
	if got := resourceTenantOf(r2); got != "t-b" {
		t.Errorf("overwrite-empty = %q, want t-b", got)
	}
	if len(r2.Attributes) != 1 {
		t.Errorf("overwrite-empty appended instead of replacing: %d attrs", len(r2.Attributes))
	}
}

func TestScopeTracesToTenant(t *testing.T) {
	if err := scopeTracesToTenant(traceReq("t-b"), "t-a"); err == nil {
		t.Error("mismatched tenant must be rejected")
	}
	if err := scopeTracesToTenant(traceReq("t-a"), "t-a"); err != nil {
		t.Errorf("matching tenant: %v", err)
	}
	req := traceReq("") // unset resource -> created + stamped
	if err := scopeTracesToTenant(req, "t-a"); err != nil {
		t.Fatalf("unstamped: %v", err)
	}
	if got := resourceTenantOf(req.ResourceSpans[0].Resource); got != "t-a" {
		t.Errorf("unstamped span resource = %q, want t-a", got)
	}
}

func TestScopeLogsToTenant(t *testing.T) {
	if err := scopeLogsToTenant(logReq("t-b"), "t-a"); err == nil {
		t.Error("mismatched tenant must be rejected")
	}
	if err := scopeLogsToTenant(logReq("t-a"), "t-a"); err != nil {
		t.Errorf("matching tenant: %v", err)
	}
	req := logReq("")
	if err := scopeLogsToTenant(req, "t-a"); err != nil {
		t.Fatalf("unstamped: %v", err)
	}
	if got := resourceTenantOf(req.ResourceLogs[0].Resource); got != "t-a" {
		t.Errorf("unstamped log resource = %q, want t-a", got)
	}
}

// dupTenantResource builds a resource carrying one probectl.tenant.id attribute
// per value (so ("", "victim") produces the ING-39 duplicate-key shape).
func dupTenantResource(values ...string) *resourcepb.Resource {
	res := &resourcepb.Resource{}
	for _, v := range values {
		res.Attributes = append(res.Attributes, stringKV(otel.AttrTenantID, v))
	}
	return res
}

func dupTenantTraceReq(values ...string) *coltracepb.ExportTraceServiceRequest {
	return &coltracepb.ExportTraceServiceRequest{ResourceSpans: []*tracepb.ResourceSpans{{Resource: dupTenantResource(values...)}}}
}

func dupTenantLogReq(values ...string) *collogspb.ExportLogsServiceRequest {
	return &collogspb.ExportLogsServiceRequest{ResourceLogs: []*logspb.ResourceLogs{{Resource: dupTenantResource(values...)}}}
}

// TestScopeSignalsRejectDuplicateTenantAttr is the ING-39 regression on the
// traces/logs INGEST scoping boundary (docs/guardrails.md G7-1). A resource
// carrying DUPLICATE tenant attributes ["", "victim"] pushed by "attacker"
// used to pass first-match scoping, leaving the foreign "victim" value on the
// resource to ride through to OTLP export. Scoping must now fail closed on the
// duplicate (and on a non-string tenant attribute), while an ordinary
// single-tenant resource is still accepted and scoped.
func TestScopeSignalsRejectDuplicateTenantAttr(t *testing.T) {
	// --- duplicate ["", "victim"] authenticated as attacker: REJECTED ---
	if err := scopeTracesToTenant(dupTenantTraceReq("", "victim"), "attacker"); err == nil {
		t.Fatal("ING-39: duplicate tenant attrs [\"\", \"victim\"] on traces authed as attacker were ACCEPTED (want reject); the foreign \"victim\" value survives first-match scoping and rides through to export")
	}
	if err := scopeLogsToTenant(dupTenantLogReq("", "victim"), "attacker"); err == nil {
		t.Fatal("ING-39: duplicate tenant attrs [\"\", \"victim\"] on logs authed as attacker were ACCEPTED (want reject); the foreign \"victim\" value survives first-match scoping and rides through to export")
	}

	// A duplicate whose values all match the authenticated tenant is still a
	// malformed resource and is rejected — fail closed on the shape, not the
	// values.
	if err := scopeTracesToTenant(dupTenantTraceReq("attacker", "attacker"), "attacker"); err == nil {
		t.Error("duplicate tenant attrs must be rejected even when every value matches the authenticated tenant")
	}

	// --- non-string tenant attribute: REJECTED (cannot be read as a tenant) ---
	badTrace := &coltracepb.ExportTraceServiceRequest{ResourceSpans: []*tracepb.ResourceSpans{{
		Resource: &resourcepb.Resource{Attributes: []*commonpb.KeyValue{{
			Key:   otel.AttrTenantID,
			Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_IntValue{IntValue: 7}},
		}}},
	}}}
	if err := scopeTracesToTenant(badTrace, "attacker"); err == nil {
		t.Error("non-string tenant attribute must be rejected")
	}

	// --- non-vacuity: a normal single-tenant resource is accepted and scoped ---
	ok := traceReq("attacker")
	if err := scopeTracesToTenant(ok, "attacker"); err != nil {
		t.Fatalf("single-tenant trace resource rejected: %v", err)
	}
	if got := resourceTenantOf(ok.ResourceSpans[0].Resource); got != "attacker" {
		t.Errorf("single-tenant trace scoped to %q, want attacker", got)
	}
	// And an unscoped resource is stamped with exactly the authenticated tenant.
	stamped := traceReq("")
	if err := scopeTracesToTenant(stamped, "attacker"); err != nil {
		t.Fatalf("unscoped trace resource rejected: %v", err)
	}
	if n := tenantAttrCount(stamped.ResourceSpans[0].Resource); n != 1 {
		t.Errorf("stamped resource has %d tenant attrs, want exactly 1", n)
	}
}

// TestScopeSignalsHandlerRejectsDuplicateTenantAttr drives the same ING-39
// regression through the real OTLP/HTTP ingest handler: a duplicate-tenant push
// must be rejected (403) and never reach the sink.
func TestScopeSignalsHandlerRejectsDuplicateTenantAttr(t *testing.T) {
	auth := NewTokenAuthenticator(map[string]string{"tok": "attacker"})
	reached := false
	h := TracesHTTPHandler(auth, TraceSinkFunc(func(context.Context, string, *coltracepb.ExportTraceServiceRequest) error {
		reached = true
		return nil
	}), 1<<20)
	srv := httptest.NewServer(h)
	defer srv.Close()

	if code := post(t, srv.URL, "tok", http.MethodPost, mustMarshal(t, dupTenantTraceReq("", "victim"))); code != http.StatusForbidden {
		t.Fatalf("duplicate-tenant trace push = %d, want 403", code)
	}
	if reached {
		t.Fatal("duplicate-tenant trace push reached the sink (must fail closed before consume)")
	}
}

func tenantAttrCount(res *resourcepb.Resource) int {
	n := 0
	for _, kv := range res.GetAttributes() {
		if kv.GetKey() == otel.AttrTenantID {
			n++
		}
	}
	return n
}

func TestSinksValidateRejectsIncomplete(t *testing.T) {
	if err := (Sinks{}).validate(); err == nil {
		t.Error("empty Sinks must be rejected")
	}
	// traces + logs present but metrics missing -> still rejected
	partial := Sinks{
		Traces: TraceSinkFunc(func(context.Context, string, *coltracepb.ExportTraceServiceRequest) error { return nil }),
		Logs:   LogSinkFunc(func(context.Context, string, *collogspb.ExportLogsServiceRequest) error { return nil }),
	}
	if err := partial.validate(); err == nil {
		t.Error("missing metrics sink must be rejected")
	}
}

func TestNewBusTraceAndLogSinks(t *testing.T) {
	var (
		gotTenant  string
		gotEntropy string
		gotPayload []byte
	)
	ts := NewBusTraceSink(func(_ context.Context, tenant, entropy string, payload []byte) error {
		gotTenant, gotEntropy, gotPayload = tenant, entropy, payload
		return nil
	})
	tr := traceReq("t-a")
	tr.ResourceSpans[0].Resource.Attributes = append(tr.ResourceSpans[0].Resource.Attributes, stringKV("service.name", "checkout"))
	if err := ts.ConsumeTraces(context.Background(), "t-a", tr); err != nil {
		t.Fatalf("ConsumeTraces: %v", err)
	}
	if gotTenant != "t-a" || gotEntropy == "" || len(gotPayload) == 0 {
		t.Errorf("bus trace sink: tenant=%q entropy=%q payloadLen=%d", gotTenant, gotEntropy, len(gotPayload))
	}

	ls := NewBusLogSink(func(_ context.Context, tenant, entropy string, payload []byte) error {
		gotTenant, gotEntropy, gotPayload = tenant, entropy, payload
		return nil
	})
	lr := logReq("t-b")
	lr.ResourceLogs[0].Resource.Attributes = append(lr.ResourceLogs[0].Resource.Attributes, stringKV("service.name", "checkout"))
	if err := ls.ConsumeLogs(context.Background(), "t-b", lr); err != nil {
		t.Fatalf("ConsumeLogs: %v", err)
	}
	if gotTenant != "t-b" || gotEntropy == "" || len(gotPayload) == 0 {
		t.Errorf("bus log sink: tenant=%q entropy=%q payloadLen=%d", gotTenant, gotEntropy, len(gotPayload))
	}
}

func TestTraceServiceExport(t *testing.T) {
	var got string
	svc := &traceService{sink: TraceSinkFunc(func(_ context.Context, tenant string, _ *coltracepb.ExportTraceServiceRequest) error {
		got = tenant
		return nil
	})}

	if _, err := svc.Export(context.Background(), traceReq("")); status.Code(err) != codes.Unauthenticated {
		t.Errorf("no tenant: code = %v, want Unauthenticated", status.Code(err))
	}
	ctx := withTenant(context.Background(), "t-a")
	if _, err := svc.Export(ctx, traceReq("t-b")); status.Code(err) != codes.PermissionDenied {
		t.Errorf("mismatch: code = %v, want PermissionDenied", status.Code(err))
	}
	if _, err := svc.Export(ctx, traceReq("t-a")); err != nil {
		t.Errorf("valid: %v", err)
	}
	if got != "t-a" {
		t.Errorf("sink tenant = %q, want t-a", got)
	}

	bad := &traceService{sink: TraceSinkFunc(func(context.Context, string, *coltracepb.ExportTraceServiceRequest) error {
		return errors.New("boom")
	})}
	if _, err := bad.Export(ctx, traceReq("t-a")); status.Code(err) != codes.Internal {
		t.Errorf("sink error: code = %v, want Internal", status.Code(err))
	}
}

func TestLogsServiceExport(t *testing.T) {
	var got string
	svc := &logsService{sink: LogSinkFunc(func(_ context.Context, tenant string, _ *collogspb.ExportLogsServiceRequest) error {
		got = tenant
		return nil
	})}

	if _, err := svc.Export(context.Background(), logReq("")); status.Code(err) != codes.Unauthenticated {
		t.Errorf("no tenant: code = %v, want Unauthenticated", status.Code(err))
	}
	ctx := withTenant(context.Background(), "t-a")
	if _, err := svc.Export(ctx, logReq("t-b")); status.Code(err) != codes.PermissionDenied {
		t.Errorf("mismatch: code = %v, want PermissionDenied", status.Code(err))
	}
	if _, err := svc.Export(ctx, logReq("t-a")); err != nil {
		t.Errorf("valid: %v", err)
	}
	if got != "t-a" {
		t.Errorf("sink tenant = %q, want t-a", got)
	}

	bad := &logsService{sink: LogSinkFunc(func(context.Context, string, *collogspb.ExportLogsServiceRequest) error {
		return errors.New("boom")
	})}
	if _, err := bad.Export(ctx, logReq("t-a")); status.Code(err) != codes.Internal {
		t.Errorf("sink error: code = %v, want Internal", status.Code(err))
	}
}

// post issues one request and returns the status code.
func post(t *testing.T, url, token, method string, body []byte) int {
	t.Helper()
	r, _ := http.NewRequest(method, url, bytes.NewReader(body))
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	r.Header.Set("Content-Type", "application/x-protobuf")
	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	return resp.StatusCode
}

func TestTracesHTTPHandler(t *testing.T) {
	auth := NewTokenAuthenticator(map[string]string{"tok": "t-a"})
	var captured string
	h := TracesHTTPHandler(auth, TraceSinkFunc(func(_ context.Context, tenant string, _ *coltracepb.ExportTraceServiceRequest) error {
		captured = tenant
		return nil
	}), 1<<20)
	srv := httptest.NewServer(h)
	defer srv.Close()

	if code := post(t, srv.URL, "tok", http.MethodGet, nil); code != http.StatusMethodNotAllowed {
		t.Errorf("GET: %d, want 405", code)
	}
	if code := post(t, srv.URL, "", http.MethodPost, mustMarshal(t, traceReq("t-a"))); code != http.StatusUnauthorized {
		t.Errorf("no token: %d, want 401", code)
	}
	// truncated length-delimited field 1 -> invalid protobuf
	if code := post(t, srv.URL, "tok", http.MethodPost, []byte{0x0a, 0x05, 0x01}); code != http.StatusBadRequest {
		t.Errorf("bad payload: %d, want 400", code)
	}
	if code := post(t, srv.URL, "tok", http.MethodPost, mustMarshal(t, traceReq("t-b"))); code != http.StatusForbidden {
		t.Errorf("out-of-tenant: %d, want 403", code)
	}
	if code := post(t, srv.URL, "tok", http.MethodPost, mustMarshal(t, traceReq("t-a"))); code != http.StatusOK {
		t.Errorf("valid: %d, want 200", code)
	}
	if captured != "t-a" {
		t.Errorf("sink tenant = %q, want t-a", captured)
	}

	// maxBytes too small -> body read fails -> 400 (also: maxBytes<=0 default branch)
	small := httptest.NewServer(TracesHTTPHandler(auth, TraceSinkFunc(func(context.Context, string, *coltracepb.ExportTraceServiceRequest) error { return nil }), 1))
	defer small.Close()
	if code := post(t, small.URL, "tok", http.MethodPost, mustMarshal(t, traceReq("t-a"))); code != http.StatusBadRequest {
		t.Errorf("oversized body: %d, want 400", code)
	}
}

func TestLogsHTTPHandler(t *testing.T) {
	auth := NewTokenAuthenticator(map[string]string{"tok": "t-a"})
	var captured string
	// maxBytes 0 exercises the defaultMaxRecvBytes branch.
	h := LogsHTTPHandler(auth, LogSinkFunc(func(_ context.Context, tenant string, _ *collogspb.ExportLogsServiceRequest) error {
		captured = tenant
		return nil
	}), 0)
	srv := httptest.NewServer(h)
	defer srv.Close()

	if code := post(t, srv.URL, "tok", http.MethodPost, mustMarshal(t, logReq("t-a"))); code != http.StatusOK {
		t.Errorf("valid: %d, want 200", code)
	}
	if captured != "t-a" {
		t.Errorf("sink tenant = %q, want t-a", captured)
	}
	if code := post(t, srv.URL, "tok", http.MethodPost, mustMarshal(t, logReq("t-b"))); code != http.StatusForbidden {
		t.Errorf("out-of-tenant: %d, want 403", code)
	}

	// sink error -> 500
	errSrv := httptest.NewServer(LogsHTTPHandler(auth, LogSinkFunc(func(context.Context, string, *collogspb.ExportLogsServiceRequest) error {
		return errors.New("boom")
	}), 1<<20))
	defer errSrv.Close()
	if code := post(t, errSrv.URL, "tok", http.MethodPost, mustMarshal(t, logReq("t-a"))); code != http.StatusInternalServerError {
		t.Errorf("sink error: %d, want 500", code)
	}
}
