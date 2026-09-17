// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package control

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/tenantlife"
)

type fakeTenantLifecycle struct {
	policy           tenantlife.RetentionPolicy
	set              tenantlife.RetentionPolicy
	setErr           error
	setActor         string
	setContextTenant string
}

func (f *fakeTenantLifecycle) ExportRedacted(context.Context, string, io.Writer, bool) (tenantlife.Manifest, error) {
	return tenantlife.Manifest{}, errors.New("not implemented")
}

func (f *fakeTenantLifecycle) ExportSubject(context.Context, string, string, io.Writer, bool) (tenantlife.SubjectManifest, error) {
	return tenantlife.SubjectManifest{}, errors.New("not implemented")
}

func (f *fakeTenantLifecycle) RetentionFor(_ context.Context, tenantID string) (tenantlife.RetentionPolicy, error) {
	p := f.policy
	p.TenantID = tenantID
	return p, nil
}

func (f *fakeTenantLifecycle) SetRetention(
	ctx context.Context,
	p tenantlife.RetentionPolicy,
	actor string,
) error {
	f.set = p
	f.setActor = actor
	if tenantID, ok := tenancy.FromContext(ctx); ok {
		f.setContextTenant = tenantID.String()
	}
	if f.setErr != nil {
		return f.setErr
	}
	f.policy = p
	return nil
}

func (f *fakeTenantLifecycle) Erase(context.Context, string, string, string) (tenantlife.Attestation, error) {
	return tenantlife.Attestation{}, errors.New("not implemented")
}

func (f *fakeTenantLifecycle) EraseSubject(context.Context, string, string, string, string) (tenantlife.SubjectErasureReport, error) {
	return tenantlife.SubjectErasureReport{}, errors.New("not implemented")
}

func lifecycleReq(t *testing.T, srv *Server, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var r io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal request body: %v", err)
		}
		r = bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, path, r)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	return rec
}

func decodeLifecycleJSON(t *testing.T, rec *httptest.ResponseRecorder) map[string]json.RawMessage {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	var got map[string]json.RawMessage
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	return got
}

func jsonKeys(m map[string]json.RawMessage) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func TestLifecycleRetentionGetAndPutReturnLifecycleStatus(t *testing.T) {
	tid := tenancy.DefaultTenantID.String()
	days := 30
	otelDays := 21
	fake := &fakeTenantLifecycle{policy: tenantlife.RetentionPolicy{
		FlowRetentionDays: &days,
		OtelRetentionDays: &otelDays,
		UpdatedBy:         "dev@probectl.local", // DPR-083: attributed to the principal
	}}
	srv := testServer(fakePinger{})
	srv.tenantLife = fake

	getBody := decodeLifecycleJSON(t, lifecycleReq(t, srv, http.MethodGet, "/v1/lifecycle/retention", nil))
	putBody := decodeLifecycleJSON(t, lifecycleReq(t, srv, http.MethodPut, "/v1/lifecycle/retention", map[string]any{
		"flow_retention_days": 14,
		"otel_retention_days": 7,
		"ebpf_retention_days": 7,
	}))

	if !reflect.DeepEqual(jsonKeys(getBody), jsonKeys(putBody)) {
		t.Fatalf("GET and PUT response keys differ: GET=%v PUT=%v", jsonKeys(getBody), jsonKeys(putBody))
	}
	if string(putBody["isolation_model"]) != `"pooled"` {
		t.Fatalf("PUT isolation_model = %s, want pooled", putBody["isolation_model"])
	}
	if string(putBody["flow_retention_days"]) != "14" {
		t.Fatalf("PUT flow_retention_days = %s, want 14", putBody["flow_retention_days"])
	}
	if string(putBody["otel_retention_days"]) != "7" {
		t.Fatalf("PUT otel_retention_days = %s, want 7", putBody["otel_retention_days"])
	}
	if fake.set.TenantID != tid || fake.set.UpdatedBy != "dev@probectl.local" || fake.set.EBPFRetentionDays == nil || *fake.set.EBPFRetentionDays != 7 {
		t.Fatalf("set policy = %+v, want tenant-bound policy", fake.set)
	}
	if fake.setActor != "dev@probectl.local" {
		t.Fatalf("retention audit actor = %q, want authenticated request actor", fake.setActor)
	}
	if fake.setContextTenant != tid {
		t.Fatalf("retention caller context = %q, want authoritative tenant %q", fake.setContextTenant, tid)
	}
	auditPolicy, found := auditPolicyFor(http.MethodPut, "/v1/lifecycle/retention")
	if !found || auditPolicy.Mode != auditModeExplicit || auditPolicy.Action != "lifecycle.retention_set" {
		t.Fatalf("retention route audit policy = %+v found=%t, want explicit lifecycle.retention_set", auditPolicy, found)
	}
}

func TestLifecycleRetentionPolicyAuditFailureReturnsStableError(t *testing.T) {
	const rawAuditError = "audit database password=do-not-return unavailable"
	fake := &fakeTenantLifecycle{setErr: errors.New(rawAuditError)}
	srv := testServer(fakePinger{})
	srv.tenantLife = fake

	rec := lifecycleReq(t, srv, http.MethodPut, "/v1/lifecycle/retention", map[string]any{
		"flow_retention_days": 14,
	})
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500: %s", rec.Code, rec.Body.String())
	}
	rawBody := rec.Body.String()
	var body struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.NewDecoder(strings.NewReader(rawBody)).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.Error.Code != "internal" || body.Error.Message != "retention update failed" {
		t.Fatalf("stable error = %+v", body.Error)
	}
	if strings.Contains(rawBody, rawAuditError) {
		t.Fatalf("response leaked audit dependency detail: %s", rawBody)
	}
	if fake.setActor != "dev@probectl.local" ||
		fake.setContextTenant != tenancy.DefaultTenantID.String() {
		t.Fatalf(
			"handler omitted bounded audit actor or authoritative tenant context: actor=%q tenant=%q",
			fake.setActor,
			fake.setContextTenant,
		)
	}
}

func TestTenantAuditRetentionBoundReturnsClientValidationError(t *testing.T) {
	fake := &fakeTenantLifecycle{setErr: tenantlife.ErrAuditRetentionExceedsMaximum}
	srv := testServer(fakePinger{})
	srv.tenantLife = fake

	rec := lifecycleReq(t, srv, http.MethodPut, "/v1/lifecycle/retention", map[string]any{
		"audit_retention_days": 366,
	})
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422: %s", rec.Code, rec.Body.String())
	}
	var body struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.Error.Code != "validation" ||
		body.Error.Message != "audit_retention_days cannot exceed the deployment audit-retention maximum" {
		t.Fatalf("client validation error = %+v", body.Error)
	}
	if fake.set.AuditRetentionDays == nil || *fake.set.AuditRetentionDays != 366 {
		t.Fatalf("engine did not receive bounded tenant audit policy: %+v", fake.set)
	}
}
