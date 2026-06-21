// SPDX-License-Identifier: LicenseRef-probectl-TBD

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
	"testing"

	"github.com/imfeelingtheagi/probectl/internal/tenancy"
	"github.com/imfeelingtheagi/probectl/internal/tenantlife"
)

type fakeTenantLifecycle struct {
	policy tenantlife.RetentionPolicy
	set    tenantlife.RetentionPolicy
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

func (f *fakeTenantLifecycle) SetRetention(_ context.Context, p tenantlife.RetentionPolicy) error {
	f.policy = p
	f.set = p
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
	fake := &fakeTenantLifecycle{policy: tenantlife.RetentionPolicy{
		FlowRetentionDays: &days,
		UpdatedBy:         "tenant:" + tid,
	}}
	srv := testServer(fakePinger{})
	srv.tenantLife = fake

	var auditedTenant string
	var auditedDays *int
	prev := recordLifecycleRetentionAudit
	recordLifecycleRetentionAudit = func(_ *Server, _ *http.Request, tid string, days *int) error {
		auditedTenant = tid
		auditedDays = days
		return nil
	}
	t.Cleanup(func() { recordLifecycleRetentionAudit = prev })

	getBody := decodeLifecycleJSON(t, lifecycleReq(t, srv, http.MethodGet, "/v1/lifecycle/retention", nil))
	putBody := decodeLifecycleJSON(t, lifecycleReq(t, srv, http.MethodPut, "/v1/lifecycle/retention", map[string]any{
		"flow_retention_days": 14,
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
	if fake.set.TenantID != tid || fake.set.UpdatedBy != "tenant:"+tid {
		t.Fatalf("set policy = %+v, want tenant-bound policy", fake.set)
	}
	if auditedTenant != tid || auditedDays == nil || *auditedDays != 14 {
		t.Fatalf("audit capture tenant=%q days=%v, want %q/14", auditedTenant, auditedDays, tid)
	}
}
