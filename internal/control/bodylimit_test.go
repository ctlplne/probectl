// SPDX-License-Identifier: LicenseRef-probectl-TBD

package control

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/imfeelingtheagi/probectl/internal/apierror"
	"github.com/imfeelingtheagi/probectl/internal/config"
)

func TestDecodeJSONRejectsOversizeAndTrailingValues(t *testing.T) {
	var dst struct {
		Name string `json:"name"`
	}
	tooLarge := httptest.NewRequest(http.MethodPost, "/v1/test", strings.NewReader(`{"name":"`+strings.Repeat("a", maxJSONBody)+`"}`))
	err := decodeJSON(tooLarge, &dst)
	var ae *apierror.Error
	if !errors.As(err, &ae) || ae.Kind != apierror.KindTooLarge {
		t.Fatalf("oversized JSON must return KindTooLarge, got %v", err)
	}

	trailing := httptest.NewRequest(http.MethodPost, "/v1/test", strings.NewReader(`{"name":"ok"} {"name":"extra"}`))
	err = decodeJSON(trailing, &dst)
	if !errors.As(err, &ae) || ae.Kind != apierror.KindBadRequest {
		t.Fatalf("trailing JSON must return KindBadRequest, got %v", err)
	}
}

func TestChangeWebhookOversizeReturns413BeforeSignature(t *testing.T) {
	srv := &Server{cfg: &config.Config{ChangeWebhooks: map[string]config.ChangeWebhook{
		"wh1": {TenantID: "00000000-0000-0000-0000-000000000001", Provider: "generic", Secret: "secret"},
	}}}
	req := httptest.NewRequest(http.MethodPost, "/ingest/changes/generic/wh1", strings.NewReader(strings.Repeat("x", changeWebhookMaxBody+1)))
	req.SetPathValue("provider", "generic")
	req.SetPathValue("id", "wh1")
	rec := httptest.NewRecorder()
	apiHandler(srv.handleChangeWebhook).ServeHTTP(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413; body=%s", rec.Code, rec.Body.String())
	}
}

func TestITSMWebhookOversizeReturns413BeforeDependencyOrSignature(t *testing.T) {
	srv := &Server{cfg: &config.Config{NotifyInbound: map[string]config.NotifyInbound{
		"snow1": {TenantID: "00000000-0000-0000-0000-000000000001", Provider: "servicenow", Secret: "secret"},
	}}}
	req := httptest.NewRequest(http.MethodPost, "/ingest/itsm/servicenow/snow1", strings.NewReader(strings.Repeat("x", itsmWebhookMaxBody+1)))
	req.SetPathValue("provider", "servicenow")
	req.SetPathValue("id", "snow1")
	rec := httptest.NewRecorder()
	apiHandler(srv.handleITSMWebhook).ServeHTTP(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413; body=%s", rec.Code, rec.Body.String())
	}
}

func TestDecodeSCIMRejectsOversizeAndTrailingValues(t *testing.T) {
	var dst map[string]any
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/scim/v2/Users", strings.NewReader(`{"userName":"`+strings.Repeat("a", scimMaxBody)+`"}`))
	if decodeSCIM(rec, req, &dst) {
		t.Fatal("oversized SCIM body should fail")
	}
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized status = %d, want 413; body=%s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/scim/v2/Users", strings.NewReader(`{"userName":"a"} {"userName":"b"}`))
	if decodeSCIM(rec, req, &dst) {
		t.Fatal("SCIM body with trailing JSON should fail")
	}
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("trailing status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
}
