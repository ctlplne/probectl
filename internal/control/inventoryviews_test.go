// SPDX-License-Identifier: LicenseRef-probectl-TBD

package control

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/endpoint"
)

func TestInventorySavedViewsTenantIsolation(t *testing.T) {
	srv := testServer(fakePinger{})
	body := []byte(`{"surface":"endpoints","name":"WiFi trouble","filters":{"cause":"wifi","q":"laptop"}}`)
	rec := doReq(srv, httptest.NewRequest(http.MethodPost, "/v1/inventory/views", bytes.NewReader(body)))
	if rec.Code != http.StatusCreated {
		t.Fatalf("create = %d %s", rec.Code, rec.Body.String())
	}
	var created struct {
		ID       string            `json:"id"`
		TenantID string            `json:"tenant_id"`
		Filters  map[string]string `json:"filters"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if created.TenantID == "" || created.Filters["cause"] != "wifi" {
		t.Fatalf("created = %+v", created)
	}

	listA := doReq(srv, httptest.NewRequest(http.MethodGet, "/v1/inventory/views?surface=endpoints", nil))
	if listA.Code != http.StatusOK || !strings.Contains(listA.Body.String(), created.ID) {
		t.Fatalf("tenant-a list = %d %s", listA.Code, listA.Body.String())
	}
	reqB := httptest.NewRequest(http.MethodGet, "/v1/inventory/views?surface=endpoints", nil)
	reqB.Header.Set("X-Probectl-Tenant", "00000000-0000-0000-0000-000000000002")
	listB := doReq(srv, reqB)
	if listB.Code != http.StatusOK || strings.Contains(listB.Body.String(), created.ID) {
		t.Fatalf("tenant-b list leaked tenant-a view: %d %s", listB.Code, listB.Body.String())
	}
	openB := httptest.NewRequest(http.MethodGet, "/v1/inventory/views/"+created.ID, nil)
	openB.Header.Set("X-Probectl-Tenant", "00000000-0000-0000-0000-000000000002")
	recB := doReq(srv, openB)
	if recB.Code != http.StatusNotFound {
		t.Fatalf("tenant-b open = %d %s", recB.Code, recB.Body.String())
	}
}

func TestEndpointFiltersAreServedTenantScoped(t *testing.T) {
	store := endpointViewFixtureStore()
	srv := testServer(fakePinger{}).WithEndpointViews(store)

	rec := do(srv, http.MethodGet, "/v1/endpoints?cause=wifi&q=anna")
	if rec.Code != http.StatusOK {
		t.Fatalf("filtered status = %d %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "laptop-anna") ||
		strings.Contains(rec.Body.String(), "kiosk-7") ||
		strings.Contains(rec.Body.String(), "secret-ep") {
		t.Fatalf("filtered body = %s", rec.Body.String())
	}
	bad := do(srv, http.MethodGet, "/v1/endpoints?cause=tenant-b")
	if bad.Code != http.StatusUnprocessableEntity {
		t.Fatalf("bad filter = %d %s", bad.Code, bad.Body.String())
	}
}

func doReq(srv *Server, req *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	return rec
}

func endpointViewFixtureStore() *endpoint.SnapshotStore {
	store := endpoint.NewSnapshotStore(0)
	at := time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)
	tenantA := "00000000-0000-0000-0000-000000000001"
	tenantB := "00000000-0000-0000-0000-000000000002"
	store.Record(tenantA, "laptop-anna", endpoint.ResultView{
		Type:       endpoint.TypeAttribution,
		Target:     "app.acme.example",
		Success:    false,
		ObservedAt: at,
		Metrics:    map[string]float64{"slow": 1},
		Attributes: map[string]string{"endpoint.cause": "wifi", "endpoint.summary": "weak RSSI"},
	})
	store.Record(tenantA, "laptop-anna", endpoint.ResultView{
		Type:       endpoint.TypeWiFi,
		Target:     "HomeNet",
		Success:    true,
		ObservedAt: at,
		Attributes: map[string]string{"wifi.ssid": "HomeNet"},
	})
	store.Record(tenantA, "kiosk-7", endpoint.ResultView{
		Type:       endpoint.TypeAttribution,
		Target:     "app.acme.example",
		Success:    false,
		ObservedAt: at,
		Metrics:    map[string]float64{"slow": 1},
		Attributes: map[string]string{"endpoint.cause": "isp"},
	})
	store.Record(tenantB, "secret-ep", endpoint.ResultView{
		Type:       endpoint.TypeAttribution,
		Target:     "secret.example",
		Success:    true,
		ObservedAt: at,
		Attributes: map[string]string{"endpoint.cause": "none"},
	})
	return store
}
