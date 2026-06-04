package control

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/imfeelingtheagi/probectl/internal/bus"
	"github.com/imfeelingtheagi/probectl/internal/endpoint"
	resultv1 "github.com/imfeelingtheagi/probectl/internal/gen/probectl/result/v1"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
)

func endpointResult(tenant, agent, typ, target string, metrics map[string]float64, attrs map[string]string, at time.Time) *resultv1.Result {
	return &resultv1.Result{
		TenantId: tenant, AgentId: agent, CanaryType: typ, ServerAddress: target,
		Success: true, StartTimeUnixNano: at.UnixNano(), Metrics: metrics, Attributes: attrs,
	}
}

// TestEndpointViewEndToEnd: results published on the endpoint topic land in the
// snapshot store and serve through /v1/endpoints, tenant-scoped.
func TestEndpointViewEndToEnd(t *testing.T) {
	b := bus.NewMemory()
	store := endpoint.NewSnapshotStore(0)
	consumer := NewEndpointViewConsumer(b, store, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = consumer.Run(ctx) }()
	time.Sleep(20 * time.Millisecond)

	at := time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC)
	def := tenancy.DefaultTenantID.String()
	publish := func(r *resultv1.Result) {
		value, err := proto.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		if err := b.Publish(ctx, bus.EndpointResultsTopic, []byte(r.GetTenantId()), value); err != nil {
			t.Fatal(err)
		}
	}
	publish(endpointResult(def, "laptop-1", "endpoint.attribution", "app.acme.example",
		map[string]float64{"confidence": 0.8, "slow": 1, "wifi_score": 0.9},
		map[string]string{"endpoint.cause": "wifi", "endpoint.summary": "weak RSSI"}, at))
	publish(endpointResult(def, "laptop-1", "endpoint.wifi", "HomeNet",
		map[string]float64{"rssi_dbm": -82, "associated": 1},
		map[string]string{"wifi.ssid": "HomeNet", "wifi.band": "2.4GHz"}, at))
	publish(endpointResult("00000000-0000-0000-0000-000000000002", "secret-ep", "endpoint.attribution", "x",
		map[string]float64{"slow": 0}, map[string]string{"endpoint.cause": "none"}, at))
	_ = b.Publish(ctx, bus.EndpointResultsTopic, []byte(def), []byte("garbage")) // dropped, never wedges

	srv := testServer(fakePinger{}).WithEndpointViews(store)
	deadline := time.Now().Add(2 * time.Second)
	for {
		rec := do(srv, http.MethodGet, "/v1/endpoints")
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d", rec.Code)
		}
		var resp struct {
			CollectorRunning bool            `json:"collector_running"`
			Items            []endpoint.View `json:"items"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatal(err)
		}
		if len(resp.Items) == 1 && resp.Items[0].WiFi != nil {
			v := resp.Items[0]
			if !resp.CollectorRunning || v.AgentID != "laptop-1" || v.Cause != "wifi" || !v.Slow {
				t.Fatalf("view = %+v", v)
			}
			if v.WiFi.Metrics["rssi_dbm"] != -82 || v.WiFi.Attributes["wifi.ssid"] != "HomeNet" {
				t.Fatalf("wifi = %+v", v.WiFi)
			}
			if strings.Contains(rec.Body.String(), "secret-ep") {
				t.Fatalf("CROSS-TENANT LEAK: %s", rec.Body.String())
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("view never landed: %s", rec.Body.String())
		}
		time.Sleep(10 * time.Millisecond)
	}

	// The other tenant sees only its own endpoint.
	rec2 := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/endpoints", nil)
	req.Header.Set("X-Probectl-Tenant", "00000000-0000-0000-0000-000000000002")
	srv.Handler().ServeHTTP(rec2, req)
	if !strings.Contains(rec2.Body.String(), "secret-ep") || strings.Contains(rec2.Body.String(), "laptop-1") {
		t.Fatalf("other-tenant view wrong: %s", rec2.Body.String())
	}

	// No store wired: honest empty response.
	bare := do(testServer(fakePinger{}), http.MethodGet, "/v1/endpoints")
	if bare.Code != http.StatusOK || !strings.Contains(bare.Body.String(), `"collector_running":false`) {
		t.Fatalf("bare = %d %s", bare.Code, bare.Body.String())
	}
}

func TestEndpointsRoutePerm(t *testing.T) {
	for _, rt := range testServer(fakePinger{}).apiRoutes() {
		if rt.Pattern == "/v1/endpoints" {
			if rt.Permission != permAgentRead {
				t.Fatalf("perm = %q, want agent.read", rt.Permission)
			}
			return
		}
	}
	t.Fatal("/v1/endpoints not registered")
}
