// SPDX-License-Identifier: LicenseRef-probectl-TBD

//go:build integration

package control

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/imfeelingtheagi/probectl/internal/bus"
	"github.com/imfeelingtheagi/probectl/internal/config"
	"github.com/imfeelingtheagi/probectl/internal/enroll"
	bgpv1 "github.com/imfeelingtheagi/probectl/internal/gen/probectl/bgp/v1"
	"github.com/imfeelingtheagi/probectl/internal/logging"
	"github.com/imfeelingtheagi/probectl/internal/pipeline"
	"github.com/imfeelingtheagi/probectl/internal/store"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
	"github.com/imfeelingtheagi/probectl/internal/tenantcrypto"
	"github.com/imfeelingtheagi/probectl/internal/topology"
)

func collectorEnrollService(t *testing.T, db *store.DB) *enroll.Service {
	t.Helper()
	ctx := context.Background()
	tenantcrypto.Reset()
	t.Cleanup(tenantcrypto.Reset)
	kek := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
	sealer, err := tenantcrypto.NewEnvelopeSealer("test", kek)
	if err != nil {
		t.Fatalf("test envelope sealer: %v", err)
	}
	tenantcrypto.SetPrimary(sealer)
	if _, err := enroll.InitCA(ctx, db.Pool()); err != nil && !strings.Contains(err.Error(), "already initialized") {
		t.Fatalf("init CA: %v", err)
	}
	svc, err := enroll.Load(ctx, db.Pool(), nil)
	if err != nil {
		t.Fatalf("load enrollment service: %v", err)
	}
	return svc
}

func TestCollectorRegistrationIsTenantScopedAndPublishBound(t *testing.T) {
	db := changeDB(t)
	svc := collectorEnrollService(t, db)
	tenantA := freshTenant(t, db, "collector-a")
	tenantB := freshTenant(t, db, "collector-b")
	agentID := uuid(t)

	srv := New(&config.Config{AuthMode: "dev"}, logging.New(io.Discard, "error", "json"), db, db.Pool(), nil, nil)
	srv.SetEnrollService(svc)
	h := srv.Handler()

	token, _, err := svc.MintToken(context.Background(), tenantA, agentID, "edge-flow-1", "test", time.Hour)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}

	cross := apiReq(t, h, http.MethodPost, "/v1/collectors/register", tenantB, map[string]any{
		"token": token, "plane": "flow", "hostname": "edge-flow-1",
	})
	if cross.Code != http.StatusUnauthorized {
		t.Fatalf("cross-tenant registration = %d %s, want 401", cross.Code, cross.Body)
	}

	ok := apiReq(t, h, http.MethodPost, "/v1/collectors/register", tenantA, map[string]any{
		"token": token, "plane": "flow", "hostname": "edge-flow-1",
	})
	if ok.Code != http.StatusCreated {
		t.Fatalf("tenant registration = %d %s, want 201", ok.Code, ok.Body)
	}
	var out collectorRegistrationResponse
	if err := json.Unmarshal(ok.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if out.TenantID != tenantA || out.AgentID != agentID || out.Plane != "flow" {
		t.Fatalf("registration response = %+v", out)
	}
	if got := out.Config.Env["PROBECTL_FLOW_AGENT_ID"]; got != agentID {
		t.Fatalf("flow env agent id = %q, want %q", got, agentID)
	}

	binding := pipeline.NewRegistryBinding(db.Pool())
	if err := binding.Verify(context.Background(), tenantA, agentID); err != nil {
		t.Fatalf("registered collector must be publish-bound in its tenant: %v", err)
	}
	if err := binding.Verify(context.Background(), tenantB, agentID); err == nil {
		t.Fatal("collector publish binding crossed tenants")
	}

	if err := tenancy.InTenant(tenancy.WithTenant(context.Background(), tenancy.ID(tenantA)), db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
		a, err := (store.Agents{}).Get(ctx, sc, agentID)
		if err != nil {
			return err
		}
		got := strings.Join(a.Capabilities, ",")
		if got != "collector,flow" {
			t.Fatalf("capabilities = %q, want collector,flow", got)
		}
		return nil
	}); err != nil {
		t.Fatalf("read registered collector: %v", err)
	}
}

func TestBGPCollectorRegistrationReturnsBMPConfigAndPublishBinding(t *testing.T) {
	db := changeDB(t)
	svc := collectorEnrollService(t, db)
	tenant := freshTenant(t, db, "collector-bgp")
	agentID := uuid(t)

	srv := New(&config.Config{AuthMode: "dev"}, logging.New(io.Discard, "error", "json"), db, db.Pool(), nil, nil)
	srv.SetEnrollService(svc)
	h := srv.Handler()

	token, _, err := svc.MintToken(context.Background(), tenant, agentID, "rrc00", "test", time.Hour)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}

	rec := apiReq(t, h, http.MethodPost, "/v1/collectors/register", tenant, map[string]any{
		"token": token, "plane": "bgp", "hostname": "rrc00",
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("BGP registration = %d %s, want 201", rec.Code, rec.Body)
	}
	var out collectorRegistrationResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if out.TenantID != tenant || out.AgentID != agentID || out.Plane != "bgp" || out.Hostname != "rrc00" {
		t.Fatalf("registration response = %+v", out)
	}
	if out.Config.StartupCommand != "probectl-bmp-listener" {
		t.Fatalf("startup command = %q, want probectl-bmp-listener", out.Config.StartupCommand)
	}
	if got := out.Config.Env["PROBECTL_BMP_COLLECTOR"]; got != agentID {
		t.Fatalf("BMP collector env = %q, want %q", got, agentID)
	}
	if got := out.Config.Env["PROBECTL_BMP_BUS_TLS_ENABLED"]; got != "true" {
		t.Fatalf("BMP bus TLS env = %q, want true", got)
	}
	if got := out.Config.YAML["source_type"]; got != "bmp" {
		t.Fatalf("BGP source type = %q, want bmp", got)
	}

	binding := pipeline.NewRegistryBinding(db.Pool())
	if err := binding.Verify(context.Background(), tenant, agentID); err != nil {
		t.Fatalf("registered BGP source must be publish-bound in its tenant: %v", err)
	}

	if err := tenancy.InTenant(tenancy.WithTenant(context.Background(), tenancy.ID(tenant)), db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
		a, err := (store.Agents{}).Get(ctx, sc, agentID)
		if err != nil {
			return err
		}
		got := strings.Join(a.Capabilities, ",")
		if got != "collector,bgp" {
			t.Fatalf("capabilities = %q, want collector,bgp", got)
		}
		return nil
	}); err != nil {
		t.Fatalf("read registered BGP source: %v", err)
	}

	now := time.Now().UTC().Truncate(time.Second)
	event := &bgpv1.BGPEvent{
		TenantId:           tenant,
		EventType:          bgpv1.EventType_EVENT_TYPE_POSSIBLE_HIJACK,
		Severity:           bgpv1.Severity_SEVERITY_CRITICAL,
		Confidence:         0.97,
		Prefix:             "192.0.2.0/24",
		NewOriginAsn:       64500,
		RpkiStatus:         bgpv1.RpkiStatus_RPKI_STATUS_INVALID,
		Collector:          "rrc00",
		PeerAsn:            64496,
		Message:            "possible hijack 192.0.2.0/24",
		DetectedAtUnixNano: now.UnixNano(),
	}
	raw, err := proto.Marshal(event)
	if err != nil {
		t.Fatalf("marshal BGP event: %v", err)
	}
	msg := bus.Message{Topic: bus.BGPEventsTopic, Key: []byte(tenant), Value: raw}

	log := logging.New(io.Discard, "error", "json")
	topoStore := topology.NewMemoryStore()
	if err := NewTopologyConsumer(nil, topoStore, log).handleBGP(context.Background(), msg); err != nil {
		t.Fatalf("topology BGP consume: %v", err)
	}
	topoTenant, err := topoStore.ForTenant(tenant)
	if err != nil {
		t.Fatalf("topology tenant: %v", err)
	}
	snap := topoTenant.Latest()
	var routed bool
	for _, edge := range snap.Edges {
		if edge.Kind == topology.EdgeRouting && edge.To == "prefix:192.0.2.0/24" {
			routed = true
		}
	}
	if !routed {
		t.Fatalf("BGP event did not reach topology routing graph: %+v", snap.Edges)
	}

	corr := BuildCorrelator(db.Pool(), 5*time.Minute, log)
	if err := NewBGPIncidentConsumer(nil, corr, log).handleLane(context.Background(), msg, ""); err != nil {
		t.Fatalf("incident BGP consume: %v", err)
	}
	open := openIncidentsRLS(t, db.Pool(), tenant)
	if len(open) != 1 {
		t.Fatalf("BGP event should open one tenant incident, got %d", len(open))
	}
	full := getIncidentRLS(t, db.Pool(), tenant, open[0].ID)
	if len(full.Signals) != 1 || full.Signals[0].Plane != "bgp" || full.Signals[0].Prefix != "192.0.2.0/24" {
		t.Fatalf("BGP incident signals = %+v", full.Signals)
	}
}
