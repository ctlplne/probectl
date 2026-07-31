// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

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

	"github.com/imfeelingtheagi/probectl/internal/audit"
	"github.com/imfeelingtheagi/probectl/internal/bus"
	"github.com/imfeelingtheagi/probectl/internal/config"
	"github.com/imfeelingtheagi/probectl/internal/crypto"
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

func tenantEnrollmentFailureEvents(t *testing.T, db *store.DB, tenantID string) []audit.Event {
	t.Helper()
	var events []audit.Event
	err := tenancy.InTenant(tenancy.WithTenant(context.Background(), tenancy.ID(tenantID)), db.Pool(),
		func(ctx context.Context, sc tenancy.Scope) error {
			var err error
			events, err = audit.ListFiltered(ctx, sc, 0, 20, audit.Filter{Action: enrollmentRejectedAuditAction})
			return err
		})
	if err != nil {
		t.Fatalf("list tenant enrollment failure audit: %v", err)
	}
	return events
}

func TestEnrollmentFailureAuditIsolationAndRedaction(t *testing.T) {
	const (
		secretToken = "pjt_DO_NOT_PERSIST_ENROLLMENT_TOKEN"
		secretCSR   = "DO_NOT_PERSIST_ENROLLMENT_CSR"
	)
	db := changeDB(t)
	svc := collectorEnrollService(t, db)
	tenantA := freshTenant(t, db, "enroll-audit-a")
	tenantB := freshTenant(t, db, "enroll-audit-b")
	srv := New(&config.Config{AuthMode: "dev"}, logging.New(io.Discard, "error", "json"), db, db.Pool(), nil, nil)
	srv.SetEnrollService(svc)
	h := srv.Handler()

	providerHead, err := audit.ProviderHeadSeq(context.Background(), db.Pool())
	if err != nil {
		t.Fatalf("provider audit head: %v", err)
	}
	invalidAgent := apiReq(t, h, http.MethodPost, "/enroll/agent", tenantA, map[string]any{
		"token": secretToken, "csr_pem": secretCSR,
	})
	if invalidAgent.Code != http.StatusUnauthorized {
		t.Fatalf("invalid agent token = %d %s, want 401", invalidAgent.Code, invalidAgent.Body)
	}
	providerEvents, err := audit.ListProvider(context.Background(), db.Pool(), providerHead, 20)
	if err != nil {
		t.Fatalf("list deployment audit: %v", err)
	}
	var deploymentFailure *audit.Event
	for i := range providerEvents {
		if providerEvents[i].Action == enrollmentRejectedAuditAction &&
			providerEvents[i].Target == string(enrollmentSurfaceAgent) {
			deploymentFailure = &providerEvents[i]
		}
	}
	if deploymentFailure == nil {
		t.Fatalf("unresolved rejection missing from deployment audit: %+v", providerEvents)
	}
	if deploymentFailure.Data["failure_class"] != string(enrollmentFailureInvalidToken) {
		t.Fatalf("deployment failure class = %#v", deploymentFailure.Data)
	}
	if deploymentFailure.Data["outcome"] != "denied" {
		t.Fatalf("deployment failure outcome = %#v", deploymentFailure.Data)
	}
	if tenantAEvents := tenantEnrollmentFailureEvents(t, db, tenantA); len(tenantAEvents) != 0 {
		t.Fatalf("unresolved rejection trusted the request's tenant header: %+v", tenantAEvents)
	}

	badCSRToken, _, err := svc.MintToken(context.Background(), tenantA, "", "bad-csr-agent", "test", time.Hour)
	if err != nil {
		t.Fatalf("mint bad-CSR token: %v", err)
	}
	badCSR := apiReq(t, h, http.MethodPost, "/enroll/agent", tenantB, map[string]any{
		"token": badCSRToken, "csr_pem": secretCSR,
	})
	if badCSR.Code != http.StatusBadRequest {
		t.Fatalf("bad CSR enrollment = %d %s, want 400", badCSR.Code, badCSR.Body)
	}
	tenantAEvents := tenantEnrollmentFailureEvents(t, db, tenantA)
	if len(tenantAEvents) != 1 ||
		tenantAEvents[0].Target != string(enrollmentSurfaceAgent) ||
		tenantAEvents[0].Data["failure_class"] != string(enrollmentFailureInvalidCSR) ||
		tenantAEvents[0].Actor != "anonymous" {
		t.Fatalf("token-resolved tenant audit = %+v, want one typed CSR rejection", tenantAEvents)
	}

	tokenA, _, err := svc.MintToken(context.Background(), tenantA, "", "collector-a", "test", time.Hour)
	if err != nil {
		t.Fatalf("mint tenant A collector token: %v", err)
	}
	invalidCollector := apiReq(t, h, http.MethodPost, "/v1/collectors/register", tenantB, map[string]any{
		"token": tokenA, "plane": "flow", "hostname": "collector-b",
	})
	if invalidCollector.Code != http.StatusUnauthorized {
		t.Fatalf("cross-tenant collector token = %d %s, want 401", invalidCollector.Code, invalidCollector.Body)
	}

	tenantBEvents := tenantEnrollmentFailureEvents(t, db, tenantB)
	if len(tenantBEvents) != 1 ||
		tenantBEvents[0].Target != string(enrollmentSurfaceCollector) ||
		tenantBEvents[0].Data["failure_class"] != string(enrollmentFailureInvalidToken) ||
		tenantBEvents[0].Data["outcome"] != "denied" {
		t.Fatalf("caller-tenant audit = %+v, want one typed collector rejection", tenantBEvents)
	}
	if tenantAEvents = tenantEnrollmentFailureEvents(t, db, tenantA); len(tenantAEvents) != 1 {
		t.Fatalf("collector rejection leaked into token owner's tenant audit: %+v", tenantAEvents)
	}

	evidence, err := json.Marshal(append(append(providerEvents, tenantAEvents...), tenantBEvents...))
	if err != nil {
		t.Fatalf("marshal audit evidence: %v", err)
	}
	for _, secret := range []string{secretToken, secretCSR, badCSRToken, tokenA} {
		if strings.Contains(string(evidence), secret) {
			t.Fatalf("secret %q persisted in enrollment audit", secret)
		}
	}
	if got := srv.Metrics().Counter(enrollmentFailureMetricName(enrollmentFailureInvalidToken), "").Value(); got != 2 {
		t.Fatalf("invalid-token failure counter = %d, want 2", got)
	}
	if got := srv.Metrics().Counter(enrollmentFailureMetricName(enrollmentFailureInvalidCSR), "").Value(); got != 1 {
		t.Fatalf("invalid-CSR failure counter = %d, want 1", got)
	}
}

func TestDeviceCollectorProfileRegistrationIsTenantScopedAndPublishBound(t *testing.T) {
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

	invalid := apiReq(t, h, http.MethodPost, "/v1/collectors/register", tenantA, map[string]any{
		"token": token, "plane": "device", "hostname": "edge-flow-1", "collection_profile": "vendor-ultra",
	})
	if invalid.Code != http.StatusBadRequest {
		t.Fatalf("invalid profile registration = %d %s, want 400", invalid.Code, invalid.Body)
	}

	cross := apiReq(t, h, http.MethodPost, "/v1/collectors/register", tenantB, map[string]any{
		"token": token, "plane": "device", "hostname": "edge-flow-1", "collection_profile": "topology-rich",
	})
	if cross.Code != http.StatusUnauthorized {
		t.Fatalf("cross-tenant registration = %d %s, want 401", cross.Code, cross.Body)
	}

	ok := apiReq(t, h, http.MethodPost, "/v1/collectors/register", tenantA, map[string]any{
		"token": token, "plane": "device", "hostname": "edge-flow-1", "collection_profile": "topology-rich",
	})
	if ok.Code != http.StatusCreated {
		t.Fatalf("tenant registration = %d %s, want 201", ok.Code, ok.Body)
	}
	var out collectorRegistrationResponse
	if err := json.Unmarshal(ok.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if out.TenantID != tenantA || out.AgentID != agentID || out.Plane != "device" {
		t.Fatalf("registration response = %+v", out)
	}
	if got := out.Config.Env["PROBECTL_DEVICE_AGENT_ID"]; got != agentID {
		t.Fatalf("device env agent id = %q, want %q", got, agentID)
	}
	if got := out.Config.Env["PROBECTL_DEVICE_PROFILE"]; got != "topology-rich" {
		t.Fatalf("device profile env = %q, want topology-rich", got)
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
		if got != "collector,device" {
			t.Fatalf("capabilities = %q, want collector,device", got)
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

func TestBMPCollectorRegistrationIssuesRegistrySVIDTwoTenant(t *testing.T) {
	db := changeDB(t)
	svc := collectorEnrollService(t, db)
	tenantA := freshTenant(t, db, "bmp-router-a")
	tenantB := freshTenant(t, db, "bmp-router-b")
	routerID := uuid(t)

	srv := New(&config.Config{AuthMode: "dev"}, logging.New(io.Discard, "error", "json"), db, db.Pool(), nil, nil)
	srv.SetEnrollService(svc)
	h := srv.Handler()

	token, _, err := svc.MintToken(context.Background(), tenantA, routerID, "edge-router-a", "test", time.Hour)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	csr, _, err := crypto.CreateCSR("edge-router-a")
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}
	body := map[string]any{
		"token":    token,
		"plane":    "bmp",
		"hostname": "edge-router-a",
		"csr_pem":  string(csr),
	}
	cross := apiReq(t, h, http.MethodPost, "/v1/collectors/register", tenantB, body)
	if cross.Code != http.StatusUnauthorized {
		t.Fatalf("tenant B used tenant A BMP token = %d %s, want 401", cross.Code, cross.Body)
	}
	rec := apiReq(t, h, http.MethodPost, "/v1/collectors/register", tenantA, body)
	if rec.Code != http.StatusCreated {
		t.Fatalf("BMP registration = %d %s, want 201", rec.Code, rec.Body)
	}
	var out collectorRegistrationResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if out.SVID == nil {
		t.Fatal("BMP registration response omitted SVID")
	}
	wantSPIFFE := crypto.BMPSPIFFEID(tenantA, routerID)
	if out.TenantID != tenantA || out.AgentID != routerID || out.Plane != "bmp" ||
		out.SVID.SPIFFEID != wantSPIFFE || out.SVID.Plane != "bmp" {
		t.Fatalf("BMP registration response = %+v, want %q", out, wantSPIFFE)
	}
	if out.Config.YAML["identity_plane"] != "bmp" ||
		out.Config.YAML["router_id"] != routerID {
		t.Fatalf("BMP router config = %+v", out.Config)
	}

	knownA, err := store.NewAgentIdentities(db.Pool()).KnownIssuedIdentity(
		context.Background(),
		tenantA,
		routerID,
		out.SVID.SPIFFEID,
		out.SVID.Serial,
	)
	if err != nil || !knownA {
		t.Fatalf("tenant A registry lookup = %v, %v", knownA, err)
	}
	knownB, err := store.NewAgentIdentities(db.Pool()).KnownIssuedIdentity(
		context.Background(),
		tenantB,
		routerID,
		out.SVID.SPIFFEID,
		out.SVID.Serial,
	)
	if err != nil {
		t.Fatalf("tenant B registry lookup: %v", err)
	}
	if knownB {
		t.Fatal("tenant B saw tenant A's BMP SVID in its identity registry")
	}
}
