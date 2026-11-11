// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package bgp_test

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/enroll"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/incident"
	pathstore "github.com/ctlplne/probectl/internal/path"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/testsupport"
	"github.com/ctlplne/probectl/internal/testsupport/shipped"
)

// This is the four-plane one-router prerequisite for FX-2's final receipt.
// It requires real SNMP, IPFIX, path and BMP sources to resolve to one device
// in the shipped stack, then checks a second tenant and a real fault. The
// rendered Admin/Explorer/path/topology/incident assertions run in this
// receipt; the runtime gate remains before promotion.
func TestFX2FRREdgeFourPlaneRealStack(t *testing.T) {
	if runtime.GOOS != "linux" {
		testsupport.SkipOrFatal(t, "the shipped control plane needs a Linux host route to FRR edge's private Docker bridge")
	}
	lab := startRoutingLabNamed(t, "probectl-qa-beta-fx2-router-"+strconv.FormatInt(time.Now().UnixNano()%1e8, 36))
	community := startEdgeSNMP(t, lab)
	address := lab.ip["edge"]
	// net-snmp reads the kernel interface table in FRR edge's network
	// namespace. A sidecar on a separate Docker bridge would fail this exact
	// ipAdEntAddr row even if both processes answered on localhost.
	got := queryEdgeSNMP(t, lab.name+"-edge-snmp", community,
		".1.3.6.1.2.1.4.20.1.1."+address)
	if got != address {
		t.Fatalf("edge SNMP interface address = %q, want FRR peer %q", got, address)
	}
	neighbor := queryEdgeSNMP(t, lab.name+"-edge-snmp", community,
		".1.0.8802.1.1.2.1.4.1.1.9.0.2.1")
	if !strings.Contains(neighbor, "fx2-access-sw1") {
		t.Fatalf("edge LLDP neighbor = %q, want fx2-access-sw1", neighbor)
	}
	st := shipped.Start(t, shipped.Options{Name: "fx2router", TenantBand: 4})
	registration := registerEdgeFlowEvidence(t, st, address)
	deviceAgentID := startShippedEdgeSNMP(t, st, registration, "red", address, community)
	supportID := awaitEdgeSNMPEvidence(t, st, registration, deviceAgentID, address)
	discoverEdgePath(t, st, registration, address)
	listener := startShippedEdgeFlow(t, st, lab, registration)
	exporter := startEdgeIPFIXExporter(t, lab, listener)
	observed := time.Now()
	emitEdgeFlow(t, lab, exporter)
	awaitShippedEdgeFlow(t, st, registration, address, observed)
	awaitEdgeFlowEvidence(t, st, registration, address, deviceAgentID, supportID)
	startEdgeBMPEvidence(t, st, lab, registration, address, deviceAgentID, supportID)
	second := registerSecondRouterTenant(t, st, registration)
	secondAgentID := startShippedEdgeSNMP(t, st, second, "blue", address, community)
	awaitEdgeSNMPEvidence(t, st, second, secondAgentID, address)
	assertRouterTenantSplit(t, st, registration, second, address)
	renderEdgeExplorer(t, st, registration, second, address, observed)
	renderRouterRegistryTenants(t, st, registration, second)
	renderRouterTopologyTenants(t, st, registration, second, address)
	incidents := proveRouterPollFailureIncidents(t, st, lab, registration, second, address)
	renderRouterIncidentTenants(t, st, registration, second, incidents, address)
	t.Logf("FX-2 router physical source: FRR edge and net-snmp share %s; LLDP neighbor is fx2-access-sw1", address)
}

type edgeFlowRegistration struct {
	tenantID, agentID, cookie, contextID, deviceID, operatorToken string
	env                                                           map[string]string
	certFile, keyFile, caFile                                     string
}

// Evidence rotation atomically replaces a dedicated identity directory. The
// shipped collector rejects arbitrary certificate names or a CA elsewhere.
func writeRouterEvidenceFiles(t *testing.T, st *shipped.Stack, name, cert string, key []byte) (string, string, string) {
	t.Helper()
	dir := filepath.Join(st.Dir, name)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	ca, err := os.ReadFile(st.CAFile)
	if err != nil {
		t.Fatal(err)
	}
	certFile, keyFile, caFile := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem"), filepath.Join(dir, "server-ca.pem")
	for _, file := range []struct {
		path string
		data []byte
	}{{certFile, []byte(cert)}, {keyFile, key}, {caFile, ca}} {
		if err := os.WriteFile(file.path, file.data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return certFile, keyFile, caFile
}

// registerEdgeFlowEvidence uses the shipped public surfaces for BOTH the raw
// flow collector and its additional restricted evidence SVID. It assigns the
// exact exporter to a site/VRF without a premature canonical device anchor.
func registerEdgeFlowEvidence(t *testing.T, st *shipped.Stack, exporterIP string, existing ...edgeFlowRegistration) edgeFlowRegistration {
	t.Helper()
	var tenant struct{ ID string }
	var op, cookie string
	var target edgeFlowRegistration
	switch len(existing) {
	case 0:
		op = st.OnboardOperator(t, "root@msp-fx2-router.example")
		st.MustCLI(t, map[string]string{"PROBECTL_API_TOKEN": op}, &tenant,
			"provider", "create-tenant", "--body",
			fmt.Sprintf(`{"slug":%q,"name":"FX-2 Router","isolation_model":"pooled"}`,
				"fx2-router-"+fmt.Sprint(time.Now().UnixNano())))
		if tenant.ID == "" {
			t.Fatal("shipped FX-2 router tenant has no ID")
		}
		cookie = st.SignIn(t, tenant.ID, "ada@acme.example", "FX-2 Router")
	case 1:
		target = existing[0]
		if target.tenantID == "" || target.cookie == "" || target.contextID == "" || target.deviceID == "" || target.agentID != "" {
			t.Fatal("existing router tenant requires its own context/device and a fresh flow registration")
		}
		tenant.ID, cookie, op = target.tenantID, target.cookie, target.operatorToken
	default:
		t.Fatal("one existing router tenant is required")
	}
	mint := func(agentID string) string {
		t.Helper()
		body := map[string]any{"name": "fx2-edge-flow", "ttl_seconds": 600}
		if agentID != "" {
			body["agent_id"] = agentID
		}
		code, raw := st.Do(t, cookie, http.MethodPost, "/v1/agents/enroll-tokens", body)
		if code != http.StatusCreated {
			t.Fatalf("mint FX-2 flow token: HTTP %d", code)
		}
		var token struct{ Token string }
		if err := json.Unmarshal(raw, &token); err != nil || token.Token == "" {
			t.Fatalf("decode FX-2 flow token: %v", err)
		}
		return token.Token
	}
	type registration struct {
		TenantID string `json:"tenant_id"`
		AgentID  string `json:"agent_id"`
		Plane    string `json:"plane"`
		Config   struct {
			Env map[string]string `json:"env"`
		} `json:"config"`
		SVID *enroll.Identity `json:"svid"`
	}
	register := func(token, plane, csr string) registration {
		t.Helper()
		code, raw := st.Do(t, cookie, http.MethodPost, "/v1/collectors/register",
			map[string]string{"token": token, "plane": plane,
				"hostname": "fx2-edge-flow", "csr_pem": csr})
		if code != http.StatusCreated {
			t.Fatalf("register FX-2 %s collector: HTTP %d", plane, code)
		}
		var out registration
		if err := json.Unmarshal(raw, &out); err != nil {
			t.Fatalf("decode FX-2 %s registration: %v", plane, err)
		}
		return out
	}
	raw := register(mint(""), "flow", "")
	if raw.TenantID != tenant.ID || raw.AgentID == "" || raw.Plane != "flow" || raw.SVID != nil ||
		raw.Config.Env == nil {
		t.Fatal("shipped raw flow registration did not bind one tenant/agent without an evidence SVID")
	}
	csr, key, err := crypto.CreateCSR("fx2-edge-flow-evidence")
	if err != nil {
		t.Fatal(err)
	}
	evidence := register(mint(raw.AgentID), "entity", string(csr))
	if evidence.TenantID != tenant.ID || evidence.AgentID != raw.AgentID ||
		evidence.Plane != "entity" || evidence.SVID == nil ||
		evidence.SVID.SPIFFEID != crypto.EntitySPIFFEID(tenant.ID, raw.AgentID) {
		t.Fatal("pinned evidence registration did not preserve the raw flow tenant/agent")
	}
	certFile, keyFile, caFile := writeRouterEvidenceFiles(t, st, "fx2-edge-flow-evidence-"+raw.AgentID, evidence.SVID.CertPEM, key)
	var routing struct {
		ContextID string `json:"context_id"`
	}
	var device struct {
		ID string `json:"id"`
	}
	routing.ContextID, device.ID = target.contextID, target.deviceID
	if len(existing) == 0 {
		code, payload := st.Do(t, cookie, http.MethodPost, "/v1/entity-contexts",
			map[string]string{"site_label": "FX-2 West DC", "vrf_label": "Customer A"})
		if code != http.StatusCreated {
			t.Fatalf("create FX-2 routing context: HTTP %d: %.300s", code, payload)
		}
		if err := json.Unmarshal(payload, &routing); err != nil || routing.ContextID == "" {
			t.Fatalf("decode FX-2 routing context: %v", err)
		}
		code, payload = st.Do(t, cookie, http.MethodPost, "/v1/entities",
			map[string]string{"context_id": routing.ContextID, "kind": "device", "label": "fx2-edge-r1"})
		if code != http.StatusCreated {
			t.Fatalf("create FX-2 canonical edge device: HTTP %d: %.300s", code, payload)
		}
		if err := json.Unmarshal(payload, &device); err != nil || device.ID == "" {
			t.Fatalf("decode FX-2 edge device: %v", err)
		}
	}
	code, payload := st.Do(t, cookie, http.MethodPut, "/v1/entity-source-contexts",
		map[string]string{"agent_id": raw.AgentID, "source_kind": "flow_exporter",
			"source_ref": exporterIP, "context_id": routing.ContextID})
	if code != http.StatusOK {
		t.Fatalf("assign FX-2 flow exporter context: HTTP %d: %.300s", code, payload)
	}
	return edgeFlowRegistration{tenantID: tenant.ID, agentID: raw.AgentID,
		cookie: cookie, contextID: routing.ContextID, deviceID: device.ID,
		operatorToken: op,
		env:           raw.Config.Env, certFile: certFile, keyFile: keyFile, caFile: caFile}
}

// The second tenant polls the same real private address with its own issued
// agent. The two contexts and device IDs come from ordinary operator APIs.
func registerSecondRouterTenant(t *testing.T, st *shipped.Stack,
	first edgeFlowRegistration) edgeFlowRegistration {
	t.Helper()
	var tenant struct{ ID string }
	st.MustCLI(t, map[string]string{"PROBECTL_API_TOKEN": first.operatorToken}, &tenant,
		"provider", "create-tenant", "--body",
		fmt.Sprintf(`{"slug":%q,"name":"FX-2 Router Blue","isolation_model":"pooled"}`,
			"fx2-router-blue-"+fmt.Sprint(time.Now().UnixNano())))
	if tenant.ID == "" || tenant.ID == first.tenantID {
		t.Fatal("second FX-2 tenant did not receive a distinct ID")
	}
	cookie := st.SignIn(t, tenant.ID, "bob@globex.example", "FX-2 Router Blue")
	code, payload := st.Do(t, cookie, http.MethodPost, "/v1/entity-contexts",
		map[string]string{"site_label": "FX-2 West DC", "vrf_label": "Customer A"})
	if code != http.StatusCreated {
		t.Fatalf("create second FX-2 routing context: HTTP %d: %.300s", code, payload)
	}
	var routing struct {
		ContextID string `json:"context_id"`
	}
	if err := json.Unmarshal(payload, &routing); err != nil ||
		routing.ContextID == "" || routing.ContextID == first.contextID {
		t.Fatalf("decode second FX-2 routing context: %v", err)
	}
	code, payload = st.Do(t, cookie, http.MethodPost, "/v1/entities",
		map[string]string{"context_id": routing.ContextID, "kind": "device", "label": "fx2-edge-r1"})
	if code != http.StatusCreated {
		t.Fatalf("create second FX-2 canonical device: HTTP %d: %.300s", code, payload)
	}
	var device struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(payload, &device); err != nil ||
		device.ID == "" || device.ID == first.deviceID {
		t.Fatalf("decode second FX-2 canonical device: %v", err)
	}
	return edgeFlowRegistration{tenantID: tenant.ID, cookie: cookie,
		contextID: routing.ContextID, deviceID: device.ID}
}

func assertRouterTenantSplit(t *testing.T, st *shipped.Stack,
	first, second edgeFlowRegistration, address string) {
	t.Helper()
	for _, pair := range [][2]edgeFlowRegistration{{first, second}, {second, first}} {
		own, other := pair[0], pair[1]
		code, payload := st.Do(t, own.cookie, http.MethodGet,
			"/v1/entities/resolve?context_id="+own.contextID+
				"&kind=address&value="+address, nil)
		var result entity.Resolution
		if code != http.StatusOK || json.Unmarshal(payload, &result) != nil ||
			result.Scope.TenantID != own.tenantID || result.Scope.ContextID != own.contextID ||
			result.Status != entity.Resolved || result.EntityID != own.deviceID ||
			result.EntityID == other.deviceID {
			t.Fatalf("FX-2 reused private address escaped tenant boundary: HTTP %d %+v", code, result)
		}
		code, payload = st.Do(t, own.cookie, http.MethodGet,
			"/v1/entities/"+other.deviceID+"?context_id="+own.contextID, nil)
		if code != http.StatusNotFound {
			t.Fatalf("FX-2 foreign device ID under own tenant returned HTTP %d: %.300s", code, payload)
		}
	}
	t.Logf("FX-2 tenant split: the same private address %s resolves to distinct tenant-owned devices", address)
}

// Render the shipped Admin registry as each tenant. The tenant IDs and
// overlapping private address are the same facts checked by the API above;
// neither browser may display the other tenant's stable device ID.
func renderRouterRegistryTenants(t *testing.T, st *shipped.Stack,
	first, second edgeFlowRegistration) {
	t.Helper()
	for _, pair := range [][2]edgeFlowRegistration{{first, second}, {second, first}} {
		own, other := pair[0], pair[1]
		testsupport.RenderUI(t, testsupport.RenderSpec{
			URL:            st.BaseURL + "/ui/admin",
			Cookies:        []testsupport.RenderCookie{{Name: auth.SessionCookie, Value: own.cookie}},
			TrustCertFiles: st.TrustCerts(), CAFile: st.CAFile,
			Expect: []string{"Canonical entity registry", "FX-2 West DC / Customer A", own.deviceID},
			Absent: []string{other.deviceID},
		})
	}
}

// Raw SNMP creates the topology nodes. Canonical IDs appear only after an
// explicit context is selected and a current tenant-scoped address join runs.
func renderRouterTopologyTenants(t *testing.T, st *shipped.Stack,
	first, second edgeFlowRegistration, address string) {
	t.Helper()
	for _, pair := range [][2]edgeFlowRegistration{{first, second}, {second, first}} {
		own, other := pair[0], pair[1]
		label := ""
		shipped.Await(t, "FX-2 topology current device for "+own.tenantID, 60*time.Second,
			func() bool {
				code, payload := st.Do(t, own.cookie, http.MethodGet,
					"/v1/topology?context_id="+own.contextID, nil)
				if code != http.StatusOK {
					return false
				}
				var graph struct {
					CanonicalContextID string `json:"canonical_context_id"`
					Nodes              []struct {
						ID                string `json:"id"`
						Label             string `json:"label"`
						CanonicalEntityID string `json:"canonical_entity_id"`
						CanonicalStatus   string `json:"canonical_status"`
					} `json:"nodes"`
				}
				if json.Unmarshal(payload, &graph) != nil || graph.CanonicalContextID != own.contextID {
					return false
				}
				for _, node := range graph.Nodes {
					if node.ID == "device:"+address && node.Label != "" &&
						node.CanonicalEntityID == own.deviceID && node.CanonicalStatus == "resolved" {
						label = node.Label
						return true
					}
				}
				return false
			})
		testsupport.RenderUI(t, testsupport.RenderSpec{
			URL:            st.BaseURL + "/ui/topology?entity_context=" + own.contextID,
			Cookies:        []testsupport.RenderCookie{{Name: auth.SessionCookie, Value: own.cookie}},
			TrustCertFiles: st.TrustCerts(), CAFile: st.CAFile,
			Expect: []string{"Topology list", label}, Absent: []string{other.deviceID},
			Steps: []testsupport.RenderStep{{Click: label, Expect: []string{own.deviceID}}},
		})
	}
}

// A real SNMP outage must enter the restricted sender-bound fault path and
// open exactly one tenant-owned incident for each separately enrolled agent.
// This runs after the healthy four-plane proof so the outage cannot fabricate
// a missing identity claim.
func proveRouterPollFailureIncidents(t *testing.T, st *shipped.Stack, lab *routingLab,
	first, second edgeFlowRegistration, address string) map[string]string {
	t.Helper()
	lab.docker(t, "stop", lab.name+"-edge-snmp")
	incidentIDs := make(map[string]string, 2)
	for _, tenant := range []edgeFlowRegistration{first, second} {
		shipped.Await(t, "FX-2 sender-bound SNMP failure incident for "+tenant.tenantID,
			90*time.Second, func() bool {
				code, payload := st.Do(t, tenant.cookie, http.MethodGet, "/v1/incidents", nil)
				if code != http.StatusOK {
					return false
				}
				var page struct {
					Items []incident.Incident `json:"items"`
				}
				if json.Unmarshal(payload, &page) != nil {
					return false
				}
				matching := ""
				for _, candidate := range page.Items {
					if candidate.ID == "" || candidate.TenantID != tenant.tenantID {
						continue
					}
					code, payload = st.Do(t, tenant.cookie, http.MethodGet,
						"/v1/incidents/"+candidate.ID, nil)
					var detail incident.Incident
					if code != http.StatusOK || json.Unmarshal(payload, &detail) != nil {
						return false
					}
					faultSignals := 0
					for _, signal := range detail.Signals {
						if signal.Kind != "device.poll_failed" {
							continue
						}
						if signal.TenantID != tenant.tenantID || signal.Plane != "device" ||
							signal.Target != address || signal.Attributes[entity.AttrFaultObservationID] == "" {
							return false
						}
						faultSignals++
					}
					if faultSignals == 0 {
						continue
					}
					if faultSignals != 1 || matching != "" {
						return false
					}
					matching = candidate.ID
				}
				if matching == "" {
					return false
				}
				incidentIDs[tenant.tenantID] = matching
				return true
			})
	}
	for _, pair := range [][2]edgeFlowRegistration{{first, second}, {second, first}} {
		own, other := pair[0], pair[1]
		code, payload := st.Do(t, own.cookie, http.MethodGet,
			"/v1/incidents/"+incidentIDs[other.tenantID], nil)
		if code != http.StatusNotFound {
			t.Fatalf("FX-2 foreign incident ID returned HTTP %d: %.300s", code, payload)
		}
	}
	t.Logf("FX-2 live fault: SNMP outage opened one incident per tenant without a cross-tenant read")
	return incidentIDs
}

// The live fault's cited signal must let each browser resolve the current
// private address only inside its own operator-owned routing context.
func renderRouterIncidentTenants(t *testing.T, st *shipped.Stack,
	first, second edgeFlowRegistration, incidentIDs map[string]string, address string) {
	t.Helper()
	for _, pair := range [][2]edgeFlowRegistration{{first, second}, {second, first}} {
		own, other := pair[0], pair[1]
		testsupport.RenderUI(t, testsupport.RenderSpec{
			URL:            st.BaseURL + "/ui/incidents?incident=" + incidentIDs[own.tenantID],
			Cookies:        []testsupport.RenderCookie{{Name: auth.SessionCookie, Value: own.cookie}},
			TrustCertFiles: st.TrustCerts(), CAFile: st.CAFile,
			Expect: []string{"SNMP device poll failed"},
			Absent: []string{other.deviceID},
			Steps: []testsupport.RenderStep{
				{Click: "SNMP device poll failed", Within: `section[aria-label="Device telemetry"]`,
					Expect: []string{"Current identity pivot"}},
				{Select: `[data-entity-current-pivot] select >> nth=0`, Value: address},
				{Select: `[data-entity-current-pivot] select >> nth=1`, Value: own.contextID},
				{Click: "Resolve current identity", Within: `[data-entity-current-pivot]`,
					Expect: []string{own.deviceID}},
			},
		})
	}
}

// The device collector uses its own raw agent ID and pinned evidence SVID.
// Its exact target is operator-anchored to the device; the flow source is
// independently assigned to the same context without a supplied anchor.
func startShippedEdgeSNMP(t *testing.T, st *shipped.Stack, reg edgeFlowRegistration,
	name, address, community string) string {
	t.Helper()
	mint := func(agentID string) string {
		t.Helper()
		body := map[string]any{"name": "fx2-" + name + "-device", "ttl_seconds": 600}
		if agentID != "" {
			body["agent_id"] = agentID
		}
		code, payload := st.Do(t, reg.cookie, http.MethodPost, "/v1/agents/enroll-tokens", body)
		if code != http.StatusCreated {
			t.Fatalf("mint FX-2 device token: HTTP %d", code)
		}
		var result struct{ Token string }
		if err := json.Unmarshal(payload, &result); err != nil || result.Token == "" {
			t.Fatalf("decode FX-2 device token: %v", err)
		}
		return result.Token
	}
	type deviceRegistration struct {
		TenantID string `json:"tenant_id"`
		AgentID  string `json:"agent_id"`
		Plane    string `json:"plane"`
		Config   struct {
			Env map[string]string `json:"env"`
		} `json:"config"`
		SVID *enroll.Identity `json:"svid"`
	}
	register := func(token, plane, csr string) deviceRegistration {
		t.Helper()
		body := map[string]string{"token": token, "plane": plane,
			"hostname": "fx2-" + name + "-device", "csr_pem": csr}
		if plane == "device" {
			body["collection_profile"] = "topology-rich"
		}
		code, payload := st.Do(t, reg.cookie, http.MethodPost, "/v1/collectors/register", body)
		if code != http.StatusCreated {
			t.Fatalf("register FX-2 %s device: HTTP %d: %.300s", plane, code, payload)
		}
		var result deviceRegistration
		if err := json.Unmarshal(payload, &result); err != nil {
			t.Fatalf("decode FX-2 %s device registration: %v", plane, err)
		}
		return result
	}
	raw := register(mint(""), "device", "")
	if raw.TenantID != reg.tenantID || raw.AgentID == "" || raw.Plane != "device" ||
		raw.SVID != nil || raw.Config.Env == nil ||
		raw.Config.Env["PROBECTL_DEVICE_TENANT"] != reg.tenantID ||
		raw.Config.Env["PROBECTL_DEVICE_AGENT_ID"] != raw.AgentID {
		t.Fatal("shipped raw device registration lost tenant/agent binding")
	}
	csr, key, err := crypto.CreateCSR("fx2-" + name + "-device-evidence")
	if err != nil {
		t.Fatal(err)
	}
	evidence := register(mint(raw.AgentID), "entity", string(csr))
	if evidence.TenantID != reg.tenantID || evidence.AgentID != raw.AgentID ||
		evidence.Plane != "entity" || evidence.SVID == nil ||
		evidence.SVID.SPIFFEID != crypto.EntitySPIFFEID(reg.tenantID, raw.AgentID) {
		t.Fatal("pinned device evidence registration did not preserve tenant/agent")
	}
	code, payload := st.Do(t, reg.cookie, http.MethodPut, "/v1/entity-source-contexts",
		map[string]string{"agent_id": raw.AgentID, "source_kind": "device_target",
			"source_ref": address, "context_id": reg.contextID, "anchor_entity_id": reg.deviceID})
	if code != http.StatusOK {
		t.Fatalf("anchor FX-2 SNMP target: HTTP %d: %.300s", code, payload)
	}
	certFile, keyFile, caFile := writeRouterEvidenceFiles(t, st, "fx2-"+name+"-device-evidence", evidence.SVID.CertPEM, key)
	env := raw.Config.Env
	env["PROBECTL_DEVICE_BUS_MODE"] = "kafka"
	env["PROBECTL_DEVICE_BUS_BROKERS"] = strings.Join(testsupport.KafkaBrokers(), ",")
	env["PROBECTL_DEVICE_BUS_ALLOW_PLAINTEXT"] = "true" // CI-only development broker
	env["PROBECTL_DEVICE_METRICS_ADDR"] = shipped.FreeAddr(t)
	env["PROBECTL_DEVICE_TARGET"] = address
	env["PROBECTL_DEVICE_TRANSPORT"] = "snmpv2c"
	env["PROBECTL_DEVICE_PORT"] = "161"
	env["PROBECTL_DEVICE_CREDENTIAL"] = "fx2"
	env["PROBECTL_DEVICE_INTERVAL"] = "15s"
	env["PROBECTL_DEVICE_NEIGHBORS"] = "true"
	env["PROBECTL_DEVICE_CRED_FX2_COMMUNITY"] = "env:PROBECTL_TEST_FX2_SNMP_COMMUNITY"
	env["PROBECTL_TEST_FX2_SNMP_COMMUNITY"] = community
	env["PROBECTL_DEVICE_EVIDENCE_CONTROL_ADDR"] = st.AgentAddr
	env["PROBECTL_DEVICE_EVIDENCE_ROTATE_URL"] = st.BaseURL + "/enroll/agent/rotate"
	env["PROBECTL_DEVICE_EVIDENCE_CERT_FILE"] = certFile
	env["PROBECTL_DEVICE_EVIDENCE_KEY_FILE"] = keyFile
	env["PROBECTL_DEVICE_EVIDENCE_CA_FILE"] = caFile
	env["PROBECTL_DEVICE_EVIDENCE_SERVER_NAME"] = "localhost"
	keys := make([]string, 0, len(env))
	for key := range env {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	values := make([]string, 0, len(keys))
	for _, key := range keys {
		values = append(values, key+"="+env[key])
	}
	log := st.StartProcess(t, "fx2-"+name+"-device-agent", st.Binary(t, "probectl-device-agent"), nil, values)
	shipped.Await(t, "shipped FX-2 device collector", 60*time.Second, func() bool {
		contents, err := os.ReadFile(log)
		return err == nil && strings.Contains(string(contents), "device collector running")
	})
	return raw.AgentID
}

// The interface-IP observation must be current under the exact device SVID.
// A configured-target alias alone cannot establish independent SNMP support.
func awaitEdgeSNMPEvidence(t *testing.T, st *shipped.Stack, reg edgeFlowRegistration,
	deviceAgentID, address string) string {
	t.Helper()
	var supportID string
	shipped.Await(t, "current FX-2 SNMP interface address", 45*time.Second, func() bool {
		code, payload := st.Do(t, reg.cookie, http.MethodGet,
			"/v1/entities?context_id="+reg.contextID+"&limit=100", nil)
		if code != http.StatusOK {
			return false
		}
		var nodes entity.Page
		if json.Unmarshal(payload, &nodes) != nil || nodes.Scope.TenantID != reg.tenantID ||
			nodes.Scope.ContextID != reg.contextID {
			return false
		}
		for _, node := range nodes.Items {
			if node.Kind != entity.Interface {
				continue
			}
			code, payload := st.Do(t, reg.cookie, http.MethodGet,
				"/v1/entities/"+node.ID+"/evidence?context_id="+reg.contextID+"&limit=100", nil)
			if code != http.StatusOK {
				continue
			}
			var evidence entity.EvidencePage
			if json.Unmarshal(payload, &evidence) != nil {
				continue
			}
			for _, item := range evidence.Items {
				if item.Current && item.Alias.Kind == entity.AddressAlias &&
					item.Alias.Value == address && strings.HasPrefix(item.SourceRef, "snmp:ifIndex:") &&
					item.SourceKey.AgentID == deviceAgentID && item.SourceKey.Kind == entity.DeviceTarget &&
					item.SourceKey.SourceRef == address {
					code, payload := st.Do(t, reg.cookie, http.MethodGet,
						"/v1/entities/resolve?context_id="+reg.contextID+
							"&kind=address&value="+address, nil)
					var resolved entity.Resolution
					matched := code == http.StatusOK && json.Unmarshal(payload, &resolved) == nil &&
						resolved.Scope.TenantID == reg.tenantID &&
						resolved.Scope.ContextID == reg.contextID &&
						resolved.Status == entity.Resolved && resolved.EntityID == reg.deviceID
					if matched {
						supportID = item.ID
					}
					return matched
				}
			}
		}
		return false
	})
	t.Logf("FX-2 SNMP source: shipped device collector persisted a current interface IP for %s", address)
	return supportID
}

// Inferred flow identity must cite the exact independent SNMP row observed
// before this live export; a raw bus event or self-supporting alias is not a
// canonical join.
func awaitEdgeFlowEvidence(t *testing.T, st *shipped.Stack, reg edgeFlowRegistration,
	address, deviceAgentID, initialSupportID string) {
	t.Helper()
	last := "no flow evidence returned"
	matched := false
	defer func() {
		if !matched {
			t.Logf("FX-2 flow join diagnostic: %s; initial SNMP support %s", last, initialSupportID)
		}
	}()
	shipped.Await(t, "sender-bound FX-2 flow evidence with SNMP support", 45*time.Second, func() bool {
		code, payload := st.Do(t, reg.cookie, http.MethodGet,
			"/v1/entities/"+reg.deviceID+"/evidence?context_id="+reg.contextID+"&limit=100", nil)
		if code != http.StatusOK {
			return false
		}
		var page entity.EvidencePage
		if json.Unmarshal(payload, &page) != nil || page.Scope.TenantID != reg.tenantID ||
			page.Scope.ContextID != reg.contextID || page.EntityID != reg.deviceID {
			return false
		}
		for _, item := range page.Items {
			if item.SourceKey.Kind == entity.FlowExporter {
				last = fmt.Sprintf("current=%t alias=%s:%s agent=%s configured=%s support=%s",
					item.Current, item.Alias.Kind, item.Alias.Value, item.SourceKey.AgentID,
					item.SourceKey.SourceRef, item.SupportEvidenceID)
			}
			if item.Current && item.Alias.Kind == entity.AddressAlias &&
				item.Alias.Value == address && item.SourceKey.AgentID == reg.agentID &&
				item.SourceKey.Kind == entity.FlowExporter &&
				item.SourceKey.SourceRef == address &&
				strings.HasPrefix(item.SourceRef, "flow:ipfix:domain:") &&
				item.SupportEvidenceID != "" &&
				currentEdgeSNMPSupport(t, st, reg, address, deviceAgentID,
					item.SupportEvidenceID, item.ObservedAt) {
				matched = true
				return true
			}
		}
		return false
	})
	t.Logf("FX-2 SNMP+flow join: current flow evidence for %s cites an independently authenticated SNMP row on device %s",
		address, reg.deviceID)
}

func currentEdgeSNMPSupport(t *testing.T, st *shipped.Stack, reg edgeFlowRegistration,
	address, deviceAgentID, supportID string, observedAt time.Time) bool {
	t.Helper()
	code, payload := st.Do(t, reg.cookie, http.MethodGet,
		"/v1/entities?context_id="+reg.contextID+"&limit=100", nil)
	var nodes entity.Page
	if code != http.StatusOK || json.Unmarshal(payload, &nodes) != nil {
		return false
	}
	for _, node := range nodes.Items {
		if node.Kind != entity.Interface && (node.Kind != entity.Device || node.ID != reg.deviceID) {
			continue
		}
		code, payload := st.Do(t, reg.cookie, http.MethodGet,
			"/v1/entities/"+node.ID+"/evidence?context_id="+reg.contextID+"&limit=100", nil)
		var page entity.EvidencePage
		if code != http.StatusOK || json.Unmarshal(payload, &page) != nil {
			continue
		}
		for _, item := range page.Items {
			if item.ID == supportID && item.Current &&
				item.Alias.Kind == entity.AddressAlias && item.Alias.Value == address &&
				item.SourceKey.AgentID == deviceAgentID &&
				item.SourceKey.Kind == entity.DeviceTarget && item.SourceKey.SourceRef == address &&
				!item.ObservedAt.After(observedAt) {
				return true
			}
		}
	}
	return false
}

// A saved native flow query uses the same raw exporter row already proven in
// ClickHouse, then the FX-2 pivot resolves that row under an explicit context.
func renderEdgeExplorer(t *testing.T, st *shipped.Stack,
	reg, other edgeFlowRegistration, address string, observed time.Time) {
	t.Helper()
	plan := flow.QueryPlan{From: observed.Add(-time.Minute), To: observed.Add(5 * time.Minute),
		GroupBy: []string{"exporter"}, View: "table", RowLimit: 20, PageSize: 20,
		Metrics: []flow.QueryMetric{{Measure: "flows", Calculation: "total", Role: "primary"}}}
	code, payload := st.Do(t, reg.cookie, http.MethodPost, "/v1/explorer/flow-views",
		map[string]any{"definition": flow.QueryViewDefinition{
			Name: "FX-2 edge exporter", Visibility: "private",
			Time: flow.QueryViewTime{Mode: "absolute"}, Plan: plan,
		}})
	if code != http.StatusCreated {
		t.Fatalf("save FX-2 native flow view: HTTP %d: %.300s", code, payload)
	}
	var saved flow.SavedQueryView
	if err := json.Unmarshal(payload, &saved); err != nil || saved.ID == "" {
		t.Fatalf("decode FX-2 native flow view: %v", err)
	}
	testsupport.RenderUI(t, testsupport.RenderSpec{
		URL:            st.BaseURL + "/ui/explore?flow_view=" + saved.ID,
		Cookies:        []testsupport.RenderCookie{{Name: auth.SessionCookie, Value: reg.cookie}},
		TrustCertFiles: st.TrustCerts(), CAFile: st.CAFile,
		Expect: []string{"Flow explorer", "Native flow query"},
		Absent: []string{other.deviceID},
		Steps: []testsupport.RenderStep{
			{Click: "Run flow query", Expect: []string{"Frozen flow results", address, "Current identity pivot"}},
			{Select: `[data-entity-current-pivot] select >> nth=0`, Value: address},
			{Select: `[data-entity-current-pivot] select >> nth=1`, Value: reg.contextID},
			{Click: "Resolve current identity", Within: `[data-entity-current-pivot]`,
				Expect: []string{reg.deviceID}},
		},
	})
}

// The control-plane vantage must reach the router's actual bridge address.
// Only an operator binding selects the routing context for the path join.
func discoverEdgePath(t *testing.T, st *shipped.Stack, reg edgeFlowRegistration, address string) {
	t.Helper()
	code, payload := st.Do(t, reg.cookie, http.MethodPost, "/v1/tests", map[string]any{
		"name": "FX-2 edge router path", "type": "icmp", "target": address,
		"interval_seconds": 60, "timeout_seconds": 3, "enabled": true,
		"params": map[string]string{"allow_private_targets": "true"},
	})
	if code != http.StatusCreated {
		t.Fatalf("create FX-2 edge path test: HTTP %d: %.300s", code, payload)
	}
	var test struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(payload, &test); err != nil || test.ID == "" {
		t.Fatalf("decode FX-2 path test: %v", err)
	}
	code, payload = st.Do(t, reg.cookie, http.MethodPut,
		"/v1/tests/"+test.ID+"/entity-context", map[string]string{"context_id": reg.contextID})
	if code != http.StatusOK {
		t.Fatalf("bind FX-2 path to operator context: HTTP %d: %.300s", code, payload)
	}
	// ClickHouse rounds discovery time to milliseconds. Leave a distinct
	// timestamp after the binding so the current-path read can prove order.
	time.Sleep(5 * time.Millisecond)
	code, payload = st.Do(t, reg.cookie, http.MethodPost, "/v1/tests/"+test.ID+"/path", nil)
	if code != http.StatusOK {
		t.Fatalf("discover FX-2 edge path: HTTP %d: %.300s", code, payload)
	}
	var trace pathstore.Path
	if err := json.Unmarshal(payload, &trace); err != nil || trace.TargetIP != address ||
		trace.Vantage != pathstore.VantageControlPlane || !trace.DestinationReached {
		t.Fatalf("FX-2 trace did not reach actual edge %s: %+v, %v", address, trace, err)
	}
	var observed bool
	for _, hop := range trace.Hops {
		for _, node := range hop.Nodes {
			observed = observed || node.IP == address
		}
	}
	if !observed {
		t.Fatalf("FX-2 path did not observe edge's actual bridge IP %s", address)
	}
	shipped.Await(t, "FX-2 path's current canonical device", 30*time.Second, func() bool {
		code, payload := st.Do(t, reg.cookie, http.MethodGet,
			"/v1/tests/"+test.ID+"/path/entities", nil)
		if code != http.StatusOK {
			return false
		}
		var joined struct {
			ContextID string `json:"context_id"`
			Status    string `json:"status"`
			Items     []struct {
				IP         string            `json:"ip"`
				Resolution entity.Resolution `json:"resolution"`
			} `json:"items"`
		}
		if json.Unmarshal(payload, &joined) != nil || joined.ContextID != reg.contextID ||
			joined.Status != "current" {
			return false
		}
		for _, item := range joined.Items {
			if item.IP == address && item.Resolution.Scope.TenantID == reg.tenantID &&
				item.Resolution.Scope.ContextID == reg.contextID &&
				item.Resolution.Status == entity.Resolved && item.Resolution.EntityID == reg.deviceID {
				return true
			}
		}
		return false
	})
	testsupport.RenderUI(t, testsupport.RenderSpec{
		URL:            st.BaseURL + "/ui/path",
		Cookies:        []testsupport.RenderCookie{{Name: auth.SessionCookie, Value: reg.cookie}},
		TrustCertFiles: st.TrustCerts(), CAFile: st.CAFile,
		Expect: []string{"Path & Topology", "FX-2 edge router path",
			"Latest path responders and current canonical identity", address, reg.deviceID},
	})
	t.Logf("FX-2 path source: control-plane trace reached %s and resolved device %s", address, reg.deviceID)
}

// rtr-a is an authenticated FRR router and edge is the peer in its actual
// BMP route frame. The listener's separate entity SVID may report only its
// own registered router source; current SNMP support selects the device.
func startEdgeBMPEvidence(t *testing.T, st *shipped.Stack, lab *routingLab,
	reg edgeFlowRegistration, edgeIP, deviceAgentID, initialSupportID string) {
	t.Helper()
	tn := startRouterBMPEvidenceListener(t, st, lab, reg, "")
	last := "no BMP evidence returned"
	matched := false
	defer func() {
		if !matched {
			t.Logf("FX-2 BMP join diagnostic: %s; initial SNMP support %s", last, initialSupportID)
		}
	}()
	shipped.Await(t, "FX-2 authenticated BMP peer with SNMP support", 45*time.Second, func() bool {
		code, payload := st.Do(t, reg.cookie, http.MethodGet,
			"/v1/entities/"+reg.deviceID+"/evidence?context_id="+reg.contextID+"&limit=100", nil)
		if code != http.StatusOK {
			return false
		}
		var page entity.EvidencePage
		if json.Unmarshal(payload, &page) != nil || page.Scope.TenantID != reg.tenantID ||
			page.Scope.ContextID != reg.contextID || page.EntityID != reg.deviceID {
			return false
		}
		for _, item := range page.Items {
			if item.SourceKey.Kind == entity.BMPPeer {
				last = fmt.Sprintf("current=%t alias=%s:%s agent=%s configured=%s support=%s",
					item.Current, item.Alias.Kind, item.Alias.Value, item.SourceKey.AgentID,
					item.SourceKey.SourceRef, item.SupportEvidenceID)
			}
			if item.Current && item.Alias.Kind == entity.AddressAlias &&
				item.Alias.Value == edgeIP && item.SourceKey.AgentID == tn.collectorID &&
				item.SourceKey.Kind == entity.BMPPeer && item.SourceKey.SourceRef == tn.routerID &&
				item.SupportEvidenceID != "" && item.OriginSerial != "" &&
				currentEdgeSNMPSupport(t, st, reg, edgeIP, deviceAgentID,
					item.SupportEvidenceID, item.ObservedAt) {
				matched = true
				return true
			}
		}
		return false
	})
	t.Logf("FX-2 BMP source: authenticated rtr-a frame names edge peer %s and current device %s",
		edgeIP, reg.deviceID)
}

// startShippedEdgeFlow binds only to the lab's host-routed Docker bridge.
// The UDP source ACL and the narrower evidence exporter list both name edge.
func startShippedEdgeFlow(t *testing.T, st *shipped.Stack, lab *routingLab, reg edgeFlowRegistration) string {
	t.Helper()
	return startShippedRouterFlow(t, st, lab, reg, lab.ip["edge"])
}

func startShippedRouterFlow(t *testing.T, st *shipped.Stack, lab *routingLab, reg edgeFlowRegistration, exporterIP string) string {
	t.Helper()
	return startShippedRouterFlowProtocols(t, st, lab, reg, exporterIP, []string{"IPFIX"})["IPFIX"]
}

func startShippedRouterFlowProtocols(t *testing.T, st *shipped.Stack, lab *routingLab, reg edgeFlowRegistration, exporterIP string, protocols []string) map[string]string {
	t.Helper()
	gateway := labBridgeGateway(t, lab)
	env := reg.env
	env["PROBECTL_FLOW_BUS_MODE"] = "kafka"
	env["PROBECTL_FLOW_BUS_BROKERS"] = strings.Join(testsupport.KafkaBrokers(), ",")
	env["PROBECTL_FLOW_BUS_ALLOW_PLAINTEXT"] = "true" // CI-only development broker
	env["PROBECTL_FLOW_FLUSH_INTERVAL"] = "100ms"
	env["PROBECTL_FLOW_METRICS_ADDR"] = shipped.FreeAddr(t)
	env["PROBECTL_FLOW_METRICS_TLS_CERT_FILE"] = st.ServerCert
	env["PROBECTL_FLOW_METRICS_TLS_KEY_FILE"] = st.ServerKey
	env["PROBECTL_FLOW_NETFLOW_ENABLED"] = "false"
	env["PROBECTL_FLOW_SFLOW_ENABLED"] = "false"
	env["PROBECTL_FLOW_IPFIX_ENABLED"] = "false"
	listeners := map[string]string{}
	var probes []*net.UDPConn
	defer func() {
		for _, probe := range probes {
			_ = probe.Close()
		}
	}()
	for _, protocol := range protocols {
		if (protocol != "NETFLOW" && protocol != "IPFIX" && protocol != "SFLOW") || listeners[protocol] != "" {
			t.Fatal("invalid or duplicate owned flow protocol", protocol)
		}
		probe, err := net.ListenUDP("udp4", &net.UDPAddr{IP: gateway, Port: 0})
		if err != nil {
			t.Fatal("reserve owned protocol listener", err)
		}
		probes = append(probes, probe)
		listener := probe.LocalAddr().String()
		listeners[protocol] = listener
		env["PROBECTL_FLOW_"+protocol+"_ENABLED"] = "true"
		env["PROBECTL_FLOW_"+protocol+"_LISTEN"] = listener
		env["PROBECTL_FLOW_"+protocol+"_ALLOWED_SOURCES"] = exporterIP + "/32"
	}
	for _, probe := range probes {
		if err := probe.Close(); err != nil {
			t.Fatal(err)
		}
	}
	probes = nil
	env["PROBECTL_FLOW_EVIDENCE_CONTROL_ADDR"] = st.AgentAddr
	env["PROBECTL_FLOW_EVIDENCE_ROTATE_URL"] = st.BaseURL + "/enroll/agent/rotate"
	env["PROBECTL_FLOW_EVIDENCE_CERT_FILE"] = reg.certFile
	env["PROBECTL_FLOW_EVIDENCE_KEY_FILE"] = reg.keyFile
	env["PROBECTL_FLOW_EVIDENCE_CA_FILE"] = reg.caFile
	env["PROBECTL_FLOW_EVIDENCE_SERVER_NAME"] = "localhost"
	env["PROBECTL_FLOW_EVIDENCE_EXPORTERS"] = exporterIP
	keys := make([]string, 0, len(env))
	for key := range env {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	values := make([]string, 0, len(keys))
	for _, key := range keys {
		values = append(values, key+"="+env[key])
	}
	log := st.StartProcess(t, "fx2-edge-flow-collector", st.Binary(t, "probectl-flow-agent"), nil, values)
	shipped.Await(t, "shipped source-bound protocol listeners", 20*time.Second, func() bool {
		contents, err := os.ReadFile(log)
		if err != nil || !strings.Contains(string(contents), "flow: listening") {
			return false
		}
		for _, listener := range listeners {
			if !strings.Contains(string(contents), listener) {
				return false
			}
		}
		return true
	})
	return listeners
}

// The query crosses the shipped collector, bus, ClickHouse and tenant API.
// A raw receipt proves real IPFIX ingestion, but does not assert identity.
func awaitShippedEdgeFlow(t *testing.T, st *shipped.Stack, reg edgeFlowRegistration, exporterIP string, observed time.Time) {
	t.Helper()
	plan := flow.QueryPlan{From: observed.Add(-time.Minute), To: observed.Add(5 * time.Minute),
		GroupBy: []string{"exporter"}, View: "table", RowLimit: 20, PageSize: 20,
		Metrics: []flow.QueryMetric{{Measure: "flows", Calculation: "total", Role: "primary"}}}
	shipped.Await(t, "edge IPFIX flow in tenant-scoped ClickHouse", 30*time.Second, func() bool {
		code, payload := st.Do(t, reg.cookie, http.MethodPost, "/v1/explorer/query",
			map[string]any{"source": "flow", "flow": plan})
		if code != http.StatusOK {
			return false
		}
		var result struct {
			Flow flowstore.PlanResult `json:"flow"`
		}
		if json.Unmarshal(payload, &result) != nil || result.Flow.Source != "raw" ||
			result.Flow.Coverage == nil || !result.Flow.Coverage.CompleteInputs {
			return false
		}
		for _, row := range result.Flow.Rows {
			if row.Group["exporter"] == exporterIP {
				count, err := strconv.ParseUint(row.Metrics["flows:total"], 10, 64)
				return err == nil && count > 0
			}
		}
		return false
	})
	t.Logf("FX-2 raw flow source: shipped collector %s persisted real edge IPFIX for tenant %s", reg.agentID, reg.tenantID)
}

func labBridgeGateway(t *testing.T, lab *routingLab) net.IP {
	t.Helper()
	gwIP := net.ParseIP(lab.gateway)
	if gwIP == nil || gwIP.To4() == nil {
		t.Fatalf("routing lab bridge gateway %q is not IPv4", lab.gateway)
	}
	return gwIP
}

// startEdgeIPFIXExporter puts the real exporter in edge's network namespace.
func startEdgeIPFIXExporter(t *testing.T, lab *routingLab, destination string) string {
	t.Helper()
	const base = "alpine:3.22.6@sha256:5291449c3df73caf6ed85e649dec1b9e818b39a5d8c871e97afc13e9cd5e8fa8"
	const image = "probectl-qa-beta-fx2-softflowd:alpine-3.22.6-v1.1.0-r0"
	cmd := exec.Command("docker", "build", "-q", "-t", image, "-")
	cmd.Stdin = strings.NewReader("FROM " + base + "\nRUN apk add --no-cache softflowd=1.1.0-r0\n")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build pinned FX-2 IPFIX exporter fixture: %v\n%s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("docker", "image", "rm", image).Run() })
	name := lab.name + "-edge-flow"
	_ = exec.Command("docker", "rm", "-f", name).Run()
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", name).Run() })
	lab.docker(t, "create", "--name", name,
		"--network", "container:"+lab.container("edge"), "--cap-add", "NET_RAW",
		image, "softflowd", "-d", "-N", "-i", "eth0", "-v", "10",
		// softflowd 1.1.0 sets a zero pcap timeout without immediate mode.
		// A small ring plus a bounded traffic burst makes libpcap deliver a
		// complete block on the low-rate CI bridge before dump-flows runs.
		"-B", "65536",
		"-n", destination,
		"-c", "/tmp/softflowd.ctl")
	lab.docker(t, "start", name)
	shipped.Await(t, "co-located edge IPFIX exporter", 30*time.Second, func() bool {
		return exec.Command("docker", "exec", name, "softflowctl", "-c", "/tmp/softflowd.ctl", "statistics").Run() == nil
	})
	return name
}

func emitEdgeFlow(t *testing.T, lab *routingLab, exporterContainer string) {
	t.Helper()
	// The exporter shares edge's network namespace and captures eth0. Clear
	// BGP setup traffic, then generate a real packet on that interface from
	// edge to its reachable rtr-a peer. A host-to-edge probe can use a local
	// bridge path that does not exercise the exporter's captured interface.
	lab.docker(t, "exec", exporterContainer, "softflowctl", "-c", "/tmp/softflowd.ctl", "delete-all")
	trafficContext, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	probe, err := exec.CommandContext(trafficContext, "docker", "exec", exporterContainer,
		"ping", "-A", "-q", "-c", "4096", "-s", "1200", "-W", "1", lab.ip["rtr-a"]).CombinedOutput()
	if err != nil {
		t.Fatalf("edge traffic burst failed: %v: %.512s", err, probe)
	}
	deadline := time.Now().Add(10 * time.Second)
	var dump []byte
	var dumpErr error
	for time.Now().Before(deadline) {
		dump, dumpErr = exec.Command("docker", "exec", exporterContainer,
			"softflowctl", "-c", "/tmp/softflowd.ctl", "dump-flows").Output()
		if dumpErr == nil && strings.Contains(string(dump), lab.ip["edge"]) &&
			strings.Contains(string(dump), lab.ip["rtr-a"]) && strings.Contains(string(dump), "proto:1") {
			lab.docker(t, "exec", exporterContainer, "softflowctl", "-c", "/tmp/softflowd.ctl", "expire-all")
			return
		}
		time.Sleep(250 * time.Millisecond)
	}
	statistics, statisticsErr := exec.Command("docker", "exec", exporterContainer,
		"softflowctl", "-c", "/tmp/softflowd.ctl", "statistics").CombinedOutput()
	t.Fatalf("edge exporter did not capture edge-to-rtr-a ICMP on eth0: dump error=%v, dump=%.4096s; statistics error=%v, statistics=%.4096s",
		dumpErr, dump, statisticsErr, statistics)
}

func startEdgeSNMP(t *testing.T, lab *routingLab) string {
	t.Helper()
	return startRouterSNMP(t, lab, "edge")
}

func startRouterSNMP(t *testing.T, lab *routingLab, router string) string {
	t.Helper()
	const base = "alpine:3.22.6@sha256:5291449c3df73caf6ed85e649dec1b9e818b39a5d8c871e97afc13e9cd5e8fa8"
	const image = "probectl-qa-beta-fx2-snmpd:alpine-3.22.6"
	dockerfile := "FROM " + base + "\nRUN apk add --no-cache net-snmp net-snmp-tools\n"
	cmd := exec.Command("docker", "build", "-q", "-t", image, "-")
	cmd.Stdin = strings.NewReader(dockerfile)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build pinned FX-2 SNMP fixture: %v\n%s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("docker", "image", "rm", image).Run() })
	name := lab.name + "-" + router + "-snmp"
	_ = exec.Command("docker", "rm", "-f", name).Run()
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", name).Run() })
	lab.docker(t, "create", "--name", name,
		"--network", "container:"+lab.container(router), image,
		"snmpd", "-f", "-Lo", "-C", "-c", "/etc/snmp/snmpd.conf", "udp:161")
	secret, err := crypto.Random(16)
	if err != nil {
		t.Fatal(err)
	}
	community := "fx2-" + hex.EncodeToString(secret)
	t.Cleanup(func() {
		if t.Failed() {
			out, _ := exec.Command("docker", "logs", "--tail", "20", name).CombinedOutput()
			t.Logf("edge SNMP sidecar log tail:\n%s", strings.ReplaceAll(string(out), community, "[redacted]"))
		}
	})
	config := fmt.Sprintf(`rocommunity %s
sysName fx2-edge-r1
sysLocation FX-2 router lab
override .1.0.8802.1.1.2.1.3.7.1.2.2 integer 5
override .1.0.8802.1.1.2.1.3.7.1.3.2 octet_str "eth0"
override .1.0.8802.1.1.2.1.3.7.1.4.2 octet_str "edge-uplink"
override .1.0.8802.1.1.2.1.4.1.1.4.0.2.1 integer 4
override .1.0.8802.1.1.2.1.4.1.1.5.0.2.1 octet_str "02:42:ac:11:00:88"
override .1.0.8802.1.1.2.1.4.1.1.6.0.2.1 integer 5
override .1.0.8802.1.1.2.1.4.1.1.7.0.2.1 octet_str "sw1-uplink"
override .1.0.8802.1.1.2.1.4.1.1.8.0.2.1 octet_str "access-uplink"
override .1.0.8802.1.1.2.1.4.1.1.9.0.2.1 octet_str "fx2-access-sw1"
override .1.0.8802.1.1.2.1.4.1.1.10.0.2.1 octet_str "access switch"
`, community)
	configFile := filepath.Join(t.TempDir(), "snmpd.conf")
	if err := os.WriteFile(configFile, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	lab.docker(t, "cp", configFile, name+":/etc/snmp/snmpd.conf")
	lab.docker(t, "start", name)
	shipped.Await(t, "co-located edge SNMP", 30*time.Second, func() bool {
		out, err := exec.Command("docker", "exec", name, "snmpget", "-v2c", "-c", community,
			"-t", "1", "-r", "0", "-Ovq", "127.0.0.1", "SNMPv2-MIB::sysName.0").Output()
		return err == nil && strings.TrimSpace(string(out)) == "fx2-edge-r1"
	})
	return community
}

func queryEdgeSNMP(t *testing.T, container, community, oid string) string {
	t.Helper()
	out, err := exec.Command("docker", "exec", container,
		"snmpget", "-v2c", "-c", community, "-t", "1", "-r", "0", "-Ovq",
		"127.0.0.1", oid).Output()
	if err != nil {
		// The argv contains a throwaway credential; never log the full command.
		t.Fatalf("edge SNMP query %s failed: %v", oid, err)
	}
	return strings.TrimSpace(string(out))
}

func startRouterBMPEvidenceListener(t *testing.T, st *shipped.Stack, lab *routingLab, reg edgeFlowRegistration, originAnchor string) *bgpTenant {
	t.Helper()
	return startRouterBMPEvidenceListenerNamed(t, st, lab, reg, originAnchor, "fx2")
}

func startRouterBMPEvidenceListenerNamed(t *testing.T, st *shipped.Stack, lab *routingLab, reg edgeFlowRegistration, originAnchor, prefix string) *bgpTenant {
	t.Helper()
	tn := &bgpTenant{slug: prefix + "-router", id: reg.tenantID, cookie: reg.cookie,
		router: "rtr-a", prefix: prefixA}
	tn.setupAPI(t, st)
	tn.registerRouterAPI(t, st)
	code, payload := st.Do(t, reg.cookie, http.MethodPut, "/v1/entity-source-contexts",
		routerBMPSourceBinding(tn.collectorID, tn.routerID, reg.contextID, originAnchor))
	if code != http.StatusOK {
		t.Fatalf("assign FX-2 authenticated BMP peer context: HTTP %d: %.300s", code, payload)
	}
	csr, key, err := crypto.CreateCSR(prefix + "-bmp-listener-evidence")
	if err != nil {
		t.Fatal(err)
	}
	code, payload = st.Do(t, reg.cookie, http.MethodPost, "/v1/agents/enroll-tokens",
		map[string]any{"name": prefix + "-bmp-evidence", "ttl_seconds": 600,
			"agent_id": tn.collectorID})
	if code != http.StatusCreated {
		t.Fatalf("mint FX-2 BMP evidence token: HTTP %d", code)
	}
	var token struct{ Token string }
	if err := json.Unmarshal(payload, &token); err != nil || token.Token == "" {
		t.Fatalf("decode FX-2 BMP evidence token: %v", err)
	}
	code, payload = st.Do(t, reg.cookie, http.MethodPost, "/v1/collectors/register",
		map[string]string{"token": token.Token, "plane": "entity",
			"hostname": prefix + "-bmp-listener", "csr_pem": string(csr)})
	if code != http.StatusCreated {
		t.Fatalf("register FX-2 BMP evidence SVID: HTTP %d: %.300s", code, payload)
	}
	var evidence struct {
		TenantID string           `json:"tenant_id"`
		AgentID  string           `json:"agent_id"`
		Plane    string           `json:"plane"`
		SVID     *enroll.Identity `json:"svid"`
	}
	if err := json.Unmarshal(payload, &evidence); err != nil ||
		evidence.TenantID != reg.tenantID || evidence.AgentID != tn.collectorID ||
		evidence.Plane != "entity" || evidence.SVID == nil ||
		evidence.SVID.SPIFFEID != crypto.EntitySPIFFEID(reg.tenantID, tn.collectorID) {
		t.Fatalf("FX-2 BMP evidence registration lost exact listener identity: %v", err)
	}
	certFile, keyFile, caFile := writeRouterEvidenceFiles(t, st, prefix+"-bmp-evidence", evidence.SVID.CertPEM, key)
	logins := bmpLogins(t, st)
	tn.listenAddr = shipped.FreeAddr(t)
	tn.listenerLog = st.StartProcess(t, prefix+"-bmp-listener",
		st.Binary(t, "probectl-bmp-listener"), nil, []string{
			"PROBECTL_BMP_LISTEN_ADDR=" + tn.listenAddr,
			"PROBECTL_BMP_TLS_CERT_FILE=" + st.ServerCert,
			"PROBECTL_BMP_TLS_KEY_FILE=" + st.ServerKey,
			"PROBECTL_BMP_TLS_CA_FILE=" + st.AgentCAFile,
			"PROBECTL_BMP_DATABASE_URL=" + logins.registry,
			"PROBECTL_BMP_REVOCATION_DATABASE_URL=" + logins.revocation,
			"PROBECTL_BMP_TENANT_ID=" + reg.tenantID,
			"PROBECTL_BMP_AGENT_ID=" + tn.collectorID,
			"PROBECTL_BMP_COLLECTOR=" + tn.collectorID,
			"PROBECTL_BMP_BUS_NAMESPACE=" + tn.lane,
			"PROBECTL_BMP_BUS_MODE=kafka",
			"PROBECTL_BMP_BUS_BROKERS=" + strings.Join(testsupport.KafkaBrokers(), ","),
			"PROBECTL_BMP_BUS_ALLOW_PLAINTEXT=true", // CI-only development broker
			"PROBECTL_BMP_METRICS_ADDR=" + shipped.FreeAddr(t),
			"PROBECTL_BMP_EVIDENCE_CONTROL_ADDR=" + st.AgentAddr,
			"PROBECTL_BMP_EVIDENCE_ROTATE_URL=" + st.BaseURL + "/enroll/agent/rotate",
			"PROBECTL_BMP_EVIDENCE_CERT_FILE=" + certFile,
			"PROBECTL_BMP_EVIDENCE_KEY_FILE=" + keyFile,
			"PROBECTL_BMP_EVIDENCE_CA_FILE=" + caFile,
			"PROBECTL_BMP_EVIDENCE_SERVER_NAME=localhost",
		})
	tn.reconnectBMP = bridgeBMP(t, lab.bmpAddr(t, tn.router), tn.listenAddr, tn.routerTLS(t, st))
	tn.awaitListener(t, "FX-2 FRR rtr-a's route from edge", "route_observation")
	return tn
}

func routerBMPSourceBinding(agent, source, contextID, anchor string) map[string]string {
	out := map[string]string{"agent_id": agent, "source_kind": "bmp_peer", "source_ref": source, "context_id": contextID}
	if anchor != "" {
		out["anchor_entity_id"] = anchor
	}
	return out
}
