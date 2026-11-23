// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package device_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httptest"
	"net/mail"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/config"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/enroll"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/reporting"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenantlife"
	"github.com/ctlplne/probectl/internal/testsupport"
	"github.com/ctlplne/probectl/internal/testsupport/shipped"
)

const prospectLabSite = "prospect-lab"
const prospectBrowserFailurePage = "<html><body>Prospect lab checkout unavailable</body></html>"

type prospectSourceLane struct {
	*deviceTenant
	flowAddress, testID, agentID, identity, flowDB string
	probeEvidence                                  string
	browserArtifact                                string
	flowSource                                     [3]byte
	physical                                       *snmpTagProof
	peer                                           *deviceTenant
	peerEntityID                                   string
	physicalLinkIDs                                [2]string
	assessment                                     store.DashboardView
	engagement                                     store.ProspectEngagement
}

// This uses the shipped binaries and tenant stores. Net-SNMP exposes
// controlled device and LLDP facts, the NetFlow exporter emits controlled
// wire counters, and the synthetic agent measures an owned loopback target.
func TestProspectLifecycleCollectsOriginalSourcesAndErasesShippedStores(t *testing.T) {
	pdfVerifier, err := exec.LookPath("pdftotext")
	if err != nil {
		testsupport.SkipOrFatal(t, "CI Poppler pdftotext is required for independent prospect PDF proof")
	}
	irPrivate := filepath.Join(t.TempDir(), "ir-private")
	if err := os.Mkdir(irPrivate, 0o700); err != nil {
		t.Fatal(err)
	}
	unlock, err := crypto.Random(32)
	if err != nil {
		t.Fatal(err)
	}
	lab := startSNMPLab(t)
	st := shipped.Start(t, shipped.Options{Name: "prospectlifecycle", TenantBand: 4, Env: map[string]string{
		"PROBECTL_TESTSYNC_SIGNING_KEY_FILE": filepath.Join(t.TempDir(), "testsync-signing-key.pem"),
		// Use the same disposable keyring that the manual MSP erasure proof mounts.
		"PROBECTL_IR_PRIVATE_KEY_DIR":    irPrivate,
		"PROBECTL_IR_UNLOCK_KEY_ID":      "prospect-lab-ir-unlock",
		"PROBECTL_IR_UNLOCK_KEY":         base64.StdEncoding.EncodeToString(unlock),
		"PROBECTL_BACKUP_RETENTION_DAYS": "14",
	}})
	// Compile before recording the compressed deadline.
	st.Binary(t, "probectl-device-agent")
	flowBinary := st.Binary(t, "probectl-flow-agent")
	operator := st.OnboardOperator(t, "root@msp-prospect.example")
	run := strconv.FormatInt(time.Now().UnixNano(), 36)
	lanes := [2]prospectSourceLane{}
	admins := [2]string{"ada@acme.example", "bob@globex.example"}
	for i, name := range []string{"north", "south"} {
		lane := &lanes[i]
		lane.flowSource = [3]byte{10, byte(55 + i), 0}
		lane.deviceTenant = &deviceTenant{slug: "prospect-" + name + "-" + run, name: "Prospect " + name, model: "hybrid",
			admin: admins[i], profile: "topology-rich", sysName: name + "-router", sysDescr: name + " observed device",
			neighbor: name + "peer-router", neighborPort: name + "-Gi0/48", transport: "snmpv2c", credential: name + "-readonly",
			community: name + "-test-only-" + run}
		var tenant struct{ ID string }
		st.MustCLI(t, map[string]string{"PROBECTL_API_TOKEN": operator}, &tenant, "provider", "create-tenant", "--body",
			fmt.Sprintf(`{"slug":%q,"name":%q,"isolation_model":%q}`, lane.slug, lane.name, lane.model))
		lane.id = tenant.ID
		lane.cookie = st.SignIn(t, lane.id, lane.admin, lane.name)
		lane.token = st.APIToken(t, lane.cookie, "tenant.read", "agent.write", "metrics.read", "topology.read", "test.read", "flow.read", "lifecycle.erase", "lifecycle.export")
		var layout struct {
			SiloRouting struct {
				ClickHouseDatabase string `json:"clickhouse_database"`
			} `json:"silo_routing"`
		}
		lane.get(t, st, "/v1/isolation/status", &layout)
		lane.flowDB = layout.SiloRouting.ClickHouseDatabase
		if lane.flowDB == "" || (i > 0 && lane.flowDB == lanes[0].flowDB) {
			t.Fatal("the two hybrid proof lanes require independent ClickHouse stores")
		}
		lane.device = lab.startDevice(t, lane.deviceTenant)
		lane.registerAPI(t, st)
		lane.physical = prepareSNMPTagProof(t, st, lane.deviceTenant)
		lane.peer = &deviceTenant{id: lane.id, slug: lane.slug + "-peer", name: lane.name + " peer", cookie: lane.cookie, model: lane.model,
			profile: "topology-rich", sysName: lane.neighbor, sysDescr: name + " observed peer", neighbor: lane.sysName,
			neighborPort: name + "-Gi0/49", transport: "snmpv2c", credential: name + "-peer-readonly", community: name + "-peer-test-only-" + run}
		lane.peer.device = lab.startDevice(t, lane.peer)
		lane.peer.registerAPI(t, st)
		peer := &snmpTagProof{tenant: lane.peer, contextID: lane.physical.contextID}
		peer.registerDeviceEvidence(t, st, lane.peer.sysName)
		lane.peerEntityID = peer.entityID
		lane.agentID = uuid.NewString()
		lane.identity = st.EnrollAgent(t, lane.id, lane.agentID, "probe-"+lane.slug)
		if _, err := os.Stat(filepath.Join(lane.identity, "testsync.pub")); err != nil {
			t.Fatal("enrollment omitted the configured-test trust key", err)
		}
		lane.probeEvidence = prepareProspectProbeEvidence(t, st, lane)
	}
	kept, erased := &lanes[1], &lanes[0]
	// A missing archive causes an actual transient SMTP 451 before any
	// acknowledgment, leaving the filed PDF available to check and export.
	archive := filepath.Join(t.TempDir(), "archive")
	mailerTLS, err := crypto.ServerTLSConfig(st.ServerCert, st.ServerKey)
	if err != nil {
		t.Fatal(err)
	}
	password, err := crypto.UUIDv4()
	if err != nil {
		t.Fatal(err)
	}
	relay := testsupport.StartArchivingSMTPServer(t, mailerTLS, "report-relay", password, archive)
	_, port, err := net.SplitHostPort(relay.Addr)
	if err != nil {
		t.Fatal(err)
	}
	recipient := "archive@" + erased.slug + ".invalid"
	destinationConfig, err := json.Marshal([]config.ReportEmailDestination{{TenantID: erased.id, ID: "sealed-assessment", Name: "Sealed assessment archive", Recipients: []string{recipient}}})
	if err != nil {
		t.Fatal(err)
	}
	st.RestartControl(t, "prospect-delivery-config", map[string]string{
		"PROBECTL_ALERT_SMTP_ADDR": net.JoinHostPort("localhost", port), "PROBECTL_ALERT_SMTP_TLS_MODE": "starttls",
		"PROBECTL_ALERT_SMTP_USERNAME": "report-relay", "PROBECTL_ALERT_SMTP_PASSWORD": password,
		"PROBECTL_ALERT_SMTP_FROM": "reports@probectl.test", "PROBECTL_ALERT_SMTP_CA_FILE": st.CAFile,
		"PROBECTL_REPORT_EMAIL_DESTINATIONS": string(destinationConfig),
	})
	unavailable := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = io.WriteString(w, prospectBrowserFailurePage)
	})
	probeTarget := httptest.NewUnstartedServer(unavailable)
	probeTarget.TLS = mailerTLS.Clone()
	probeTarget.StartTLS()
	t.Cleanup(probeTarget.Close)
	browserTarget := httptest.NewServer(unavailable)
	t.Cleanup(browserTarget.Close)
	t.Setenv("PROBECTL_AGENT_CANARY_CA_DIR", filepath.Dir(st.CAFile))
	for i := range lanes {
		lane := &lanes[i]
		prepareProspectSourceViews(t, st, lane, probeTarget.URL+"/"+lane.slug)
		lane.flowAddress = shipped.FreeUDPAddr(t)
	}
	destination := prospectiveArchiveDestination(t, st, erased)
	endsAt := time.Now().UTC().Add(120 * time.Second).Truncate(time.Microsecond)
	for i := range lanes {
		lane := &lanes[i]
		input := map[string]any{"assessment_view_id": lane.assessment.ID, "assessment_view_revision": lane.assessment.UpdatedAt,
			"preparer": "Assessment by " + lane.slug, "ends_at": endsAt}
		if lane == erased {
			input["destination_id"], input["confirm_tenant"] = destination, lane.slug
			snmpTagWrite(t, st, lane.deviceTenant, http.StatusCreated, http.MethodPost, "/v1/lifecycle/prospect", input, &lane.engagement)
		} else {
			lane.cli(t, st, &lane.engagement, "lifecycle", "start-prospect", "--body-file", st.SecretFile(t, input))
		}
		if lane.engagement.Revision != 1 || !lane.engagement.EndsAt.Equal(endsAt) || (lane.engagement.ConsentedAt != nil) != (lane == erased) {
			t.Fatal("source lane lost the exact engagement deadline or consent binding")
		}
		lane.hint["prospect_collection_ends_at"] = endsAt.Format(time.RFC3339Nano)
		lane.startAgent(t, st, lab)
		lane.peer.hint["prospect_collection_ends_at"] = endsAt.Format(time.RFC3339Nano)
		lane.peer.startAgent(t, st, lab)
		startProspectFlowCollector(t, st, lane, flowBinary, endsAt)
		go shipped.ExportNetFlow(t.Context(), lane.flowAddress, lane.flowSource)
		st.StartAgent(t, lane.identity, "probe-"+lane.slug, []string{"http", "browser"}, fmt.Sprintf(`prospect_collection_ends_at: %q
identity:
  server: %q
  auto_rotate: true
artifact_store:
  dir: %q
  isolation: hybrid
browser:
  driver: http
canaries:
  - type: browser
    target: %q
    interval: 5s
    timeout: 4s
    params:
      allow_private_targets: "true"
test_sync:
  enabled: true
  interval: 2s
  allowed_types: [http]
  allow_private_targets: true
%s`, endsAt.Format(time.RFC3339Nano), st.BaseURL, st.ObjectDir, browserTarget.URL+"/artifact/"+lane.slug, lane.probeEvidence), prospectLabSite)
	}
	// The final minute is represented by the exact current raw-flow view. The
	// controlled exporters continue through the tick and the collection fence.
	for i := range lanes {
		lane := &lanes[i]
		lane.awaitNeighbors(t, st, 35*time.Second)
		lane.peer.awaitNeighbors(t, st, 35*time.Second)
		lane.awaitMetrics(t, st, 35*time.Second)
		awaitProspectWireSamples(t, st, lane)
		awaitProspectBrowserArtifact(t, st, lane)
		restartProspectDeviceSources(t, st, lab, lane)
		awaitProspectPhysicalLinks(t, st, lane)
		t.Logf("%s has original configured HTTPS, decoded NetFlow and canonical LLDP results", lane.slug)
	}
	proveShippedProspectCutoffAndErasure(t, st, erased, kept, relay, archive, recipient, pdfVerifier, endsAt)
}

func prepareProspectProbeEvidence(t *testing.T, st *shipped.Stack, lane *prospectSourceLane) string {
	t.Helper()
	csr, key, err := crypto.CreateCSR("probe-evidence-" + lane.slug)
	if err != nil {
		t.Fatal(err)
	}
	var token struct{ Token string }
	snmpTagWrite(t, st, lane.deviceTenant, http.StatusCreated, http.MethodPost, "/v1/agents/enroll-tokens",
		map[string]any{"agent_id": lane.agentID, "name": "probe-evidence-" + lane.slug, "ttl_seconds": 600}, &token)
	var enrolled enroll.CollectorIdentity
	snmpTagWrite(t, st, lane.deviceTenant, http.StatusCreated, http.MethodPost, "/v1/collectors/register",
		map[string]string{"token": token.Token, "plane": "entity", "hostname": "probe-evidence-" + lane.slug, "csr_pem": string(csr)}, &enrolled)
	if enrolled.TenantID != lane.id || enrolled.AgentID != lane.agentID || enrolled.SVID == nil ||
		enrolled.SVID.SPIFFEID != crypto.EntitySPIFFEID(lane.id, lane.agentID) {
		t.Fatal("the independent synthetic evidence channel changed its source identity")
	}
	dir := t.TempDir()
	serverCA, err := os.ReadFile(st.CAFile)
	if err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string][]byte{"cert.pem": []byte(enrolled.SVID.CertPEM), "key.pem": key, "server-ca.pem": serverCA} {
		if err := os.WriteFile(filepath.Join(dir, name), body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return fmt.Sprintf(`evidence:
  control_addr: %q
  server_name: localhost
  cert_file: %q
  key_file: %q
  ca_file: %q
`, st.AgentAddr, filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem"), filepath.Join(dir, "server-ca.pem"))
}

func prepareProspectSourceViews(t *testing.T, st *shipped.Stack, lane *prospectSourceLane, target string) {
	t.Helper()
	var site struct{ ID string }
	snmpTagWrite(t, st, lane.deviceTenant, http.StatusCreated, http.MethodPost, "/v1/entities",
		map[string]string{"context_id": lane.physical.contextID, "kind": "site", "label": prospectLabSite}, &site)
	snmpTagWrite(t, st, lane.deviceTenant, http.StatusOK, http.MethodPut, "/v1/entity-source-contexts", map[string]string{
		"agent_id": lane.agentID, "source_kind": "agent_site", "source_ref": lane.agentID,
		"context_id": lane.physical.contextID, "anchor_entity_id": site.ID,
	}, nil)
	var test struct{ ID string }
	snmpTagWrite(t, st, lane.deviceTenant, http.StatusCreated, http.MethodPost, "/v1/tests", map[string]any{
		"name": lane.slug + " original availability", "type": "http", "target": target, "interval_seconds": 10,
		"timeout_seconds": 3, "params": map[string]string{"allow_private_targets": "true", "ca_file": st.CAFile}, "enabled": true,
	}, &test)
	lane.testID = test.ID
	if lane.testID == "" {
		t.Fatal("the shipped probe has no retained test ID")
	}
	snmpTagWrite(t, st, lane.deviceTenant, http.StatusOK, http.MethodPut, "/v1/tests/"+test.ID+"/entity-context",
		map[string]string{"context_id": lane.physical.contextID}, nil)
	snmpTagWrite(t, st, lane.deviceTenant, http.StatusOK, http.MethodPut, "/v1/entity-source-contexts", map[string]string{
		"agent_id": lane.agentID, "source_kind": "path_agent", "source_ref": test.ID,
		"context_id": lane.physical.contextID, "anchor_entity_id": lane.physical.entityID,
	}, nil)
	var view flow.SavedQueryView
	snmpTagWrite(t, st, lane.deviceTenant, http.StatusCreated, http.MethodPost, "/v1/explorer/flow-views", flow.SaveQueryView{Definition: flow.QueryViewDefinition{
		Name: lane.slug + " original NetFlow", Visibility: "private", Time: flow.QueryViewTime{Mode: "lookback", LookbackSeconds: 60},
		Plan: prospectiveFlowPlan(time.Time{}, time.Time{}),
	}}, &view)
	// The saved template carries a valid assessment interval. The worker
	// replaces that interval with the engagement's exact persisted clocks.
	priorEnd := time.Now().UTC().Add(-time.Second)
	snmpTagWrite(t, st, lane.deviceTenant, http.StatusCreated, http.MethodPost, "/v1/dashboards", reporting.DashboardCreateInput{
		Name: lane.slug + " assessment", Preset: "operator", Definition: reporting.DashboardDefinition{
			ClientReport: &reporting.ClientReportDefinition{Timezone: "UTC", Period: "assessment", Assessment: &reporting.ClientReportAssessment{
				From: priorEnd.Add(-time.Hour).Format(time.RFC3339Nano), To: priorEnd.Format(time.RFC3339Nano), Preparer: "Assessment by " + lane.slug,
			}},
			FlowSources:         []reporting.FlowSourceRef{{ID: view.ID, Version: view.Version}},
			RedactionState:      "current tenant policy",
			Provenance:          []string{"Controlled NetFlow exporter, live synthetic HTTPS and simulated Net-SNMP devices"},
			CoverageLimitations: []string{"Two owned lab tenants with a compressed engagement window"},
		},
	}, &lane.assessment)
	if lane.assessment.ID == "" || lane.assessment.UpdatedAt.IsZero() {
		t.Fatal("assessment did not retain an exact saved dashboard revision")
	}
}

func prospectiveFlowPlan(from, to time.Time) flow.QueryPlan {
	return flow.QueryPlan{From: from, To: to, View: "table", DataSeries: "raw", GroupBy: []string{"src_addr"}, RowLimit: 20, PageSize: 20, BucketSeconds: 60,
		Metrics: []flow.QueryMetric{{Measure: "bytes", Calculation: "total", Role: "primary"}, {Measure: "flows", Calculation: "total", Role: "additional"},
			{Measure: "packets", Calculation: "total", Role: "additional"}},
		Filter: &flow.QueryFilterGroup{Conditions: []flow.QueryPredicate{{Field: "src_addr", Op: flow.QueryCIDR, Values: []string{"10.55.0.0/16", "10.56.0.0/16"}}}}}
}

func prospectiveFlows(t *testing.T, st *shipped.Stack, lane *prospectSourceLane, from, to time.Time) flowstore.PlanResult {
	t.Helper()
	var result struct{ Flow flowstore.PlanResult }
	snmpTagWrite(t, st, lane.deviceTenant, http.StatusOK, http.MethodPost, "/v1/explorer/query",
		map[string]any{"source": "flow", "flow": prospectiveFlowPlan(from, to)}, &result)
	return result.Flow
}

func awaitProspectWireSamples(t *testing.T, st *shipped.Stack, lane *prospectSourceLane) {
	t.Helper()
	shipped.Await(t, lane.slug+"'s original configured HTTPS 503 result", 35*time.Second, func() bool {
		var history struct {
			Items []struct {
				Attributes map[string]string  `json:"attributes"`
				Metrics    map[string]float64 `json:"metrics"`
				ObservedAt time.Time          `json:"observed_at"`
			} `json:"items"`
		}
		lane.get(t, st, "/v1/results/history?window=1h", &history)
		for _, result := range history.Items {
			if result.Attributes["probectl.test.id"] == lane.testID && result.Metrics["http.status"] == http.StatusServiceUnavailable &&
				!result.ObservedAt.Before(lane.engagement.StartsAt) {
				return true
			}
		}
		return false
	})
	shipped.Await(t, lane.slug+"'s original decoded NetFlow sample", 25*time.Second, func() bool {
		now := time.Now().UTC()
		result := prospectiveFlows(t, st, lane, now.Add(-time.Minute), now)
		return result.Totals["flows:total"] != "" && result.Totals["flows:total"] != "0"
	})
}

func awaitProspectBrowserArtifact(t *testing.T, st *shipped.Stack, lane *prospectSourceLane) {
	t.Helper()
	shipped.Await(t, lane.slug+"'s own retained browser failure", 20*time.Second, func() bool {
		var history struct {
			Items []struct {
				AgentID    string            `json:"agent_id"`
				Attributes map[string]string `json:"attributes"`
			} `json:"items"`
		}
		lane.get(t, st, "/v1/results/history?window=1h", &history)
		for _, result := range history.Items {
			key := result.Attributes["browser.screenshot.key"]
			if result.AgentID != lane.agentID || key == "" {
				continue
			}
			if !strings.HasPrefix(key, "silo/"+lane.id+"/browser/") || key != filepath.ToSlash(filepath.Clean(key)) {
				t.Fatal("browser failure did not use the hybrid tenant's object namespace")
			}
			body, err := os.ReadFile(filepath.Join(st.ObjectDir, key))
			if err != nil || string(body) != prospectBrowserFailurePage {
				t.Fatal("browser failure did not retain the exact controlled HTTP body", err)
			}
			lane.browserArtifact = key
			return true
		}
		return false
	})
}

func restartProspectDeviceSources(t *testing.T, st *shipped.Stack, lab *snmpLab, lane *prospectSourceLane) {
	t.Helper()
	devices := [2]*deviceTenant{lane.deviceTenant, lane.peer}
	for i, id := range [2]string{lane.physical.entityID, lane.peerEntityID} {
		device := devices[i]
		path := "/v1/entities/" + id + "/evidence?context_id=" + lane.physical.contextID
		shipped.Await(t, device.slug+"'s independent SNMP identity", 20*time.Second, func() bool {
			var page entity.EvidencePage
			lane.get(t, st, path, &page)
			for _, fact := range page.Items {
				if fact.Alias.Kind == entity.SNMPDeviceAlias && fact.Alias.Value == device.sysName && fact.Current &&
					fact.SourceKey.AgentID == device.collectorID && !fact.ObservedAt.Before(lane.engagement.StartsAt) {
					return page.Scope.TenantID == lane.id && page.EntityID == id
				}
			}
			return false
		})
	}
	// A collector that starts first may see its peer before the peer's signed
	// name is known. Restart the owned lab processes after both independent
	// names arrive to exercise the next collection without waiting an hour.
	for _, device := range devices {
		st.Stop(t, "device-agent-"+device.slug)
		device.startAgent(t, st, lab)
	}
}

func awaitProspectPhysicalLinks(t *testing.T, st *shipped.Stack, lane *prospectSourceLane) {
	t.Helper()
	for i, id := range [2]string{lane.physical.entityID, lane.peerEntityID} {
		path := "/v1/entities/" + id + "/links?context_id=" + lane.physical.contextID
		shipped.Await(t, lane.slug+"'s canonical physical peer", 28*time.Second, func() bool {
			var page entity.LinkPage
			lane.get(t, st, path, &page)
			for _, link := range page.Items {
				if link.Kind == "physical" && link.SourceKind == entity.DeviceTarget && link.ToEntityID == id &&
					link.ID != "" && link.EvidenceID != "" && !link.ObservedAt.Before(lane.engagement.StartsAt) {
					lane.physicalLinkIDs[i] = link.ID
					return page.Scope.TenantID == lane.id && page.EntityID == id
				}
			}
			return false
		})
	}
}

func proveShippedProspectCutoffAndErasure(t *testing.T, st *shipped.Stack, erased, kept *prospectSourceLane,
	relay *testsupport.SMTPServer, archive, recipient, pdfVerifier string, endsAt time.Time) {
	t.Helper()
	ctx := t.Context()
	db, err := pgxpool.New(ctx, st.AdminDSN)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	var originals [2]store.ProspectEngagement
	var pdfs [2][]byte
	var sampled [2]string
	lanes := [2]*prospectSourceLane{erased, kept}
	for i, lane := range lanes {
		shipped.Await(t, lane.slug+"'s filed assessment", time.Until(endsAt)+180*time.Second, func() bool {
			lane.get(t, st, "/v1/lifecycle/prospect", &originals[i])
			return originals[i].AssessmentArtifactID != "" && (lane != erased || originals[i].DeliveryState == "retrying")
		})
		if !originals[i].StartsAt.Equal(lane.engagement.StartsAt) || !originals[i].EndsAt.Equal(endsAt) || !originals[i].AssessmentAt.Equal(lane.assessment.UpdatedAt) {
			t.Fatal("filed assessment changed its original view or exact clocks")
		}
		path := "/v1/dashboard-report-artifacts/" + originals[i].AssessmentArtifactID
		status, pdf := st.Do(t, lane.cookie, http.MethodGet, path, nil)
		if status != http.StatusOK || !bytes.HasPrefix(pdf, []byte("%PDF-")) {
			t.Fatal("the tenant cannot read its filed PDF", status)
		}
		if code, _ := st.Do(t, lanes[1-i].cookie, http.MethodGet, path, nil); code != http.StatusNotFound {
			t.Fatal("the sibling can read a foreign assessment attachment", code)
		}
		pdfs[i] = pdf
		flow := prospectiveFlows(t, st, lane, endsAt.Add(-time.Minute), endsAt)
		sampled[i] = flow.Totals["flows:total"]
		if flow.Source != "raw" || flow.Coverage == nil || !flow.Coverage.CompleteInputs || len(flow.Rows) != 5 || sampled[i] == "" || sampled[i] == "0" {
			t.Fatal("the exact saved interval omitted controlled original flow input")
		}
		assertProspectWireCounters(t, lane, flow)
		assertNoProspectFlowsAfterEnd(t, st, lane, endsAt)
		assertProspectOriginalPDF(t, pdfVerifier, pdf, lane, lanes[1-i], flow)
		verifyProspectSourceExport(t, st, lane, lanes[1-i])
		checkShippedProspectStores(t, db, st.ObjectDir, lane, endsAt, true)
		t.Logf("%s has an independently reconciled PDF and a scoped export with its exact retained artifact", lane.slug)
	}
	if len(relay.Messages()) != 0 {
		t.Fatal("SMTP acknowledged while its independent archive was unavailable")
	}
	if code, _ := st.Do(t, erased.cookie, http.MethodPost, "/auth/logout", nil); code != http.StatusNoContent {
		t.Fatal("the original interactive session could not be closed", code)
	}
	if code, _ := st.Do(t, erased.cookie, http.MethodGet, "/v1/lifecycle/prospect", nil); code != http.StatusUnauthorized {
		t.Fatal("the original interactive session retained authority after logout", code)
	}
	var activeAtCutoff, noErasureAudit bool
	if err := db.QueryRow(ctx, `SELECT
		(SELECT count(*)=2 FROM public.tenants
		 WHERE id IN ($1::uuid,$2::uuid) AND status='active' AND audit_write_fenced_at IS NULL
		 AND prospect_collection_ends_at=$3),
		NOT EXISTS (SELECT 1 FROM public.provider_audit_events
		 WHERE target IN ($1::uuid::text,$2::uuid::text) AND action IN ('lifecycle.erase_fence','lifecycle.erase'))`,
		erased.id, kept.id, endsAt).Scan(&activeAtCutoff, &noErasureAudit); err != nil || !activeAtCutoff || !noErasureAudit {
		t.Fatalf("prospect state before archive acceptance was invalid (active at cutoff %t, no erasure audit %t): %v", activeAtCutoff, noErasureAudit, err)
	}
	if err := os.Mkdir(archive, 0o700); err != nil {
		t.Fatal(err)
	}
	shipped.Await(t, erased.slug+"'s erased registry state after durable delivery", 180*time.Second, func() bool {
		var status string
		if err := db.QueryRow(ctx, `SELECT status FROM public.tenants WHERE id=$1`, erased.id).Scan(&status); err != nil {
			t.Fatal(err)
		}
		return status == "deleted"
	})
	assertShippedProspectReceipt(t, db, erased, kept, hex.EncodeToString(crypto.Hash(pdfs[0])))
	checkShippedProspectStores(t, db, st.ObjectDir, erased, endsAt, false)
	checkShippedProspectStores(t, db, st.ObjectDir, kept, endsAt, true)
	messages := relay.Messages()
	if len(messages) != 1 || !messages[0].TLS || len(messages[0].To) != 1 || messages[0].To[0] != recipient {
		t.Fatal("the shipped retry did not archive one exact tenant envelope")
	}
	verifyShippedProspectArchive(t, archive, pdfs[0])
	flow := prospectiveFlows(t, st, kept, endsAt.Add(-time.Minute), endsAt)
	if flow.Totals["flows:total"] != sampled[1] {
		t.Fatal("the erased tenant affected the sibling's exact retained flows")
	}
	assertNoProspectFlowsAfterEnd(t, st, kept, endsAt)
	status, body := st.Do(t, kept.cookie, http.MethodGet, "/v1/dashboard-report-artifacts/"+originals[1].AssessmentArtifactID, nil)
	if status != http.StatusOK || !bytes.Equal(body, pdfs[1]) {
		t.Fatal("the erased tenant affected the sibling's filed PDF")
	}
	verifyProspectSourceExport(t, st, kept, erased)
}

func assertNoProspectFlowsAfterEnd(t *testing.T, st *shipped.Stack, lane *prospectSourceLane, end time.Time) {
	t.Helper()
	// Leave the exact last admitted microsecond in the already checked window.
	result := prospectiveFlows(t, st, lane, end.Add(time.Microsecond), time.Now().UTC())
	if result.Source != "raw" || result.Coverage == nil || !result.Coverage.CompleteInputs || len(result.Rows) != 0 {
		t.Fatal("the running wire exporter refilled the tenant's raw store after cutoff")
	}
}

func assertProspectWireCounters(t *testing.T, lane *prospectSourceLane, result flowstore.PlanResult) {
	t.Helper()
	prefix := fmt.Sprintf("%d.%d.%d.", lane.flowSource[0], lane.flowSource[1], lane.flowSource[2])
	seen := make(map[string]bool, 5)
	var total int64
	for _, row := range result.Rows {
		address := row.Group["src_addr"]
		host, ok := strings.CutPrefix(address, prefix)
		index, indexErr := strconv.Atoi(host)
		count, countErr := strconv.ParseInt(row.Metrics["flows:total"], 10, 64)
		if !ok || indexErr != nil || index < 1 || index > 5 || seen[address] || countErr != nil || count < 1 || count > 120 ||
			row.Metrics["bytes:total"] != strconv.FormatInt(count*1500, 10) ||
			row.Metrics["packets:total"] != strconv.FormatInt(count*10, 10) {
			t.Fatal("the raw query changed the controlled wire counters or included a foreign source", address)
		}
		seen[address] = true
		total += count
	}
	if result.Totals["flows:total"] != strconv.FormatInt(total, 10) ||
		result.Totals["bytes:total"] != strconv.FormatInt(total*1500, 10) ||
		result.Totals["packets:total"] != strconv.FormatInt(total*10, 10) {
		t.Fatal("the raw totals do not equal the five original wire sources")
	}
}

func assertProspectOriginalPDF(t *testing.T, binary string, pdf []byte, owned, sibling *prospectSourceLane, flow flowstore.PlanResult) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, "-layout", "-enc", "UTF-8", "-", "-")
	cmd.Stdin = bytes.NewReader(pdf)
	text, err := cmd.Output()
	if err != nil || len(text) == 0 || len(text) > 8<<20 {
		t.Fatal("independent prospect PDF extraction failed", err)
	}
	compact := strings.Join(strings.Fields(string(text)), "")
	for _, want := range []string{
		owned.slug, owned.testID, "probectl", "Assessmentby" + owned.slug,
		owned.engagement.StartsAt.UTC().Format(time.RFC3339Nano), owned.engagement.EndsAt.UTC().Format(time.RFC3339Nano),
		"Assessmentavailability", "Canonicalinventoryatreportcapture",
		"Observedphysicaladjacencyatreportcapture", "Observedassessmentrisksandcapacityhotspots", "Assessmentmeasurementcoverageandgaps",
		owned.physical.entityID, owned.peerEntityID, owned.neighborPort, owned.peer.neighborPort, owned.neighbor, owned.sysName,
		owned.physicalLinkIDs[0], owned.physicalLinkIDs[1],
		flow.Totals["flows:total"], flow.Totals["bytes:total"], flow.Totals["packets:total"],
	} {
		if !strings.Contains(compact, want) {
			t.Fatal("the independent PDF omitted an original evidence value", want)
		}
	}
	for _, row := range flow.Rows {
		for _, want := range []string{row.Group["src_addr"], row.Metrics["bytes:total"], row.Metrics["flows:total"], row.Metrics["packets:total"]} {
			if want == "" || !strings.Contains(compact, want) {
				t.Fatal("the independent PDF omitted an exact scoped flow row value", want)
			}
		}
	}
	foreignSource := fmt.Sprintf("%d.%d.%d.", sibling.flowSource[0], sibling.flowSource[1], sibling.flowSource[2])
	for _, foreign := range []string{sibling.slug, sibling.testID, sibling.peerEntityID, sibling.physical.entityID, sibling.neighborPort, foreignSource} {
		if strings.Contains(compact, foreign) {
			t.Fatal("the independent PDF included another tenant's report source")
		}
	}
}

func verifyProspectSourceExport(t *testing.T, st *shipped.Stack, lane, sibling *prospectSourceLane) {
	t.Helper()
	code, raw := st.Do(t, lane.cookie, http.MethodGet, "/v1/lifecycle/export", nil)
	if code != http.StatusOK {
		t.Fatal("could not export the original assessment tenant", code)
	}
	gz, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	source := fmt.Sprintf("%d.%d.%d.1", lane.flowSource[0], lane.flowSource[1], lane.flowSource[2])
	foreignSource := fmt.Sprintf("%d.%d.%d.", sibling.flowSource[0], sibling.flowSource[1], sibling.flowSource[2])
	needed := map[string]string{"manifest.json": lane.id, "flows.jsonl": source, "postgres/tests.jsonl": lane.testID,
		"postgres/device_neighbor_evidence.jsonl": lane.neighbor, "postgres/entity_evidence.jsonl": lane.testID}
	for {
		entry, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		want, ok := needed[entry.Name]
		if !ok {
			continue
		}
		body, err := io.ReadAll(io.LimitReader(tr, 8<<20))
		if err != nil || !bytes.Contains(body, []byte(want)) || bytes.Contains(body, []byte(sibling.id)) ||
			(entry.Name == "flows.jsonl" && bytes.Contains(body, []byte(foreignSource))) {
			t.Fatal("an original export member omitted its scope or showed foreign input", entry.Name, err)
		}
		if entry.Name == "manifest.json" {
			var manifest struct{ Objects []tenantlife.ObjectRef }
			if err := json.Unmarshal(body, &manifest); err != nil {
				t.Fatal("the tenant's original export manifest is unreadable", err)
			}
			found := false
			for _, object := range manifest.Objects {
				found = found || object.Key == lane.browserArtifact && object.Size == int64(len(prospectBrowserFailurePage))
			}
			if !found {
				t.Fatal("the original export omitted the exact owned synthetic failure artifact")
			}
		}
		delete(needed, entry.Name)
	}
	if len(needed) != 0 {
		t.Fatal("original scoped export lost required evidence members", needed)
	}
}

func checkShippedProspectStores(t *testing.T, db *pgxpool.Pool, objectRoot string, lane *prospectSourceLane, endsAt time.Time, retained bool) {
	t.Helper()
	var results, neighbors, after int
	if err := db.QueryRow(t.Context(), `SELECT
		(SELECT count(*) FROM public.entity_evidence WHERE tenant_id=$1 AND configured_ref=$3 AND source_ref='probe:configured-test'),
		(SELECT count(*) FROM public.device_neighbor_evidence WHERE tenant_id=$1),
		(SELECT count(*) FROM public.entity_evidence WHERE tenant_id=$1 AND observed_at>$2 AND configured_ref=$3 AND source_ref='probe:configured-test') +
		(SELECT count(*) FROM public.device_neighbor_evidence WHERE tenant_id=$1 AND observed_at>$2)`, lane.id, endsAt, lane.testID).
		Scan(&results, &neighbors, &after); err != nil {
		t.Fatal("cannot independently read the shipped PostgreSQL stores", err)
	}
	if after != 0 || (results > 0) != retained || (neighbors > 0) != retained {
		t.Fatal("shipped PostgreSQL lost retained data, accepted a late observation or retained erased results", results, neighbors, after)
	}
	for _, r := range lane.flowDB {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '_' {
			t.Fatal("invalid generated ClickHouse database identifier")
		}
	}
	raw, err := shipped.CHQuery(shipped.CHURL(), `SELECT count() FROM system.databases WHERE name='`+lane.flowDB+`'`)
	if err != nil || (strings.TrimSpace(raw) == "1") != retained {
		t.Fatal("shipped ClickHouse did not preserve the sibling or remove its erased peer", err)
	}
	series := promSeries(t, `probectl_device_uptime_seconds{tenant_id="`+lane.id+`"}`)
	if (len(series) > 0) != retained {
		t.Fatal("shipped metrics did not preserve the sibling or remove its erased peer")
	}
	var artifacts int
	err = filepath.WalkDir(filepath.Join(objectRoot, "silo", lane.id), func(_ string, entry os.DirEntry, err error) error {
		if err == nil && !entry.IsDir() {
			artifacts++
		}
		return err
	})
	if err != nil && !os.IsNotExist(err) || (artifacts > 0) != retained {
		t.Fatal("shipped object storage did not preserve the sibling or remove its erased peer", err)
	}
}

func assertShippedProspectReceipt(t *testing.T, db *pgxpool.Pool, erased, kept *prospectSourceLane, assessmentSHA string) {
	t.Helper()
	ctx := t.Context()
	if err := audit.ProviderVerify(ctx, db); err != nil {
		t.Fatal("the shipped provider audit chain does not verify", err)
	}
	var status, recorded, reportHash string
	var receipt []byte
	var fences int
	if err := db.QueryRow(ctx, `SELECT (SELECT status FROM public.tenants WHERE id=$2), count(*)::integer,
		max(data->'scheduled_prospect'->>'assessment_sha256') FROM public.provider_audit_events
		WHERE target=$1 AND action='lifecycle.erase_fence' AND data ? 'scheduled_prospect'`, erased.id, kept.id).
		Scan(&status, &fences, &recorded); err != nil || status != "active" || fences != 1 || recorded != assessmentSHA {
		t.Fatal("the shipped fence omitted its original digest or changed the sibling registry", err)
	}
	if err := db.QueryRow(ctx, `SELECT data->'prospect_attestation', data->>'report_sha256'
		FROM public.provider_audit_events WHERE target=$1 AND action='lifecycle.erase' AND data ? 'prospect_attestation'`, erased.id).
		Scan(&receipt, &reportHash); err != nil {
		t.Fatal("the shipped provider audit did not retain the completed attestation", err)
	}
	var att tenantlife.Attestation
	if err := json.Unmarshal(receipt, &att); err != nil || !att.Complete || att.TenantID != erased.id || att.TenantSlug != erased.slug || att.ReportSHA256 != reportHash {
		t.Fatal("the shipped erasure returned the wrong completed attestation", err)
	}
	required := map[string]bool{"postgres": true, "flows": true, "tsdb": true, "objects": true}
	for _, result := range att.Stores {
		if !result.VerifiedZero || required[result.Store] && result.Notes == "store not deployed" {
			t.Fatal("the shipped attestation did not independently verify the store", result.Store)
		}
		delete(required, result.Store)
	}
	if len(required) > 0 {
		t.Fatal("the shipped attestation omitted deployed stores", required)
	}
	att.ReportSHA256 = ""
	canonical, err := json.Marshal(att)
	if err != nil || hex.EncodeToString(crypto.Hash(canonical)) != reportHash {
		t.Fatal("the shipped attestation digest failed independent recomputation", err)
	}
}

func verifyShippedProspectArchive(t *testing.T, archive string, want []byte) {
	t.Helper()
	entries, err := os.ReadDir(archive)
	if err != nil || len(entries) != 1 {
		t.Fatal("the durable relay did not retain exactly one archived message", err)
	}
	file, err := os.Open(filepath.Join(archive, entries[0].Name()))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	message, err := mail.ReadMessage(file)
	if err != nil {
		t.Fatal(err)
	}
	_, params, err := mime.ParseMediaType(message.Header.Get("Content-Type"))
	if err != nil || params["boundary"] == "" {
		t.Fatal("the archive omitted MIME framing", err)
	}
	parts := multipart.NewReader(message.Body, params["boundary"])
	for {
		part, err := parts.NextPart()
		if err != nil {
			t.Fatal("the relay archive omitted the exact filed assessment", err)
		}
		if strings.HasPrefix(part.Header.Get("Content-Type"), "application/pdf") {
			body, err := io.ReadAll(io.LimitReader(base64.NewDecoder(base64.StdEncoding, part), int64(len(want))+1))
			if err != nil || !bytes.Equal(body, want) {
				t.Fatal("the archived attachment changed the already verified PDF bytes", err)
			}
			return
		}
	}
}

func prospectiveArchiveDestination(t *testing.T, st *shipped.Stack, lane *prospectSourceLane) string {
	t.Helper()
	var schedules struct {
		Destinations []struct {
			ID       string `json:"id"`
			Outbound bool   `json:"outbound"`
			Ready    bool   `json:"ready"`
		} `json:"destinations"`
	}
	lane.get(t, st, "/v1/dashboard-report-schedules", &schedules)
	for _, destination := range schedules.Destinations {
		if destination.Outbound && destination.Ready && strings.HasPrefix(destination.ID, "email/sealed-assessment/") {
			return destination.ID
		}
	}
	t.Fatal("configured durable destination is unavailable to its tenant")
	return ""
}

func startProspectFlowCollector(t *testing.T, st *shipped.Stack, lane *prospectSourceLane, binary string, endsAt time.Time) {
	t.Helper()
	var join struct{ Token string }
	snmpTagWrite(t, st, lane.deviceTenant, http.StatusCreated, http.MethodPost, "/v1/agents/enroll-tokens",
		map[string]any{"name": "flow-" + lane.slug, "ttl_seconds": 600}, &join)
	var registered registration
	snmpTagWrite(t, st, lane.deviceTenant, http.StatusCreated, http.MethodPost, "/v1/collectors/register",
		map[string]any{"token": join.Token, "plane": "flow", "hostname": "flow-" + lane.slug}, &registered)
	if registered.TenantID != lane.id || registered.AgentID == "" || registered.Config.Env == nil || registered.Config.YAML == nil {
		t.Fatal("flow collector lost its scoped registered source")
	}
	registered.Config.YAML["apiVersion"] = "probectl.io/flow-agent/v1"
	registered.Config.YAML["prospect_collection_ends_at"] = endsAt.Format(time.RFC3339Nano)
	cfg := st.SecretFile(t, registered.Config.YAML)
	env := registered.Config.Env
	for key, value := range map[string]string{
		"PROBECTL_FLOW_BUS_MODE": "kafka", "PROBECTL_FLOW_BUS_BROKERS": strings.Join(testsupport.KafkaBrokers(), ","),
		"PROBECTL_FLOW_BUS_ALLOW_PLAINTEXT": "true", "PROBECTL_FLOW_FLUSH_INTERVAL": "1s",
		"PROBECTL_FLOW_METRICS_ADDR": "127.0.0.1:0", "PROBECTL_FLOW_METRICS_TLS_CERT_FILE": st.ServerCert, "PROBECTL_FLOW_METRICS_TLS_KEY_FILE": st.ServerKey,
		"PROBECTL_FLOW_NETFLOW_LISTEN": lane.flowAddress, "PROBECTL_FLOW_NETFLOW_ALLOWED_SOURCES": "127.0.0.1/32", "PROBECTL_FLOW_NETFLOW_ENABLED": "true",
		"PROBECTL_FLOW_IPFIX_ENABLED": "false", "PROBECTL_FLOW_SFLOW_ENABLED": "false",
	} {
		env[key] = value
	}
	values := make([]string, 0, len(env))
	for key, value := range env {
		values = append(values, key+"="+value)
	}
	log := st.StartProcess(t, "prospect-flow-"+lane.slug, binary, []string{"-config", cfg}, values)
	shipped.Await(t, lane.slug+"'s registered flow listener", 20*time.Second, func() bool {
		raw, _ := os.ReadFile(log)
		return bytes.Contains(raw, []byte("flow: listening"))
	})
}
