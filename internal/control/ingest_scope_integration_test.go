// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package control

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/twmb/franz-go/pkg/kgo"
	"google.golang.org/protobuf/proto"

	"github.com/ctlplne/probectl/internal/bgp"
	"github.com/ctlplne/probectl/internal/bus"
	"github.com/ctlplne/probectl/internal/config"
	resultv1 "github.com/ctlplne/probectl/internal/gen/probectl/result/v1"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/testsupport"
)

// TestSharedFeedsIngestOnceAndBGPIngestsPerTenantRealStack is the real-stack
// receipt for CLM-INGEST-SCOPE ("Open-data/threat feeds are ingested once
// (shared) then scoped per tenant; BGP collector ingestion runs per tenant by
// decision of record"). It runs the multi-tenant profile's shape — strict
// tenant lanes on — over real PostgreSQL and Kafka with three tenants, the
// production builders (BuildThreatIntel, BuildEnrichment), the production
// result fan with the IOC sink, the real Python analyzer under the shipped Go
// bridge, the strict BGP incident consumer, and the public /v1 API with
// production sessions:
//
//  1. threat intel is fetched ONCE into one shared store — the mirror is
//     deleted right after that single refresh, so every later match can only
//     come from the shared copy — and both tenants see the same feed status;
//  2. matches are scoped per tenant: tenant A's two results (a Feodo C2 IP and
//     an address inside a Spamhaus DROP block) become A's detections, tenant
//     B's result on the same C2 IP becomes B's own detection on its own
//     incident, and a tenant that touched nothing malicious sees none;
//  3. open-data enrichment is shared context: both tenants get the identical
//     answer for the same address;
//  4. BGP collector ingestion is per tenant: each tenant runs its own analyzer
//     on its own copy of the feed, publishing on its own lane, and sees only
//     its own monitored prefix; an event on the shared lane is refused by the
//     strict consumer and reaches no tenant.
func TestSharedFeedsIngestOnceAndBGPIngestsPerTenantRealStack(t *testing.T) {
	ctx := context.Background()
	python, err := exec.LookPath("python3")
	if err != nil {
		testsupport.SkipOrFatal(t, "python3 unavailable: %v", err)
	}
	brokers := testsupport.KafkaBrokers()
	if len(brokers) == 0 {
		testsupport.SkipOrFatal(t, "PROBECTL_TEST_KAFKA not set — the ingest-scope receipt needs a real bus")
	}
	db := changeDB(t) // real PostgreSQL, migrated
	b, err := bus.NewKafka(brokers, 0, kgo.AllowAutoTopicCreation())
	if err != nil {
		t.Fatalf("kafka: %v", err)
	}
	t.Cleanup(func() { _ = b.Close() })
	runCtx, cancel := context.WithCancel(ctx)
	t.Cleanup(cancel)
	log := quietLog()
	tenantA, tenantB, tenantC := freshTenant(t, db, "scope-a"), freshTenant(t, db, "scope-b"), freshTenant(t, db, "scope-c")

	// 1. One mirror, one store, one refresh. The C2 IP and the DROP block sit
	// in documentation ranges no other receipt uses.
	const c2IP, dropBlock, dropHost = "203.0.113.66", "198.18.0.0/15", "198.18.4.4"
	mirror := t.TempDir()
	fcWrite(t, mirror, "feodo_tracker", []byte(c2IP+"\n"))
	fcWrite(t, mirror, "spamhaus_drop", []byte(dropBlock+" ; SBL-scope\n"))
	asnFile := fcWrite(t, t.TempDir(), "asn.csv",
		[]byte("network,autonomous_system_number,autonomous_system_organization\n203.0.113.0/24,64666,SCOPE-TEST-NET\n"))
	cfg := &config.Config{
		HSTSEnabled: true, HSTSMaxAge: time.Hour,
		AuthMode: "session", SessionTTL: time.Hour, SessionHMACKey: fcRandom(t),
		ThreatIntelEnabled: true, ThreatIntelRefresh: time.Hour,
		ThreatIntelFeeds: []string{"feodo_tracker", "spamhaus_drop"}, ThreatIntelMirror: "file://" + mirror,
		FlowEnrichASNFile: asnFile,
	}
	iocs, refresher, ok := BuildThreatIntel(cfg, log)
	if !ok {
		t.Fatal("threat intel did not build")
	}
	refresher.Refresh(ctx)
	if iocs.Count() != 2 {
		t.Fatalf("shared IOC store holds %d indicators after the one refresh, want 2", iocs.Count())
	}
	if err := os.RemoveAll(mirror); err != nil {
		t.Fatal(err)
	}
	enricher, ok := BuildEnrichment(cfg, log)
	if !ok {
		t.Fatal("open-data enrichment did not build")
	}
	srv := New(cfg, log, db, db.Pool(), nil, nil).
		WithTenantStatus(NewTenantStatusCache(db.Pool(), 0)).
		WithOpenDataStatus(enricher, iocs, refresher)
	h := srv.Handler()
	alice, carol, dave := sessionAdmin(t, db, srv, h, tenantA, "alice"), sessionAdmin(t, db, srv, h, tenantB, "carol"), sessionAdmin(t, db, srv, h, tenantC, "dave")

	// The production result fan with the IOC sink, writing tenant incidents.
	corr := BuildCorrelator(db.Pool(), 10*time.Minute, log)
	fan := NewResultFan(b, log, ResultSink{Name: "threat-intel-ip", Fn: NewIOCConsumer(b, corr, iocs, log).SinkResult}).
		WithGroup("ingest-scope-proof")
	go func() { _ = fan.Run(runCtx) }()

	// 2. Results keyed exactly as the agent transport keys them.
	for _, r := range []struct{ tenant, target string }{
		{tenantA, c2IP + ":443"}, {tenantA, dropHost + ":443"}, {tenantB, c2IP + ":443"}, {tenantC, "192.0.2.200:443"},
	} {
		payload, err := proto.Marshal(&resultv1.Result{TenantId: r.tenant, AgentId: "scope-agent", CanaryType: "tcp",
			ServerAddress: r.target, Success: true, StartTimeUnixNano: time.Now().UnixNano()})
		if err != nil {
			t.Fatal(err)
		}
		if err := b.Publish(ctx, bus.NetworkResultsTopic, bus.TenantKey(r.tenant, "scope-agent"), payload); err != nil {
			t.Fatalf("publish result: %v", err)
		}
	}
	detA := awaitDetections(t, alice, 2)
	detB := awaitDetections(t, carol, 1)
	if got := detectionEntities(detA); !got[c2IP] || !got[dropHost] {
		t.Fatalf("tenant A detections = %+v, want the C2 IP and the DROP host", detA)
	}
	if detB[0].Entity != c2IP || detB[0].Source != "feodo_tracker" {
		t.Fatalf("tenant B detection = %+v, want its own C2 match", detB[0])
	}
	for _, d := range detA {
		if d.Entity == c2IP && d.IncidentID == detB[0].IncidentID {
			t.Fatalf("tenants A and B share incident %s for the same indicator", d.IncidentID)
		}
	}
	time.Sleep(2 * time.Second) // B and C would have gained anything misrouted by now
	if n := len(scopeDetections(t, carol)); n != 1 {
		t.Fatalf("tenant B has %d detections, want only its own one", n)
	}
	if n := len(scopeDetections(t, dave)); n != 0 {
		t.Fatalf("tenant C touched nothing malicious but has %d detections", n)
	}

	// Feed status and enrichment: shared context, identical for every tenant.
	statusA, statusB := scopeIOCCount(t, alice), scopeIOCCount(t, carol)
	if statusA != 2 || statusB != 2 {
		t.Fatalf("intel status ioc_count A=%d B=%d, want the one shared store (2) for both", statusA, statusB)
	}
	enrichA, enrichB := alice.text(t, "/v1/opendata/enrichment?ip="+c2IP), carol.text(t, "/v1/opendata/enrichment?ip="+c2IP)
	if enrichA != enrichB || !strings.Contains(enrichA, "64666") {
		t.Fatalf("enrichment differs per tenant or misses the shared ASN:\nA %s\nB %s", enrichA, enrichB)
	}

	// 4. BGP: per-tenant analyzers on per-tenant lanes, strict consumer.
	lanes := map[string]string{}
	var laneTopics []string
	for _, tenant := range []string{tenantA, tenantB, tenantC} {
		ns, err := store.NewTenants(db.Pool()).BusNamespace(ctx, tenant)
		if err != nil {
			t.Fatal(err)
		}
		lanes[ns] = tenant
		topic, err := bus.TopicFor(ns, bus.BGPEventsTopic)
		if err != nil {
			t.Fatal(err)
		}
		laneTopics = append(laneTopics, topic)
	}
	if _, err := b.EnsureTopics(ctx, laneTopics, 1, -1); err != nil {
		t.Fatalf("create tenant lanes: %v", err)
	}
	consumer := NewBGPIncidentConsumer(b, corr, log).WithNamespaceTenants(lanes).WithStrictTenantLanes(true)
	go func() { _ = consumer.Run(runCtx) }()

	// What both BGP producers used to do: an event on the shared lane.
	if err := bgp.PublishEvent(ctx, b, bgp.Event{TenantID: tenantA, EventType: "possible_hijack", Severity: "critical",
		Confidence: 0.9, Prefix: "203.0.113.0/24", NewOriginASN: 64999, DetectedAtUnixNano: time.Now().UnixNano()}); err != nil {
		t.Fatalf("publish shared-lane event: %v", err)
	}

	replay := fcWrite(t, t.TempDir(), "ris.jsonl", []byte(
		risUpdate("192.0.2.0/24", 65551)+"\n"+risUpdate("198.51.100.0/24", 65552)+"\n"))
	nsOf := func(tenant string) string {
		for ns, id := range lanes {
			if id == tenant {
				return ns
			}
		}
		t.Fatalf("no lane for %s", tenant)
		return ""
	}
	runTenantAnalyzer(t, b, python, tenantA, nsOf(tenantA), "192.0.2.0/24", 64496, replay)
	runTenantAnalyzer(t, b, python, tenantB, nsOf(tenantB), "198.51.100.0/24", 64497, replay)
	if err := b.Flush(ctx); err != nil {
		t.Fatalf("flush analyzer events: %v", err)
	}
	awaitBGPPrefix(t, alice, "192.0.2.0/24")
	awaitBGPPrefix(t, carol, "198.51.100.0/24")
	time.Sleep(3 * time.Second) // the shared-lane and cross-tenant events would have landed by now
	if events := alice.text(t, "/v1/bgp/events?limit=100"); strings.Contains(events, "198.51.100.0/24") || strings.Contains(events, "203.0.113.0/24") {
		t.Fatalf("tenant A sees another tenant's route or a shared-lane event: %s", events)
	}
	if events := carol.text(t, "/v1/bgp/events?limit=100"); strings.Contains(events, "192.0.2.0/24") {
		t.Fatalf("tenant B sees tenant A's monitored prefix: %s", events)
	}
	if events := dave.text(t, "/v1/bgp/events?limit=100"); strings.Contains(events, "/24") {
		t.Fatalf("tenant C runs no analyzer but has BGP events: %s", events)
	}
}

// runTenantAnalyzer runs one tenant's own analyzer (the shipped Go supervisor
// around the Python analyzer) over its own copy of the feed, on its lane.
func runTenantAnalyzer(t *testing.T, b bus.Bus, python, tenant, namespace, prefix string, expectedOrigin int, replay string) {
	t.Helper()
	repoRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	config, err := json.Marshal(map[string]any{
		"tenant_id": tenant, "collector": "rrc00",
		"monitored_prefixes": []map[string]any{{"prefix": prefix, "expected_origins": []int{expectedOrigin}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	configFile := fcWrite(t, t.TempDir(), "analyzer.json", config)
	runner, err := bgp.NewAnalyzerRunner(b, bgp.AnalyzerProcess{
		TenantID: tenant, BusNamespace: namespace, Executable: python,
		Args: []string{"-m", "probectl_analyzer", "--config", configFile, "--replay", replay},
		Env:  append(os.Environ(), "PYTHONPATH="+filepath.Join(repoRoot, "analyzer"), "PYTHONUNBUFFERED=1"),
	}, quietLog())
	if err != nil {
		t.Fatal(err)
	}
	if err := runner.Run(context.Background()); err != nil {
		t.Fatalf("tenant %s analyzer: %v", tenant, err)
	}
}

// risUpdate is one RIS Live UPDATE announcing prefix from origin.
func risUpdate(prefix string, origin int) string {
	return fmt.Sprintf(`{"type":"ris_message","data":{"type":"UPDATE","timestamp":%d.0,"peer":"192.0.2.1","peer_asn":"64511","host":"rrc00",`+
		`"path":[64511,64500,%d],"announcements":[{"next_hop":"192.0.2.1","prefixes":["%s"]}],"withdrawals":[]}}`,
		time.Now().Unix(), origin, prefix)
}

type scopeDetection struct {
	Entity     string `json:"entity"`
	Source     string `json:"source"`
	IncidentID string `json:"incident_id"`
}

func scopeDetections(t *testing.T, u *fcUser) []scopeDetection {
	t.Helper()
	var out struct {
		Items []scopeDetection `json:"items"`
	}
	fcJSON(t, []byte(u.text(t, "/v1/threat/detections")), &out)
	return out.Items
}

func awaitDetections(t *testing.T, u *fcUser, want int) []scopeDetection {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		if items := scopeDetections(t, u); len(items) >= want {
			return items
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatalf("tenant never reached %d threat detections (has %+v)", want, scopeDetections(t, u))
	return nil
}

func detectionEntities(items []scopeDetection) map[string]bool {
	out := map[string]bool{}
	for _, d := range items {
		out[d.Entity] = true
	}
	return out
}

func scopeIOCCount(t *testing.T, u *fcUser) int {
	t.Helper()
	var out struct {
		IOCCount int `json:"ioc_count"`
	}
	fcJSON(t, []byte(u.text(t, "/v1/threat/intel/status")), &out)
	return out.IOCCount
}

func awaitBGPPrefix(t *testing.T, u *fcUser, prefix string) {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(u.text(t, "/v1/bgp/events?limit=100"), prefix) {
			return
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatalf("BGP events for %s never reached the tenant", prefix)
}
