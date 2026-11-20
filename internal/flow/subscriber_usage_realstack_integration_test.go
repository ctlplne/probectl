// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package flow_test

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/agent"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/enroll"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/testspec"
	"github.com/ctlplne/probectl/internal/testsupport"
	"github.com/ctlplne/probectl/internal/testsupport/shipped"
)

type subscriberLane struct {
	*nativeLane
	tagID, contextID, alphaAssignment string
	alphaTarget                       string
	probeTests                        [2]store.Test
	evidence                          *agent.EvidenceClient
}

func TestShippedSubscriberUsageReconcilesOverlappingTenantAndSubscriberScopes(t *testing.T) {
	stack := shipped.Start(t, shipped.Options{Name: "subscriberusage", TenantBand: 3})
	operator := stack.OnboardOperator(t, "root@msp-subscriber-usage.example")
	run := strconv.FormatInt(time.Now().UnixNano(), 36)
	lanes := []subscriberLane{{nativeLane: &nativeLane{name: "red", octet: 184}}, {nativeLane: &nativeLane{name: "blue", octet: 184}}}
	for i := range lanes {
		lanes[i].provision(t, stack, operator, run)
		lanes[i].configureSubscribers(t, stack)
		lanes[i].configureSubscriberProbes(t, stack)
	}
	from := time.Now().UTC().Truncate(time.Millisecond)
	time.Sleep(5 * time.Millisecond)
	for i, lane := range lanes {
		lane.sendSubscriberRecords(t, uint64(i+1))
		for j, probe := range lane.probeTests {
			lane.recordSubscriberProbe(t, probe, uint64((i+1)*1000+j*100))
		}
	}
	time.Sleep(5 * time.Millisecond)
	to := time.Now().UTC()
	var refs [2]flow.SavedQueryView
	for i, lane := range lanes {
		want := uint64(i + 1)
		refs[i] = lane.waitAndSaveSubscriberView(t, stack, from, to, want*3000)
		assertSubscriberLaneUsage(t, stack, lane, refs[i], 0, want*1000, want*40, want*1000)
		assertSubscriberLaneUsage(t, stack, lane, refs[i], 1, want*2000, want*60, want*1000+100)
		assertSubscriberExchange(t, stack, lane, refs[i], want*1000, want*40)
	}
	for i, lane := range lanes {
		other := lanes[1-i]
		foreign := struct {
			flow.SubscriberUsageRequest
			Exchange flow.SubscriberExchangeRequest `json:"exchange"`
		}{SubscriberUsageRequest: flow.SubscriberUsageRequest{Version: refs[1-i].Version, TagID: other.tagID, TagKey: "subscriber", Subscriber: "alpha", IncludeLatency: true},
			Exchange: flow.SubscriberExchangeRequest{Target: "uisp", ExternalID: "foreign-export"}}
		lane.do(t, stack, http.MethodPost, subscriberUsagePath(refs[1-i].ID), foreign, nil, http.StatusNotFound)
		foreign.Version = refs[i].Version
		lane.do(t, stack, http.MethodPost, subscriberUsagePath(refs[i].ID), foreign, nil, http.StatusNotFound)
	}
	proveSubscriberUsageConsole(t, stack, lanes[0], refs[0])
	lanes[0].do(t, stack, http.MethodPut, "/v1/entity-contexts/"+lanes[0].contextID+"/tag-assignments/"+lanes[0].alphaAssignment,
		map[string]string{"tag_id": lanes[0].tagID, "target_kind": "prefix", "target_id": lanes[0].alphaTarget, "value": "next-subscriber"}, nil, http.StatusOK)
	lanes[0].do(t, stack, http.MethodPost, subscriberUsagePath(refs[0].ID), flow.SubscriberUsageRequest{
		Version: refs[0].Version, TagID: lanes[0].tagID, TagKey: "subscriber", Subscriber: "next-subscriber",
	}, nil, http.StatusConflict)
}

func assertSubscriberExchange(t *testing.T, st *shipped.Stack, lane subscriberLane, view flow.SavedQueryView, bytes, packets uint64) {
	t.Helper()
	params := struct {
		flow.SubscriberUsageRequest
		Exchange flow.SubscriberExchangeRequest `json:"exchange"`
	}{SubscriberUsageRequest: flow.SubscriberUsageRequest{Version: view.Version, TagID: lane.tagID, TagKey: "subscriber", Subscriber: "alpha"}}
	externalID := "vendor-" + lane.name + "-account"
	for _, vendor := range []struct{ target, column string }{{"splynx", "service_id"}, {"sonar", "account_id"}, {"uisp", "subscriber_id"}} {
		params.Exchange = flow.SubscriberExchangeRequest{Target: vendor.target, ExternalID: externalID}
		var response struct {
			flow.SubscriberUsageReport
			Exchange flow.SubscriberExchangePreview `json:"exchange"`
		}
		lane.do(t, st, http.MethodPost, subscriberUsagePath(view.ID), params, &response, http.StatusOK)
		if response.Exchange.Target != vendor.target || !response.Exchange.Preview {
			t.Fatal("the exact vendor selection lost its preview state", response.Exchange)
		}
		rows, err := csv.NewReader(strings.NewReader(response.Exchange.CSV)).ReadAll()
		if err != nil || len(rows) != 2 || len(rows[1]) != 13 || rows[0][0] != vendor.column || rows[1][0] != externalID ||
			rows[1][6] != strconv.FormatUint(bytes, 10) || rows[1][10] != strconv.FormatUint(packets, 10) ||
			rows[1][11] != response.ViewVersion || rows[1][12] != response.TagRevision {
			t.Fatal("exchange output failed to reconcile exact scoped counters and provenance", rows, err)
		}
		if vendor.target == "splynx" {
			var fromCLI struct {
				Exchange flow.SubscriberExchangePreview `json:"exchange"`
			}
			st.MustCLI(t, map[string]string{"PROBECTL_API_TOKEN": lane.apiToken}, &fromCLI, "explorer", "subscriber-usage", view.ID, "--body-file", st.SecretFile(t, params))
			if fromCLI.Exchange != response.Exchange {
				t.Fatal("native CLI did not preserve the received exact export")
			}
		}
	}
	params.Exchange.ExternalID = "=1+1"
	lane.do(t, st, http.MethodPost, subscriberUsagePath(view.ID), params, nil, http.StatusUnprocessableEntity)
}

func (l *subscriberLane) configureSubscriberProbes(t *testing.T, st *shipped.Stack) {
	t.Helper()
	name := "subscriber-icmp-" + l.name
	csr, key, err := crypto.CreateCSR(name)
	if err != nil {
		t.Fatal(err)
	}
	var token struct{ Token string }
	l.do(t, st, http.MethodPost, "/v1/agents/enroll-tokens", map[string]any{
		"agent_id": l.agent, "name": name, "ttl_seconds": 600,
	}, &token, http.StatusCreated)
	var issued enroll.CollectorIdentity
	l.do(t, st, http.MethodPost, "/v1/collectors/register", map[string]string{
		"token": token.Token, "plane": "entity", "hostname": name, "csr_pem": string(csr),
	}, &issued, http.StatusCreated)
	if issued.AgentID != l.agent || issued.TenantID != l.id || issued.SVID == nil || issued.SVID.SPIFFEID != crypto.EntitySPIFFEID(l.id, l.agent) {
		t.Fatal("subscriber measurement identity did not bind to the original tenant and agent")
	}
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	for path, pem := range map[string][]byte{certPath: []byte(issued.SVID.CertPEM), keyPath: key} {
		if err := os.WriteFile(path, pem, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	l.evidence, err = agent.DialEntityEvidence(st.AgentAddr, certPath, keyPath, st.CAFile, "localhost")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.evidence.Close() })
	var anchor entity.Record
	l.do(t, st, http.MethodPost, "/v1/entities", map[string]string{
		"context_id": l.contextID, "kind": "device", "label": "Subscriber test vantage",
	}, &anchor, http.StatusCreated)
	for i, key := range []string{"alpha", "beta"} {
		probe := &l.probeTests[i]
		l.do(t, st, http.MethodPost, "/v1/tests", map[string]any{
			"name": key + " latency", "type": "icmp", "target": "192.0.2.184", "interval_seconds": 60,
			"timeout_seconds": 5, "params": map[string]string{"count": "3"},
		}, probe, http.StatusCreated)
		l.do(t, st, http.MethodPut, "/v1/tests/"+probe.ID+"/entity-context", map[string]string{
			"context_id": l.contextID,
		}, nil, http.StatusOK)
		l.do(t, st, http.MethodPut, "/v1/entity-source-contexts", map[string]string{
			"context_id": l.contextID, "agent_id": l.agent, "source_kind": "path_agent", "source_ref": probe.ID, "anchor_entity_id": anchor.ID,
		}, nil, http.StatusOK)
		l.do(t, st, http.MethodPost, "/v1/entity-contexts/"+l.contextID+"/tag-assignments", map[string]string{
			"tag_id": l.tagID, "target_kind": "test", "target_id": probe.ID, "value": key,
		}, nil, http.StatusCreated)
	}
}

func (l *subscriberLane) recordSubscriberProbe(t *testing.T, probe store.Test, base uint64) {
	t.Helper()
	digest, err := testspec.DefinitionHash(testspec.ExecutableDefinition{
		ID: probe.ID, Type: probe.Type, Target: probe.Target, IntervalSeconds: probe.IntervalSeconds, TimeoutSeconds: probe.TimeoutSeconds, Params: probe.Params,
	})
	if err != nil {
		t.Fatal(err)
	}
	id, err := crypto.UUIDv4()
	if err != nil {
		t.Fatal(err)
	}
	at := time.Now().UTC()
	observation := entity.Observation{ID: id, Source: entity.SourceKey{AgentID: l.agent, Kind: entity.PathAgent, SourceRef: probe.ID},
		Alias: entity.AliasKey{Kind: entity.AddressAlias, Value: probe.Target}, SourceRef: "icmp:configured-test", ObservedAt: at,
		ICMP: &entity.ICMPMeasurement{Version: 3, DefinitionHash: digest, StartedAt: at, CompletedAt: at,
			Requested: 3, Attempted: 3, Transmitted: 3, Replies: 3, ReadComplete: true, Responders: []string{probe.Target},
			RoundTrips: &entity.ICMPRoundTrips{Nanos: []uint64{base, base + 1, base + 1}, ExecutionNanos: 3*base + 2},
		},
	}
	// Submit synthetic measurements over the production evidence transport.
	// No ICMP packets go to the documentation address used as the target.
	accepted, unresolved, err := l.evidence.Submit(t.Context(), []entity.Observation{observation})
	if err != nil || accepted != 1 || unresolved != 0 {
		t.Fatal("typed original round trips not retained", accepted, unresolved, err)
	}
}

func (l *subscriberLane) configureSubscribers(t *testing.T, st *shipped.Stack) {
	t.Helper()
	var context entity.ContextRecord
	l.do(t, st, http.MethodPost, "/v1/entity-contexts", map[string]string{"site_label": "Subscriber lab", "vrf_label": "Subscriber service"}, &context, http.StatusCreated)
	l.contextID = context.ContextID
	l.do(t, st, http.MethodPut, "/v1/entity-source-contexts", map[string]string{
		"context_id": context.ContextID, "agent_id": l.agent, "source_kind": "flow_exporter", "source_ref": "127.0.0.1",
	}, nil, http.StatusOK)
	var tag struct{ ID string }
	l.do(t, st, http.MethodPost, "/v1/tags", map[string]string{"key": "subscriber"}, &tag, http.StatusCreated)
	l.tagID = tag.ID
	for i, key := range []string{"alpha", "beta"} {
		var scope entity.Record
		l.do(t, st, http.MethodPost, "/v1/entities", map[string]string{
			"context_id": context.ContextID, "kind": "prefix", "label": key, "network_prefix": fmt.Sprintf("10.%d.%d.0/24", l.octet, i+1),
		}, &scope, http.StatusCreated)
		var assignment store.TagAssignmentRecord
		l.do(t, st, http.MethodPost, "/v1/entity-contexts/"+context.ContextID+"/tag-assignments", map[string]string{
			"tag_id": tag.ID, "target_kind": "prefix", "target_id": scope.ID, "value": key,
		}, &assignment, http.StatusCreated)
		if i == 0 {
			l.alphaAssignment, l.alphaTarget = assignment.ID, scope.ID
		}
	}
}

func (l *subscriberLane) sendSubscriberRecords(t *testing.T, multiplier uint64) {
	t.Helper()
	export, err := net.Dial("udp", l.listeners["IPFIX"])
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = export.Close() }()
	for i, amount := range []uint64{100, 200} {
		record := controlledTrafficIPFIX(t, l.octet, i, 0, 901+i, time.Now().UTC(), trafficVector{transport: 6, port: 41000}, amount*multiplier, uint64(i*2+4)*multiplier)
		if n, err := export.Write(record); err != nil || n != len(record) {
			t.Fatal("the synthetic subscriber observation did not reach the loopback exporter", err)
		}
	}
}

func (l *subscriberLane) waitAndSaveSubscriberView(t *testing.T, st *shipped.Stack, from, to time.Time, bytes uint64) flow.SavedQueryView {
	t.Helper()
	plan := nativeGoldenPlan(l.octet, to, []string{"dst_addr"})
	plan.From, plan.To, plan.DataSeries = from, to, "raw"
	shipped.Await(t, "exact subscriber observations have reached the tenant store", 30*time.Second, func() bool {
		code, raw := st.Do(t, l.cookie, http.MethodPost, "/v1/explorer/query", map[string]any{"source": "flow", "flow": plan})
		var found struct{ Flow flowstore.PlanResult }
		return code == http.StatusOK && json.Unmarshal(raw, &found) == nil && found.Flow.Totals["bytes:total"] == strconv.FormatUint(bytes, 10)
	})
	var saved flow.SavedQueryView
	l.do(t, st, http.MethodPost, "/v1/explorer/flow-views", map[string]any{"definition": flow.QueryViewDefinition{
		Name: "Subscriber lab usage", Visibility: "private", Time: flow.QueryViewTime{Mode: "absolute"}, Plan: plan,
	}}, &saved, http.StatusCreated)
	return saved
}

func subscriberUsagePath(id string) string {
	return "/v1/explorer/flow-views/" + id + "/subscriber-usage"
}

func assertSubscriberLaneUsage(t *testing.T, st *shipped.Stack, lane subscriberLane, view flow.SavedQueryView, subscriber int, bytes, packets, roundTrip uint64) {
	t.Helper()
	value := []string{"alpha", "beta"}[subscriber]
	input := flow.SubscriberUsageRequest{Version: view.Version, TagID: lane.tagID, TagKey: "subscriber", Subscriber: value}
	var report flow.SubscriberUsageReport
	lane.do(t, st, http.MethodPost, subscriberUsagePath(view.ID), input, &report, http.StatusOK)
	want := flow.SubscriberTraffic{Bytes: strconv.FormatUint(bytes, 10), Packets: strconv.FormatUint(packets, 10)}
	if report.Subscriber != value || report.TagID != lane.tagID || report.Total != want || report.Download != want || report.Upload.Bytes != "0" || report.LatencyIncluded || len(report.Latency) > 0 ||
		len(report.TopServices) != 1 || report.TopServices[0].Status != "unknown" || report.TopServices[0].Traffic != want {
		t.Fatalf("subscriber usage did not reconcile the original scoped counters: %+v", report)
	}
	input.IncludeLatency = true
	lane.do(t, st, http.MethodPost, subscriberUsagePath(view.ID), input, &report, http.StatusOK)
	if !report.LatencyIncluded || len(report.Latency) != 1 {
		t.Fatalf("expected one original RTT source for the subscriber: %+v", report.Latency)
	}
	latency := report.Latency[0]
	if latency.TestID != lane.probeTests[subscriber].ID || latency.AgentID != lane.agent || latency.ContextID != lane.contextID ||
		latency.Target != "192.0.2.184" || latency.Coverage != "observed_original_round_trips_only" || latency.Samples != "3" ||
		latency.SumNanos != strconv.FormatUint(3*roundTrip+2, 10) || latency.MeanNanos != latency.SumNanos+"/3" ||
		latency.MinimumNanos != strconv.FormatUint(roundTrip, 10) || latency.MaximumNanos != strconv.FormatUint(roundTrip+1, 10) {
		t.Fatal("original round trips lost precision or subscriber/tenant isolation", latency)
	}
	var fromCLI flow.SubscriberUsageReport
	st.MustCLI(t, map[string]string{"PROBECTL_API_TOKEN": lane.apiToken}, &fromCLI, "explorer", "subscriber-usage", view.ID, "--body-file", st.SecretFile(t, input))
	if fromCLI.Total != want || fromCLI.TagRevision != report.TagRevision || len(fromCLI.Latency) != 1 || fromCLI.Latency[0] != latency {
		t.Fatal("CLI did not preserve the exact subscriber report")
	}
}

func proveSubscriberUsageConsole(t *testing.T, st *shipped.Stack, lane subscriberLane, view flow.SavedQueryView) {
	t.Helper()
	for _, theme := range []string{"light", "dark"} {
		export := filepath.Join(t.TempDir(), "subscriber-usage-preview.csv")
		testsupport.RenderUI(t, testsupport.RenderSpec{
			URL: st.BaseURL + "/ui/explore?flow_view=" + view.ID, TrustCertFiles: st.TrustCerts(), CAFile: st.CAFile, Accessibility: true, Theme: theme,
			Cookies: []testsupport.RenderCookie{{Name: auth.SessionCookie, Value: lane.cookie}}, Expect: []string{"Subscriber usage"},
			Steps: []testsupport.RenderStep{
				{Click: "Open subscriber usage", Expect: []string{"Subscriber prefix tag"}},
				{Select: "label:text-is('Subscriber prefix tag') + div select", Value: lane.tagID},
				{Fill: "label:text-is('Subscriber tag value') + div input", Value: "alpha"},
				{Click: "Include original ICMP latency", Role: "checkbox"},
				{Select: "label:text-is('ISP exchange preview') + div select", Value: "uisp"},
				{Fill: "label:text-is('External service or account ID') + div input", Value: "carrier-local-alpha"},
				{Click: "Run subscriber report", Expect: []string{"Observed usage for alpha", "1000 bytes", "Remote services", "Observed ICMP latency", "3002/3"}, Absent: []string{"beta latency", "6002/3"}},
				{Click: "Download exchange CSV", Download: export},
			},
		})
		file, err := os.Open(export)
		if err != nil {
			t.Fatal(err)
		}
		rows, err := csv.NewReader(file).ReadAll()
		_ = file.Close()
		if err != nil || len(rows) != 2 || len(rows[1]) != 13 || rows[0][0] != "subscriber_id" || rows[1][0] != "carrier-local-alpha" || rows[1][6] != "1000" {
			t.Fatal("the downloaded preview lost its selected identifier or exact counters", rows, err)
		}
	}
}
