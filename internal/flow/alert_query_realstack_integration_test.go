// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package flow_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/alert"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/incident"
	"github.com/ctlplne/probectl/internal/testsupport"
	"github.com/ctlplne/probectl/internal/testsupport/shipped"
)

const nativeAlertSource = "10.203.99.1"

type nativeQueryAlert struct {
	lane  *nativeLane
	view  flow.SavedQueryView
	rule  alert.Rule
	group string
	token string
	high  uint32
}

// This extends the existing real collector/Dex/PG/ClickHouse receipt. Both
// tenants deliberately reuse an address and exporter, with different counters.
// It does not claim hardware exporters or the separate production broker TLS
// release-image proof; those standing requirements remain independently owed.
func proveNativeSavedQueryAlerts(t *testing.T, st *shipped.Stack, addr string, lanes []*nativeLane) {
	t.Helper()
	if len(lanes) != 2 {
		t.Fatal("original source proof requires its two real tenant lanes")
	}
	proofs := make([]nativeQueryAlert, len(lanes))
	for i, lane := range lanes {
		p := &proofs[i]
		p.lane = lane
		p.high = []uint32{1000, 10000}[i]
		plan := nativeGoldenPlan(lane.octet, time.Now().UTC(), []string{"src_addr"})
		plan.Filter = &flow.QueryFilterGroup{Conditions: []flow.QueryPredicate{{Field: "src_addr", Op: flow.QueryCIDR, Values: []string{nativeAlertSource + "/32"}}}}
		plan.Metrics = plan.Metrics[:1]
		plan.DataSeries = "raw"
		lane.do(t, st, http.MethodPost, "/v1/explorer/flow-views", map[string]any{"definition": flow.QueryViewDefinition{Name: "Query alert " + lane.name, Visibility: "private", Time: flow.QueryViewTime{Mode: "lookback", LookbackSeconds: 60}, Plan: plan}}, &p.view, http.StatusCreated)
		var me struct {
			UserID string `json:"user_id"`
		}
		lane.do(t, st, http.MethodGet, "/v1/me", nil, &me, http.StatusOK)
		issued := strings.Split(strings.TrimSpace(st.Subcommand(t, "mcp-token", "--tenant", lane.id, "--user", me.UserID, "--scope", "read,write,ai.query", "--expires-days", "1")), "\n")
		p.token = issued[len(issued)-1]
		input := alert.QueryRuleInput{Name: "Saved query " + lane.name, QuerySource: alert.QuerySourceInput{ViewID: p.view.ID, ViewVersion: p.view.Version, EverySeconds: 1, Condition: alert.QueryCondition{Mode: "threshold", Metric: "bytes:total", Comparison: alert.GT, Threshold: "500"}}}
		if i == 0 {
			lane.do(t, st, http.MethodPost, "/v1/alerts", input, &p.rule, http.StatusCreated)
		} else {
			p.call(t, st, addr, "alert_query_create", input, &p.rule, false)
		}
		if p.rule.ID == "" || p.rule.Metric != alert.QueryMetric {
			t.Fatal("public query creation did not return an admitted canonical rule")
		}
		t.Cleanup(func() {
			code, _ := st.Do(t, lane.cookie, http.MethodDelete, "/v1/alerts/"+p.rule.ID, nil)
			if code != http.StatusNoContent && code != http.StatusNotFound {
				t.Error("owned query alert cleanup refused", code)
			}
		})
		lane.sendAlertWire(t, p.high, 1)
	}
	// Wait for actual durable flow evaluation, not elapsed sleep as proof.
	deadline := time.Now().Add(50 * time.Second)
	for time.Now().Before(deadline) {
		ready := true
		for i := range proofs {
			p := &proofs[i]
			var active struct {
				Items   []alert.ActiveAlert `json:"items"`
				Running bool                `json:"evaluator_running"`
			}
			p.lane.do(t, st, http.MethodGet, "/v1/alerts/active", nil, &active, http.StatusOK)
			for _, item := range active.Items {
				if item.RuleID == p.rule.ID {
					p.group = item.Labels["query_group"]
				}
			}
			ready = ready && active.Running && alert.ValidQueryGroupKey(p.group)
		}
		if ready {
			break
		}
		time.Sleep(300 * time.Millisecond)
	}
	for i := range proofs {
		p := &proofs[i]
		if !alert.ValidQueryGroupKey(p.group) {
			t.Fatal("original wire threshold never fired for tenant", p.lane.name)
		}
		var inspected alert.QueryGroupInspection
		p.lane.do(t, st, http.MethodGet, "/v1/alerts/rules/"+p.rule.ID+"/query-group?group="+p.group, nil, &inspected, http.StatusOK)
		if !inspected.Present || !inspected.ConditionMet || inspected.Dimensions["src_addr"] != nativeAlertSource || inspected.ExactValue != strconv.FormatUint(uint64(p.high), 10) {
			t.Fatal("real current group lost original tenant wire counter", inspected)
		}
		var cli alert.QueryGroupInspection
		st.MustCLI(t, map[string]string{"PROBECTL_API_TOKEN": p.lane.apiToken}, &cli, "alert", "query-group", p.rule.ID, "--query", "group="+p.group)
		if cli.ExactValue != inspected.ExactValue || cli.GroupKey != p.group {
			t.Fatal("built CLI changed the actual query group")
		}
		p.call(t, st, addr, "alert_query_group_get", map[string]any{"rule_id": p.rule.ID, "group": p.group}, nil, false)
		other := &proofs[1-i]
		p.lane.do(t, st, http.MethodGet, "/v1/alerts/rules/"+other.rule.ID+"/query-source", nil, nil, http.StatusNotFound)
		p.call(t, st, addr, "alert_query_group_get", map[string]any{"rule_id": other.rule.ID, "group": other.group}, nil, true)
		if p.group == other.group {
			t.Fatal("overlapping address crossed the tenant/rule group domain")
		}
	}
	sequence := uint32(2)
	for i := range proofs {
		p, other := &proofs[i], &proofs[1-i]
		for _, theme := range []string{"light", "dark"} {
			for j := range proofs {
				proofs[j].lane.sendAlertWire(t, proofs[j].high, sequence)
			}
			sequence++
			testsupport.RenderUI(t, testsupport.RenderSpec{URL: st.BaseURL + "/ui/alerts", Cookies: []testsupport.RenderCookie{{Name: auth.SessionCookie, Value: p.lane.cookie}}, TrustCertFiles: st.TrustCerts(), CAFile: st.CAFile, Theme: theme, Accessibility: true, Expect: []string{p.rule.Name}, Absent: []string{other.rule.Name}, Steps: []testsupport.RenderStep{{Click: "Details", Expect: []string{"Current query group"}}, {Click: "Inspect current group", Expect: []string{nativeAlertSource, "Exact current value", "not a historical firing receipt"}}}})
		}
	}
	// Continued low traffic keeps the group present while every high input ages
	// out of the original 60-second window. Neither source rebinding nor empty
	// results are used to manufacture resolution.
	deadline = time.Now().Add(100 * time.Second)
	resolved := false
	for ; time.Now().Before(deadline); sequence++ {
		all := true
		for i := range proofs {
			p := &proofs[i]
			p.lane.sendAlertWire(t, 1, sequence)
			firing, cleared := p.transitions(t, st)
			if firing > 1 || cleared > 1 {
				t.Fatal("one original wire episode emitted duplicate transitions", p.lane.name, firing, cleared)
			}
			all = all && firing == 1 && cleared == 1
		}
		if all {
			resolved = true
			break
		}
		time.Sleep(time.Second)
	}
	if !resolved {
		t.Fatal("original high-to-low wire traffic did not resolve exactly once")
	}
	for i := range proofs {
		p := &proofs[i]
		firing, cleared := p.transitions(t, st)
		if firing != 1 || cleared != 1 {
			t.Fatal("original real episode transition count changed", firing, cleared)
		}
		incidentReady := false
		until := time.Now().Add(20 * time.Second)
		for time.Now().Before(until) {
			var page struct {
				Items   []incident.Incident `json:"items"`
				Running bool                `json:"correlation_running"`
			}
			p.lane.do(t, st, http.MethodGet, "/v1/incidents", nil, &page, http.StatusOK)
			found := []incident.Incident{}
			for _, item := range page.Items {
				if item.Target == "query:"+p.rule.ID+":"+p.group {
					found = append(found, item)
				}
			}
			if len(found) > 1 {
				t.Fatal("one original group split into multiple incidents", p.lane.name, len(found))
			}
			if page.Running && len(found) == 1 {
				var room incident.Incident
				p.lane.do(t, st, http.MethodGet, "/v1/incidents/"+found[0].ID, nil, &room, http.StatusOK)
				counts := map[string]int{}
				for _, signal := range room.Signals {
					if signal.Attributes["rule_id"] == p.rule.ID {
						counts[signal.Kind]++
					}
				}
				if room.SignalsTruncated || counts["alert.firing"] > 1 || counts["alert.resolved"] > 1 || room.SignalCount > 2 {
					t.Fatal("one normal incident lost coverage or duplicated an original signal", counts, room.SignalCount)
				}
				if counts["alert.firing"] == 1 && counts["alert.resolved"] == 1 && room.SignalCount == 2 {
					incidentReady = true
					break
				}
			}
			time.Sleep(200 * time.Millisecond)
		}
		if !incidentReady {
			t.Fatal("original fire/resolve did not publish to one normal owned incident", p.lane.name)
		}
		p.lane.do(t, st, http.MethodDelete, "/v1/alerts/"+p.rule.ID, nil, nil, http.StatusNoContent)
	}
	t.Log("real-integration: paired overlapping-address NetFlow5 through signed collector registration, mTLS evidence, existing development Kafka/Prometheus and tenant-bound ClickHouse/Postgres; REST/native creation, exact REST/CLI/current MCP groups, both-theme served AA, one fire/resolve and one normal incident. Production release transports/hardware remain separate.")
}

func (p *nativeQueryAlert) transitions(t *testing.T, st *shipped.Stack) (int, int) {
	t.Helper()
	var response alert.EvaluationsResult
	p.lane.do(t, st, http.MethodGet, "/v1/alerts/"+p.rule.ID+"/evaluations?limit=100", nil, &response, http.StatusOK)
	fired, resolved := 0, 0
	for _, receipt := range response.Items {
		switch receipt.State {
		case alert.EvaluationFiring:
			fired++
		case alert.EvaluationResolved:
			resolved++
		}
	}
	return fired, resolved
}

func (lane *nativeLane) sendAlertWire(t *testing.T, quantity, sequence uint32) {
	t.Helper()
	now := time.Now()
	seconds, nanos := now.Unix(), now.Nanosecond()
	if seconds < 0 || seconds > 4294967295 || nanos < 0 || nanos > 999999999 {
		t.Fatal("source fixture clock is outside the actual NetFlow5 wire representation")
	}
	packet := nativeWire(t, uint16(5), uint16(1), uint32(60000), uint32(seconds), uint32(nanos), sequence, uint8(0), uint8(0), uint16(0))
	packet = append(packet, nativeWire(t, [4]byte{10, 203, 99, 1}, [4]byte{198, 51, 100, 1}, [4]byte{}, uint16(1), uint16(2), uint32(1), quantity, uint32(59000), uint32(59900), uint16(41999), uint16(443), uint8(0), uint8(0x18), uint8(6), uint8(0), uint16(64512), uint16(64513), uint8(24), uint8(24), uint16(0))...)
	connection, err := net.Dial("udp", lane.listeners["NETFLOW"])
	if err != nil {
		t.Fatal(err)
	}
	n, err := connection.Write(packet)
	_ = connection.Close()
	if err != nil || n != len(packet) {
		t.Fatal("original query alert datagram failed")
	}
}

func (p *nativeQueryAlert) call(t *testing.T, st *shipped.Stack, addr, name string, args, out any, wantError bool) {
	t.Helper()
	body, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": map[string]any{"name": name, "arguments": args}})
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "https://"+addr+"/", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+p.token)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json, text/event-stream")
	request.Header.Set("MCP-Protocol-Version", "2026-07-28")
	request.Header.Set("Mcp-Method", "tools/call")
	request.Header.Set("Mcp-Name", name)
	response, err := st.Client().Do(request)
	if err != nil {
		t.Fatal("query alert native TLS call failed")
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, 4<<20))
	if err != nil || response.StatusCode != http.StatusOK {
		t.Fatal("query alert native response unavailable")
	}
	var result struct {
		Error  json.RawMessage `json:"error"`
		Result struct {
			IsError    bool            `json:"isError"`
			Structured json.RawMessage `json:"structuredContent"`
		} `json:"result"`
	}
	if json.Unmarshal(raw, &result) != nil || len(result.Error) != 0 || result.Result.IsError != wantError {
		t.Fatal("query alert native result did not match required authority", name, wantError)
	}
	if !wantError && out != nil {
		if err := json.Unmarshal(result.Result.Structured, out); err != nil {
			t.Fatal(fmt.Errorf("native query alert shape: %w", err))
		}
	}
}
