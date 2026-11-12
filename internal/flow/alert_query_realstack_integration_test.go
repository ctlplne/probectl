// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package flow_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/alert"
	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/incident"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport"
	"github.com/ctlplne/probectl/internal/testsupport/shipped"
)

const nativeAlertSource = "10.203.99.1"

type nativeQueryAlert struct {
	lane         *nativeLane
	view         flow.SavedQueryView
	rule         alert.Rule
	group        string
	token        string
	high         uint32
	nextSequence uint32
	fingerprint  string
	since        time.Time
}

// This extends the existing real collector/Dex/PG/ClickHouse receipt. Both
// tenants deliberately reuse an address and exporter, with different counters.
// It does not claim hardware exporters or the separate production broker TLS
// release-image proof; those standing requirements remain independently owed.
func proveNativeSavedQueryAlerts(t *testing.T, st *shipped.Stack, addr string, lanes []*nativeLane) []nativeQueryAlert {
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
	for i := range proofs {
		proofs[i].nextSequence = sequence + 1
		proofs[i].fingerprint = ""
	}
	return proofs
}

func (p *nativeQueryAlert) transitions(t *testing.T, st *shipped.Stack) (int, int) {
	t.Helper()
	var response alert.EvaluationsResult
	path := "/v1/alerts/" + p.rule.ID + "/evaluations?limit=100"
	if p.fingerprint != "" {
		path += "&fingerprint=" + url.QueryEscape(p.fingerprint)
	}
	p.lane.do(t, st, http.MethodGet, path, nil, &response, http.StatusOK)
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
	lane.sendAlertASWire(t, quantity, sequence, 64512)
}

func (lane *nativeLane) sendAlertASWire(t *testing.T, quantity, sequence uint32, sourceASN uint16) {
	t.Helper()
	now := time.Now()
	seconds, nanos := now.Unix(), now.Nanosecond()
	if seconds < 0 || seconds > 4294967295 || nanos < 0 || nanos > 999999999 {
		t.Fatal("source fixture clock is outside the actual NetFlow5 wire representation")
	}
	packet := nativeWire(t, uint16(5), uint16(1), uint32(60000), uint32(seconds), uint32(nanos), sequence, uint8(0), uint8(0), uint16(0))
	packet = append(packet, nativeWire(t, [4]byte{10, 203, 99, 1}, [4]byte{198, 51, 100, 1}, [4]byte{}, uint16(1), uint16(2), uint32(1), quantity, uint32(59000), uint32(59900), uint16(41999), uint16(443), uint8(0), uint8(0x18), uint8(6), uint8(0), sourceASN, uint16(64513), uint8(24), uint8(24), uint16(0))...)
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

// The same actual source proves novelty, cadence preservation and top-set exit.
// The original new-AS row must still be retained at resolution, so expiry or
// source edits cannot substitute for eviction from the selected top ten.
func proveNativeSavedQueryNewGroups(t *testing.T, st *shipped.Stack, proofs []nativeQueryAlert, cleanup func(string, string)) {
	t.Helper()
	if len(proofs) != 2 {
		t.Fatal("original real threshold source prerequisites did not execute")
	}
	for i := range proofs {
		p := &proofs[i]
		p.group, p.fingerprint = "", ""
		p.lane.sendAlertASWire(t, 1, p.nextSequence, 64512)
		p.nextSequence++
		plan := nativeGoldenPlan(p.lane.octet, time.Now().UTC(), []string{"src_asn"})
		plan.Filter = &flow.QueryFilterGroup{Conditions: []flow.QueryPredicate{{Field: "src_addr", Op: flow.QueryCIDR, Values: []string{nativeAlertSource + "/32"}}}}
		plan.Metrics = plan.Metrics[:1]
		plan.DataSeries = "raw"
		plan.RowLimit, plan.PageSize = 10, 10
		p.lane.do(t, st, http.MethodPost, "/v1/explorer/flow-views", map[string]any{"definition": flow.QueryViewDefinition{Name: "New AS " + p.lane.name, Visibility: "private", Time: flow.QueryViewTime{Mode: "lookback", LookbackSeconds: 300}, Plan: plan}}, &p.view, http.StatusCreated)
		shipped.Await(t, "retained actual initial source AS before warming", 20*time.Second, func() bool {
			current, _, err := flow.MaterializeQueryView(p.view.Definition, time.Now().UTC())
			if err != nil {
				t.Fatal(err)
			}
			for _, row := range p.lane.query(t, st, current).Rows {
				if row.Group["src_asn"] == "64512" {
					return true
				}
			}
			return false
		})
		input := alert.QueryRuleInput{Name: "New selected AS " + p.lane.name, QuerySource: alert.QuerySourceInput{ViewID: p.view.ID, ViewVersion: p.view.Version, EverySeconds: 1, Condition: alert.QueryCondition{Mode: "new_group"}}}
		p.lane.do(t, st, http.MethodPost, "/v1/alerts", input, &p.rule, http.StatusCreated)
		cleanup(p.lane.cookie, p.rule.ID)
		var configured alert.QuerySourceState
		shipped.Await(t, "actual initial complete novelty baseline", 30*time.Second, func() bool {
			p.lane.do(t, st, http.MethodGet, "/v1/alerts/rules/"+p.rule.ID+"/query-source", nil, &configured, http.StatusOK)
			return configured.NextAt != nil
		})
		key := nativeASKey(t, p, "64512")
		var initial alert.QueryGroupInspection
		p.lane.do(t, st, http.MethodGet, "/v1/alerts/rules/"+p.rule.ID+"/query-group?group="+key, nil, &initial, http.StatusOK)
		if !initial.BaselineInitialized || !initial.Present || initial.ConditionMet || initial.Dimensions["src_asn"] != "64512" {
			t.Fatal("initial actual AS set did not warm without firing", initial)
		}
		fired, resolved := p.transitions(t, st)
		if fired != 0 || resolved != 0 {
			t.Fatal("initial source set emitted a novelty episode", fired, resolved)
		}
	}
	for i := range proofs {
		p, other := &proofs[i], &proofs[1-i]
		p.lane.do(t, st, http.MethodGet, "/v1/alerts/rules/"+other.rule.ID+"/query-source", nil, nil, http.StatusNotFound)
	}
	for i := range proofs {
		p := &proofs[i]
		var configured alert.QuerySourceState
		p.lane.sendAlertASWire(t, 1, p.nextSequence, 64513)
		p.nextSequence++
		shipped.Await(t, "one original new selected AS", 30*time.Second, func() bool {
			var active struct {
				Items []alert.ActiveAlert `json:"items"`
			}
			p.lane.do(t, st, http.MethodGet, "/v1/alerts/active", nil, &active, http.StatusOK)
			found := 0
			for _, item := range active.Items {
				if item.RuleID == p.rule.ID {
					found++
					p.group = item.Labels["query_group"]
					p.fingerprint = item.EvaluationFingerprint
					p.since = item.Since
				}
			}
			if found > 1 {
				t.Fatal("one new AS emitted multiple firing groups")
			}
			if found == 1 && (!alert.ValidQueryGroupKey(p.group) || p.fingerprint == "") {
				t.Fatal("actual novelty episode omitted its group or evaluation identity")
			}
			return found == 1
		})
		var entered alert.QueryGroupInspection
		p.lane.do(t, st, http.MethodGet, "/v1/alerts/rules/"+p.rule.ID+"/query-group?group="+p.group, nil, &entered, http.StatusOK)
		if !entered.Present || !entered.ConditionMet || entered.Dimensions["src_asn"] != "64513" {
			t.Fatal("new actual source AS did not become the firing group", entered)
		}
		if i == 0 {
			other := &proofs[1]
			var foreign alert.QueryGroupInspection
			other.lane.do(t, st, http.MethodGet, "/v1/alerts/rules/"+other.rule.ID+"/query-group?group="+nativeASKey(t, other, "64513"), nil, &foreign, http.StatusOK)
			if foreign.Present || foreign.ConditionMet || len(foreign.Dimensions) != 0 {
				t.Fatal("tenant A's new source AS entered tenant B's selected set", foreign)
			}
		}
		// Use the same configuring browser credential: this changes cadence only,
		// without authorizing a different owner/ceiling or redefining the query.
		cadence := alert.QuerySourceInput{ViewID: p.view.ID, ViewVersion: p.view.Version, EverySeconds: 2, Condition: alert.QueryCondition{Mode: "new_group"}}
		p.lane.do(t, st, http.MethodPut, "/v1/alerts/rules/"+p.rule.ID+"/query-source", cadence, &configured, http.StatusOK)
		p.lane.do(t, st, http.MethodGet, "/v1/alerts/rules/"+p.rule.ID+"/query-source", nil, &configured, http.StatusOK)
		if configured.NextAt == nil {
			t.Fatal("cadence-only edit discarded the actual baseline clock")
		}
		firstDue := *configured.NextAt
		shipped.Await(t, "scheduled read after a cadence-only edit", 10*time.Second, func() bool {
			p.lane.do(t, st, http.MethodGet, "/v1/alerts/rules/"+p.rule.ID+"/query-source", nil, &configured, http.StatusOK)
			return configured.NextAt != nil && configured.NextAt.After(firstDue)
		})
		p.lane.do(t, st, http.MethodGet, "/v1/alerts/rules/"+p.rule.ID+"/query-group?group="+p.group, nil, &entered, http.StatusOK)
		fired, resolved := p.transitions(t, st)
		if !entered.ConditionMet || fired != 1 || resolved != 0 {
			t.Fatal("cadence-only edit invented a novelty resolution or repeat", entered, fired, resolved)
		}
	}
}

func proveNativeSavedQueryNewGroupRestartAndExit(t *testing.T, st *shipped.Stack, proofs []nativeQueryAlert) {
	t.Helper()
	for i := range proofs {
		p := &proofs[i]
		shipped.Await(t, "restored actual still-firing novelty episode", 30*time.Second, func() bool {
			var active struct {
				Items []alert.ActiveAlert `json:"items"`
			}
			p.lane.do(t, st, http.MethodGet, "/v1/alerts/active", nil, &active, http.StatusOK)
			for _, item := range active.Items {
				if item.RuleID == p.rule.ID {
					if item.Labels["query_group"] != p.group || item.EvaluationFingerprint != p.fingerprint || !item.Since.Truncate(time.Microsecond).Equal(p.since.Truncate(time.Microsecond)) {
						t.Fatal("control restart changed the original actual novelty episode", item)
					}
					return true
				}
			}
			return false
		})
		fired, resolved := p.transitions(t, st)
		if fired != 1 || resolved != 0 {
			t.Fatal("control restart repeated or resolved the original actual novelty episode", fired, resolved)
		}
		for asn := uint16(64514); asn < 64524; asn++ {
			p.lane.sendAlertASWire(t, 100, p.nextSequence, asn)
			p.nextSequence++
		}
		shipped.Await(t, "original new AS leaves the complete selected top ten", 20*time.Second, func() bool {
			fired, resolved = p.transitions(t, st)
			if fired > 1 || resolved > 1 {
				t.Fatal("one original novelty episode repeated", fired, resolved)
			}
			return fired == 1 && resolved == 1
		})
		var entered alert.QueryGroupInspection
		p.lane.do(t, st, http.MethodGet, "/v1/alerts/rules/"+p.rule.ID+"/query-group?group="+p.group, nil, &entered, http.StatusOK)
		if entered.Present || entered.ConditionMet || len(entered.Dimensions) != 0 {
			t.Fatal("departed top-set identity leaked another group or remained firing", entered)
		}
		complete, _, err := flow.MaterializeQueryView(p.view.Definition, time.Now().UTC())
		if err != nil {
			t.Fatal(err)
		}
		complete.RowLimit, complete.PageSize = 20, 20
		retained := p.lane.query(t, st, complete)
		present := false
		for _, row := range retained.Rows {
			if row.Group["src_asn"] == "64513" {
				present = true
				if row.Metrics["bytes:total"] != "1" {
					t.Fatal("original new-AS wire input changed")
				}
			}
		}
		if !present {
			t.Fatal("expiry substituted for actual top-ten departure")
		}
	}
	for i := range proofs {
		p := &proofs[i]
		p.lane.do(t, st, http.MethodDelete, "/v1/alerts/"+p.rule.ID, nil, nil, http.StatusNoContent)
	}
	t.Log("real-integration: two tenant-bound raw senders warm one AS, add a new top-ten AS, preserve its episode across a cadence-only edit and actual control restart, then resolve once on complete top-ten eviction while the original row remains retained; no source edit or timeout manufactures clearance")
}

// The digest is only a lookup handle for independently known wire dimensions;
// the public reader still proves that this exact AS exists under current grants.
func nativeASKey(t *testing.T, p *nativeQueryAlert, asn string) string {
	t.Helper()
	ctx := tenancy.WithTenant(context.Background(), tenancy.ID(p.lane.id))
	condition := alert.QueryCondition{Mode: "new_group"}
	binding := alert.QueryGroupBinding{TenantID: p.lane.id, RuleID: p.rule.ID, ViewID: p.view.ID, ViewVersion: p.view.Version, Condition: condition}
	decisions, _, err := alert.EvaluateQueryGroups(ctx, binding, alert.QueryGroupSnapshot{TenantID: p.lane.id, ViewID: p.view.ID, ViewVersion: p.view.Version, At: time.Now().UTC(), Complete: true, Groups: []alert.QueryGroup{{Dimensions: map[string]string{"src_asn": asn}}}}, alert.QueryGroupState{}, alert.QueryGroupBudget{MemoryBytes: 1 << 20, WorkUnits: 1 << 20})
	if err != nil || len(decisions) != 1 {
		t.Fatal("baseline lookup handle unavailable", err)
	}
	return decisions[0].Key
}

// Freeze the already-proven wire population before the operator lowers its
// resource allowance. The same absolute source cannot age out during restart.
func prepareNativeSavedQueryCostSources(t *testing.T, st *shipped.Stack, proofs []nativeQueryAlert) []nativeQueryAlert {
	t.Helper()
	if len(proofs) != 2 {
		t.Fatal("physical save-cost proof requires both original source lanes")
	}
	out := append([]nativeQueryAlert(nil), proofs...)
	for i := range out {
		p := &out[i]
		plan, _, err := flow.MaterializeQueryView(p.view.Definition, time.Now().UTC())
		if err != nil {
			t.Fatal(err)
		}
		p.lane.do(t, st, http.MethodPost, "/v1/explorer/flow-views", map[string]any{"definition": flow.QueryViewDefinition{Name: "Save-cost wire source " + p.lane.name, Visibility: "private", Time: flow.QueryViewTime{Mode: "absolute"}, Plan: plan}}, &p.view, http.StatusCreated)
		if len(p.lane.query(t, st, plan).Rows) < 2 {
			t.Fatal("physical save-cost source lacks multiple independently retained rows")
		}
	}
	return out
}

func proveNativeSavedQuerySaveCost(t *testing.T, st *shipped.Stack, sources []nativeQueryAlert) {
	t.Helper()
	for _, source := range sources {
		var before, after struct {
			Items []alert.Rule `json:"items"`
		}
		source.lane.do(t, st, http.MethodGet, "/v1/alerts", nil, &before, http.StatusOK)
		input := alert.QueryRuleInput{Name: "Over-cost actual source " + source.lane.name, QuerySource: alert.QuerySourceInput{ViewID: source.view.ID, ViewVersion: source.view.Version, EverySeconds: 60, Condition: alert.QueryCondition{Mode: "new_group"}}}
		var refusal struct {
			Error struct {
				Code string `json:"code"`
			} `json:"error"`
		}
		source.lane.do(t, st, http.MethodPost, "/v1/alerts", input, &refusal, http.StatusUnprocessableEntity)
		if refusal.Error.Code != string(apierror.CodeFlowQueryBudget) {
			t.Fatal("physical save did not refuse the actual source cost", refusal.Error.Code)
		}
		source.lane.do(t, st, http.MethodGet, "/v1/alerts", nil, &after, http.StatusOK)
		ids := make(map[string]bool, len(before.Items))
		for _, item := range before.Items {
			ids[item.ID] = true
		}
		if len(before.Items) != len(after.Items) {
			t.Fatal("refused physical source save retained a partial alert")
		}
		for _, item := range after.Items {
			if !ids[item.ID] {
				t.Fatal("refused physical source save replaced an existing alert")
			}
		}
	}
	t.Log("real-integration: both frozen actual wire populations exceed the operator's one-row read budget; alert creation refuses with the resource-budget code and leaves both tenant rule sets unchanged")
}
