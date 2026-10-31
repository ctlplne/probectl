// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package flow_test

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/testsupport"
	"github.com/ctlplne/probectl/internal/testsupport/shipped"
)

// TestNativeFlowExplorerRealStack is the CI-native F17 receipt, using the
// existing four-store shipped test harness: real Dex sessions, signed collector
// registration, real protocol datagrams, the shipped collector/consumer and the
// policy-bound ClickHouse reader, REST, CLI, MCP and rendered native Explorer.
// Its Kafka and Prometheus use the existing CI development transport profile;
// this test does not claim production transport hardening or hardware exporters.
// The separate exact-image program receipt exercises the production TLS profile.
func TestNativeFlowExplorerRealStack(t *testing.T) {
	st := shipped.Start(t, shipped.Options{Name: "nativeflow", TenantBand: 4})
	op := st.OnboardOperator(t, "root@msp-nativeflow.example")
	run := strconv.FormatInt(time.Now().UnixNano(), 36)
	lanes := []*nativeLane{{name: "red", octet: 181, bytes: 1000}, {name: "blue", octet: 182, bytes: 5000}}
	for _, lane := range lanes {
		lane.provision(t, st, op, run)
	}
	at := time.Now().UTC()
	for _, lane := range lanes {
		lane.send(t)
	}
	for _, lane := range lanes {
		lane.awaitFlows(t, st, at)
	}
	for i, lane := range lanes {
		other := lanes[1-i]
		lane.proveDimensions(t, st, other, at)
		plan := nativeGoldenPlan(lane.octet, at, []string{"protocol", "src_addr", "src_port"})
		result := lane.query(t, st, plan)
		var cli struct {
			Flow flowstore.PlanResult `json:"flow"`
		}
		st.MustCLI(t, map[string]string{"PROBECTL_API_TOKEN": lane.apiToken}, &cli, "explorer", "query", "--body-file", st.SecretFile(t, map[string]any{"source": "flow", "flow": plan}))
		if fmt.Sprint(cli.Flow.Totals) != fmt.Sprint(result.Totals) || len(cli.Flow.Rows) != 4 {
			t.Fatal("release CLI lost native golden quantities")
		}
		var saved flow.SavedQueryView
		plan.View = "bar"
		lane.do(t, st, http.MethodPost, "/v1/explorer/flow-views", map[string]any{"definition": flow.QueryViewDefinition{Name: "Native golden " + lane.name, Visibility: "private", Time: flow.QueryViewTime{Mode: "absolute"}, Plan: plan}}, &saved, http.StatusCreated)
		lane.view = saved.ID
		testsupport.RenderUI(t, testsupport.RenderSpec{URL: st.BaseURL + "/ui/explore?flow_view=" + saved.ID, Cookies: []testsupport.RenderCookie{{Name: auth.SessionCookie, Value: lane.cookie}}, TrustCertFiles: st.TrustCerts(), CAFile: st.CAFile, Expect: []string{"Flow explorer", "Native flow query"}, Absent: []string{fmt.Sprintf("10.%d.", other.octet)}, Steps: []testsupport.RenderStep{{Click: "Run flow query", Expect: []string{"Frozen flow results", "Exact flow details", "netflow5", "netflow9", "ipfix", "sflow5", fmt.Sprintf("10.%d.1.1", lane.octet)}}}})
		var preview struct {
			Proposal struct {
				Status string `json:"status"`
			} `json:"proposal"`
			Flow json.RawMessage `json:"flow"`
		}
		lane.do(t, st, http.MethodPost, "/v1/explorer/query", map[string]any{"source": "flow", "plan_only": true, "question": "show bps all rows"}, &preview, http.StatusOK)
		if preview.Proposal.Status != "ready" || len(preview.Flow) != 0 {
			t.Fatal("stateless natural-language proposal executed telemetry or was unavailable")
		}
	}
	for i, lane := range lanes {
		lane.do(t, st, http.MethodGet, "/v1/explorer/flow-views/"+lanes[1-i].view, nil, nil, http.StatusNotFound)
	}
	mcpAddr := shipped.FreeAddr(t)
	st.RestartControl(t, "native-flow-mcp", map[string]string{"PROBECTL_MCP_HTTP_ADDR": mcpAddr, "PROBECTL_MCP_TLS_CERT_FILE": st.ServerCert, "PROBECTL_MCP_TLS_KEY_FILE": st.ServerKey})
	for i, lane := range lanes {
		lane.proveMCP(t, st, mcpAddr, lanes[1-i], at)
	}
}

type nativeLane struct {
	name, id, cookie, apiToken, agent, view string
	octet                                   int
	bytes                                   uint32
	listeners                               map[string]string
}

func (lane *nativeLane) do(t *testing.T, st *shipped.Stack, method, path string, body, out any, want int) {
	t.Helper()
	code, raw := st.Do(t, lane.cookie, method, path, body)
	if code != want {
		t.Fatalf("%s %s as %s = %d,want %d: %.600s", method, path, lane.name, code, want, raw)
	}
	if out != nil {
		if err := json.Unmarshal(raw, out); err != nil {
			t.Fatal(err)
		}
	}
}
func (lane *nativeLane) provision(t *testing.T, st *shipped.Stack, operator, run string) {
	t.Helper()
	var tenant struct{ ID string }
	st.MustCLI(t, map[string]string{"PROBECTL_API_TOKEN": operator}, &tenant, "provider", "create-tenant", "--body", fmt.Sprintf(`{"slug":%q,"name":%q,"isolation_model":"pooled"}`, "native-"+lane.name+"-"+run, "Native "+lane.name))
	lane.id = tenant.ID
	email := "ada@acme.example"
	if lane.name == "blue" {
		email = "bob@globex.example"
	}
	lane.cookie = st.SignIn(t, lane.id, email, "Native "+lane.name)
	lane.apiToken = st.APIToken(t, lane.cookie, "read", "ai.query")
	var join struct{ Token string }
	lane.do(t, st, http.MethodPost, "/v1/agents/enroll-tokens", map[string]any{"name": "native-" + lane.name, "ttl_seconds": 600}, &join, http.StatusCreated)
	var registration struct {
		TenantID string `json:"tenant_id"`
		AgentID  string `json:"agent_id"`
		Config   struct {
			Env map[string]string `json:"env"`
		} `json:"config"`
	}
	lane.do(t, st, http.MethodPost, "/v1/collectors/register", map[string]any{"token": join.Token, "plane": "flow", "hostname": "native-" + lane.name}, &registration, http.StatusCreated)
	if registration.TenantID != lane.id || registration.AgentID == "" {
		t.Fatal("collector registration lost authenticated tenant")
	}
	lane.agent = registration.AgentID
	env := registration.Config.Env
	if env == nil {
		t.Fatal("collector registration omitted signed environment")
	}
	env["PROBECTL_FLOW_BUS_MODE"] = "kafka"
	env["PROBECTL_FLOW_BUS_BROKERS"] = strings.Join(testsupport.KafkaBrokers(), ",")
	env["PROBECTL_FLOW_BUS_ALLOW_PLAINTEXT"] = "true" // existing CI-only development broker profile
	env["PROBECTL_FLOW_FLUSH_INTERVAL"] = "100ms"
	env["PROBECTL_FLOW_METRICS_ADDR"] = shipped.FreeAddr(t)
	env["PROBECTL_FLOW_METRICS_TLS_CERT_FILE"] = st.ServerCert
	env["PROBECTL_FLOW_METRICS_TLS_KEY_FILE"] = st.ServerKey
	lane.listeners = map[string]string{}
	for _, protocol := range []string{"NETFLOW", "IPFIX", "SFLOW"} {
		addr := shipped.FreeUDPAddr(t)
		lane.listeners[protocol] = addr
		env["PROBECTL_FLOW_"+protocol+"_LISTEN"] = addr
		env["PROBECTL_FLOW_"+protocol+"_ALLOWED_SOURCES"] = "127.0.0.1/32"
		env["PROBECTL_FLOW_"+protocol+"_ENABLED"] = "true"
	}
	values := make([]string, 0, len(env))
	for key, value := range env {
		values = append(values, key+"="+value)
	}
	log := st.StartProcess(t, "native-collector-"+lane.name, st.Binary(t, "probectl-flow-agent"), nil, values)
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		raw, err := os.ReadFile(log)
		if err == nil && strings.Count(string(raw), "flow: listening") == 3 {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("shipped native collector failed to open all three protocol listeners")
}
func nativeGoldenPlan(octet int, at time.Time, fields []string) flow.QueryPlan {
	return flow.QueryPlan{From: at.Add(-time.Minute), To: at.Add(5 * time.Minute), GroupBy: fields, View: "table", RowLimit: 350, PageSize: 350, BucketSeconds: 60, Metrics: []flow.QueryMetric{{Measure: "bytes", Calculation: "total", Role: "primary"}, {Measure: "packets", Calculation: "total", Role: "additional"}, {Measure: "flows", Calculation: "total", Role: "additional"}}, Filter: &flow.QueryFilterGroup{Conditions: []flow.QueryPredicate{{Field: "src_addr", Op: flow.QueryCIDR, Values: []string{fmt.Sprintf("10.%d.0.0/16", octet)}}}}}
}
func (lane *nativeLane) query(t *testing.T, st *shipped.Stack, plan flow.QueryPlan) flowstore.PlanResult {
	t.Helper()
	var result struct {
		Flow flowstore.PlanResult `json:"flow"`
	}
	lane.do(t, st, http.MethodPost, "/v1/explorer/query", map[string]any{"source": "flow", "flow": plan}, &result, http.StatusOK)
	if result.Flow.Source != "raw" || result.Flow.Coverage == nil || !result.Flow.Coverage.CompleteInputs {
		t.Fatal("native receipt did not execute complete raw source")
	}
	return result.Flow
}
func (lane *nativeLane) awaitFlows(t *testing.T, st *shipped.Stack, at time.Time) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		result := lane.query(t, st, nativeGoldenPlan(lane.octet, at, []string{"protocol"}))
		if result.Totals["flows:total"] == "4" {
			if result.Totals["bytes:total"] != strconv.FormatUint(uint64(lane.bytes)+10800, 10) || result.Totals["packets:total"] != "160" {
				t.Fatal("native received quantities differ from generated wire counters")
			}
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatal("native wire population did not reach durable ClickHouse")
}
func (lane *nativeLane) proveDimensions(t *testing.T, st *shipped.Stack, other *nativeLane, at time.Time) {
	t.Helper()
	for _, field := range flow.QueryFields() {
		plan := nativeGoldenPlan(lane.octet, at, []string{field.Name})
		result := lane.query(t, st, plan)
		if result.Totals["flows:total"] != "4" || len(result.Rows) == 0 {
			t.Fatalf("%s lost known wire inputs", field.Name)
		}
		sample := result.Rows[0].Group[field.Name]
		plan.Filter.Conditions = append(plan.Filter.Conditions, flow.QueryPredicate{Field: field.Name, Op: flow.QueryEqual, Values: []string{sample}})
		if own := lane.query(t, st, plan); own.Totals["flows:total"] == "0" {
			t.Fatalf("%s equality lost its own wire value", field.Name)
		}
		plan.Filter.Conditions[0].Values = []string{fmt.Sprintf("10.%d.0.0/16", other.octet)}
		foreign := lane.query(t, st, plan)
		if len(foreign.Rows) != 0 || foreign.Totals["flows:total"] != "0" {
			t.Fatalf("%s foreign-prefix substitution disclosed another tenant", field.Name)
		}
	}
}
func (lane *nativeLane) proveMCP(t *testing.T, st *shipped.Stack, addr string, other *nativeLane, at time.Time) {
	t.Helper()
	var me struct {
		UserID string `json:"user_id"`
	}
	lane.do(t, st, http.MethodGet, "/v1/me", nil, &me, http.StatusOK)
	output := st.Subcommand(t, "mcp-token", "--tenant", lane.id, "--user", me.UserID, "--scope", "read,ai.query", "--expires-days", "1")
	lines := strings.Split(strings.TrimSpace(output), "\n")
	token := lines[len(lines)-1]
	call := func(plan flow.QueryPlan) struct {
		Result struct {
			IsError    bool `json:"isError"`
			Structured struct {
				Flow struct {
					Rows   []json.RawMessage                `json:"rows"`
					Totals []struct{ Metric, Value string } `json:"totals"`
				} `json:"flow"`
			} `json:"structuredContent"`
		} `json:"result"`
	} {
		t.Helper()
		body, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": map[string]any{"name": "flow_explorer_query", "arguments": map[string]any{"plan": plan}, "_meta": map[string]any{"io.modelcontextprotocol/protocolVersion": "2026-07-28", "io.modelcontextprotocol/clientCapabilities": map[string]any{}}}})
		if err != nil {
			t.Fatal(err)
		}
		request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "https://"+addr+"/", bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Authorization", "Bearer "+token)
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Accept", "application/json, text/event-stream")
		request.Header.Set("MCP-Protocol-Version", "2026-07-28")
		request.Header.Set("Mcp-Method", "tools/call")
		request.Header.Set("Mcp-Name", "flow_explorer_query")
		request.Header.Set("X-Probectl-Tenant", other.id)
		response, err := st.Client().Do(request)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		raw, err := io.ReadAll(io.LimitReader(response.Body, 4<<20))
		if err != nil || response.StatusCode != http.StatusOK {
			t.Fatal("native MCP HTTPS request failed")
		}
		var result struct {
			Result struct {
				IsError    bool `json:"isError"`
				Structured struct {
					Flow struct {
						Rows   []json.RawMessage                `json:"rows"`
						Totals []struct{ Metric, Value string } `json:"totals"`
					} `json:"flow"`
				} `json:"structuredContent"`
			} `json:"result"`
		}
		if err := json.Unmarshal(raw, &result); err != nil {
			t.Fatal(err)
		}
		return result
	}
	plan := nativeGoldenPlan(lane.octet, at, []string{"protocol"})
	if denied := call(plan); !denied.Result.IsError {
		t.Fatal("MCP released golden flow data without tenant consent")
	}
	lane.do(t, st, http.MethodPut, "/v1/governance/policy", map[string]any{"ai_remote_egress": true, "redact_export": true}, nil, http.StatusOK)
	result := call(plan)
	if result.Result.IsError || len(result.Result.Structured.Flow.Rows) != 4 {
		t.Fatal("native MCP failed to return known wire groups")
	}
	want := strconv.FormatUint(uint64(lane.bytes)+10800, 10)
	found := false
	for _, total := range result.Result.Structured.Flow.Totals {
		if total.Metric == "bytes:total" {
			found = true
			if total.Value != want {
				t.Fatal("MCP native wire total differs from REST/CLI")
			}
		}
	}
	if !found {
		t.Fatal("MCP omitted golden byte total")
	}
	plan.Filter.Conditions[0].Values = []string{fmt.Sprintf("10.%d.0.0/16", other.octet)}
	if foreign := call(plan); foreign.Result.IsError || len(foreign.Result.Structured.Flow.Rows) != 0 {
		t.Fatal("MCP foreign-prefix substitution escaped tenant scope")
	}
}

func nativeWire(t *testing.T, values ...any) []byte {
	t.Helper()
	var out bytes.Buffer
	for _, value := range values {
		if err := binary.Write(&out, binary.BigEndian, value); err != nil {
			t.Fatal(err)
		}
	}
	return out.Bytes()
}
func (lane *nativeLane) send(t *testing.T) {
	t.Helper()
	ip := func(n, last byte) [4]byte { return [4]byte{10, byte(lane.octet), n, last} } //nolint:gosec // fixed fixture octets181/182
	now := time.Now()
	seconds := uint32(now.Unix()) //nolint:gosec // bounded protocol timestamp fixture
	nf5 := nativeWire(t, uint16(5), uint16(1), uint32(60000), seconds, uint32(now.Nanosecond()), uint32(0), uint8(0), uint8(0), uint16(0))
	nf5 = append(nf5, nativeWire(t, ip(1, 1), ip(1, 2), [4]byte{}, uint16(1), uint16(2), uint32(10), lane.bytes, uint32(59000), uint32(59900), uint16(41001), uint16(443), uint8(0), uint8(0x18), uint8(6), uint8(0), uint16(64512), uint16(64513), uint8(24), uint8(24), uint16(0))...)
	dataset := func(n byte) []byte {
		body := nativeWire(t, ip(n, 1), ip(n, 2), uint16(41000)+uint16(n), uint16(443), uint8(6), uint32(n)*1000, uint32(n)*10)
		return append(nativeWire(t, uint16(256), uint16(4+len(body))), body...)
	} //nolint:gosec // tiny fixed wire records
	template := func(id uint16) []byte {
		fields := []uint16{8, 4, 12, 4, 7, 2, 11, 2, 4, 1, 1, 4, 2, 4}
		body := nativeWire(t, uint16(256), uint16(7), fields)
		return append(nativeWire(t, id, uint16(4+len(body))), body...)
	} //nolint:gosec // tiny fixed template
	nf9 := append(nativeWire(t, uint16(9), uint16(2), uint32(60000), seconds, uint32(0), uint32(7)), template(0)...)
	nf9 = append(nf9, dataset(2)...)
	body := append(template(2), dataset(3)...)
	ipfix := append(nativeWire(t, uint16(10), uint16(16+len(body)), seconds, uint32(0), uint32(9)), body...) //nolint:gosec // tiny fixed datagram
	tcp := nativeWire(t, uint16(41004), uint16(443), uint32(1), uint32(0), uint8(0x50), uint8(0x10), uint16(8192), uint16(0), uint16(0))
	frame := append([]byte{2, 0, 0, 0, 0, 1, 2, 0, 0, 0, 0, 2, 8, 0}, nativeWire(t, uint8(0x45), uint8(0), uint16(40), uint16(1234), uint16(0), uint8(64), uint8(6), uint16(0), ip(4, 1), ip(4, 2))...)
	frame = append(frame, tcp...)
	raw := append(nativeWire(t, uint32(1), uint32(len(frame)+4), uint32(4), uint32(len(frame))), frame...)
	for len(raw)%4 != 0 {
		raw = append(raw, 0)
	} //nolint:gosec // fixed58-byte header frame
	rec := append(nativeWire(t, uint32(1), uint32(len(raw))), raw...) //nolint:gosec // fixed protocol fixture
	sample := append(nativeWire(t, uint32(1), uint32(0x01000001), uint32(100), uint32(100), uint32(0), uint32(3), uint32(4), uint32(1)), rec...)
	sf := append(nativeWire(t, uint32(5), uint32(1), [4]byte{127, 0, 0, 1}, uint32(0), uint32(1), uint32(1000), uint32(1), uint32(1), uint32(len(sample))), sample...) //nolint:gosec // fixed protocol fixture
	for _, packet := range []struct {
		protocol string
		wire     []byte
	}{{"NETFLOW", nf5}, {"NETFLOW", nf9}, {"IPFIX", ipfix}, {"SFLOW", sf}} {
		connection, err := net.Dial("udp", lane.listeners[packet.protocol])
		if err != nil {
			t.Fatal(err)
		}
		n, err := connection.Write(packet.wire)
		_ = connection.Close()
		if err != nil || n != len(packet.wire) {
			t.Fatal("golden datagram send failed")
		}
	}
}
