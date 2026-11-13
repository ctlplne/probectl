// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package e2e

import (
	"bytes"
	"encoding/binary"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

type releaseFlowReport struct {
	packetPrefixEntity, packetAgent, packetIncident                             string
	api                                                                         api
	tenant, address, source, version, snapshot, artifact, dashboard, sourceName string
	quantity                                                                    uint32
	packet                                                                      bool
	packetContext, packetEntity, packetTag, packetRule, packetValue             string
	packetPrefixCustomer                                                        string
	body, frozen                                                                []byte
	packetImpactInput, packetImpact                                             json.RawMessage
}

// Generated NetFlow wire -> actual registered collector -> TLS/SASL Kafka ->
// HTTPS ClickHouse reader -> release-image source reports and encrypted FS
// snapshots. The distinct mTLS probe/TLS Prometheus proof remains mandatory.
// This is production-transport software evidence, not hardware-exporter proof.
func proveReleaseSourceReports(t *testing.T, root, work, ca, cert, key string, stack composeStack, secrets storeSecrets,
	cli func(...string) string, readers []api) []releaseFlowReport {
	t.Helper()
	return proveReleaseSourceReportsForSender(t, root, work, ca, cert, key, "", stack, secrets, cli, readers, false)
}

func proveReleaseSourceReportsForSender(t *testing.T, root, work, ca, cert, key, evidenceAddr string, stack composeStack, secrets storeSecrets,
	cli func(...string) string, readers []api, packet bool) []releaseFlowReport {
	t.Helper()
	collector, command := filepath.Join(work, "probectl-flow-agent"), filepath.Join(work, "probectl-report-cli")
	runCmd(t, root, nil, "go", "build", "-o", collector, "./cmd/probectl-flow-agent")
	runCmd(t, root, nil, "go", "build", "-o", command, "./cmd/probectl")
	proofs := []releaseFlowReport{
		{api: readers[0], tenant: tenantA, address: "10.211.1.1", quantity: 31337},
		{api: readers[1], tenant: tenantB, address: "10.212.1.1", quantity: 77331},
	}
	if packet {
		buildReleasePacketExporter(t, root)
		for i := range proofs {
			proofs[i].packet = true
			proofs[i].address = "127.0.0." + strconv.Itoa(i+2)
			proofs[i].quantity = releasePacketCount * (releasePacketPayload + 20 + 8)
		}
	}
	at := time.Now().UTC()
	for i := range proofs {
		p := &proofs[i]
		p.sourceName = "Release source " + strconv.Itoa(i)
		if p.packet {
			p.sourceName = "Captured packet source " + strconv.Itoa(i)
		}
		address, stop, exited := startReleaseReportCollector(t, p, collector, work, ca, cert, key, evidenceAddr, stack, secrets, cli, i)
		defer stop()
		if p.packet {
			stopExporter := p.sendCapturedPackets(t, address)
			// Stop before the other cohort starts. The collector stays live
			// to attest actual silence without capturing the next burst.
			stopExporter()
		} else {
			p.send(t, address, i)
		}
		plan := p.plan(at)
		var observed struct {
			Flow struct {
				Totals map[string]string `json:"totals"`
				Rows   []json.RawMessage `json:"rows"`
			} `json:"flow"`
			Paging struct {
				ID string `json:"snapshot_id"`
			} `json:"flow_paging"`
		}
		ingested := false
		defer func() {
			if p.packet && !ingested {
				t.Logf("real packet last stored query: rows=%d bytes=%s packets=%s flows=%s; expected packets=%d bytes=%d flows=1", len(observed.Flow.Rows), observed.Flow.Totals["bytes:total"], observed.Flow.Totals["packets:total"], observed.Flow.Totals["flows:total"], releasePacketCount, p.quantity)
			}
		}()
		waitFor(t, "release flow through tenant-forced ClickHouse reader", 90*time.Second, func() bool {
			if err := exited(); err != nil {
				t.Fatal("release flow collector exited during source ingestion", err)
			}
			p.api.json(t, http.StatusOK, http.MethodPost, "/v1/explorer/query", map[string]any{"source": "flow", "flow": plan}, &observed)
			return len(observed.Flow.Rows) == 1 && observed.Flow.Totals["bytes:total"] == strconv.FormatUint(uint64(p.quantity), 10)
		})
		if observed.Flow.Totals["flows:total"] != "1" || observed.Paging.ID == "" {
			t.Fatal("release source lost exact flow count or object-backed snapshot")
		}
		ingested = true
		if p.packet {
			p.retagCapturedHistory(t, plan)
			p.api.json(t, http.StatusOK, http.MethodPost, "/v1/explorer/query", map[string]any{"source": "flow", "flow": plan}, &observed)
			if len(observed.Flow.Rows) != 1 || observed.Flow.Totals["bytes:total"] != strconv.FormatUint(uint64(p.quantity), 10) || observed.Flow.Totals["flows:total"] != "1" || observed.Paging.ID == "" {
				t.Fatal("real source rule edit changed historical input counters or snapshot")
			}
		}
		p.snapshot = observed.Paging.ID
		code, frozen := p.api.do(t, http.MethodGet, "/v1/explorer/flow-snapshots/"+p.snapshot+"/csv", nil)
		if code != http.StatusOK || !bytes.Contains(frozen, []byte(p.address)) {
			t.Fatal("release encrypted snapshot object did not read back its own address", code)
		}
		p.frozen = frozen
		if body, code := p.runCLI(t, command, ca, "explorer", "snapshot-csv", p.snapshot); code != 0 || !bytes.Equal(body, frozen) {
			t.Fatal("built verified snapshot CLI differs from stored object bytes")
		}
		var view struct{ ID, Version string }
		p.api.json(t, http.StatusCreated, http.MethodPost, "/v1/explorer/flow-views",
			map[string]any{"definition": map[string]any{"name": p.sourceName, "visibility": "private", "time": map[string]string{"mode": "absolute"}, "plan": plan}}, &view)
		if view.ID == "" || view.Version == "" {
			t.Fatal("release source lost its pinned saved identity")
		}
		p.source, p.version = view.ID, view.Version
		var dashboard struct {
			ID       string
			TenantID string `json:"tenant_id"`
		}
		name := "Release collector source " + strconv.Itoa(i)
		provenance := []string{"actual compiled collector; generated NetFlowv5; verified TLS/SASL bus and HTTPS stores"}
		limitations := []string{"software protocol fixture, no hardware-exporter claim"}
		if p.packet {
			name = "Captured collector report " + strconv.Itoa(i)
			provenance = []string{"actual softflowd IPFIX capture of owned ICMP packets; verified TLS/SASL bus and HTTPS stores"}
			limitations = []string{"real software exporter on loopback; no hardware or physical-router claim"}
		}
		p.api.json(t, http.StatusCreated, http.MethodPost, "/v1/dashboards", map[string]any{
			"name": name, "preset": "operator", "shared": false,
			"definition": map[string]any{"flow_sources": []map[string]string{{"id": view.ID, "version": view.Version}},
				"provenance":      provenance,
				"redaction_state": "tenant-scoped", "coverage_limitations": limitations}}, &dashboard)
		if dashboard.TenantID != p.tenant || dashboard.ID == "" {
			t.Fatal("release source dashboard changed tenant")
		}
		p.dashboard = dashboard.ID
		var artifact struct{ ID string }
		p.api.json(t, http.StatusCreated, http.MethodPost, "/v1/dashboard-reports", map[string]string{"dashboard_id": dashboard.ID, "format": "csv"}, &artifact)
		p.artifact = artifact.ID
		if p.artifact == "" {
			t.Fatal("release source artifact has no identity")
		}
		code, p.body = p.api.do(t, http.MethodGet, "/v1/dashboard-report-artifacts/"+p.artifact, nil)
		if code != http.StatusOK {
			t.Fatal("release source artifact was not readable", code)
		}
		p.verify(t, p.body)
		if body, code := p.runCLI(t, command, ca, "dashboard-report", "download", p.artifact); code != 0 || !bytes.Equal(body, p.body) {
			t.Fatal("built report CLI differs from complete release artifact")
		}
	}
	for i := range proofs {
		p, foreign := &proofs[i], &proofs[1-i]
		if packet {
			p.assertPacketIdentity(t, foreign)
		}
		for _, path := range []string{"/v1/dashboard-report-artifacts/" + p.artifact, "/v1/explorer/flow-snapshots/" + p.snapshot + "/csv",
			"/v1/explorer/flow-views/" + p.source} {
			if status, _ := foreign.api.do(t, http.MethodGet, path, nil, "X-Probectl-Tenant", p.tenant); status != http.StatusUnauthorized {
				t.Fatal("forged release tenant header was not rejected at authentication", status)
			}
			if status, _ := foreign.api.do(t, http.MethodGet, path, nil); status != http.StatusNotFound {
				t.Fatal("foreign release report/source/object was not hidden", status)
			}
		}
		plan := foreign.plan(at)
		plan["filter"] = map[string]any{"conditions": []map[string]any{{"field": "src_addr", "op": "eq", "values": []string{p.address}}}}
		var result struct {
			Flow struct {
				Rows []json.RawMessage `json:"rows"`
			} `json:"flow"`
		}
		foreign.api.json(t, http.StatusOK, http.MethodPost, "/v1/explorer/query", map[string]any{"source": "flow", "flow": plan}, &result)
		if len(result.Flow.Rows) != 0 {
			t.Fatal("release query source substitution crossed tenant store boundary")
		}
	}
	if packet {
		for i := range proofs {
			proofs[i].provePacketFaultImpact(t, &proofs[1-i], at, command, ca)
		}
		t.Log("real packet report sources: actual softflowd IPFIX capture, exact selected packet/IP-byte counters, query-time rule history, registered collectors, TLS/SASL Kafka, HTTPS ClickHouse, encrypted snapshots and stored reports, paired API/CLI and foreign refusals passed; no hardware claim")
	} else {
		t.Log("release profile source reports: actual registered collectors, TLS/SASL Kafka, HTTPS ClickHouse, encrypted snapshot objects and Postgres report publication, paired API/builtCLI and foreign refusals passed; generated NetFlow provenance retained")
	}
	return proofs
}

func startReleaseReportCollector(t *testing.T, p *releaseFlowReport, collector, work, ca, cert, key, evidenceAddr string,
	stack composeStack, secrets storeSecrets, cli func(...string) string, i int) (string, func(), func() error) {
	t.Helper()
	number := 7 + i
	if p.packet {
		number += 10
	}
	agent := fmt.Sprintf("a7000000-0000-4000-8000-%012d", number)
	hostname := "release-report-source"
	if p.packet {
		hostname = "release-packet-source"
		p.packetAgent = agent
	}
	token := mintEnrollTokenTTL(t, cli, p.tenant, agent, hostname, "10m")
	var registration struct {
		TenantID string `json:"tenant_id"`
		AgentID  string `json:"agent_id"`
		Config   struct {
			Env map[string]string `json:"env"`
		} `json:"config"`
	}
	p.api.json(t, http.StatusCreated, http.MethodPost, "/v1/collectors/register",
		map[string]string{"token": token, "plane": "flow", "hostname": hostname}, &registration)
	env := registration.Config.Env
	if registration.TenantID != p.tenant || registration.AgentID != agent || env["PROBECTL_FLOW_TENANT"] != p.tenant ||
		env["PROBECTL_FLOW_AGENT_ID"] != agent || env["PROBECTL_FLOW_BUS_NAMESPACE"] == "" {
		t.Fatal("release flow registration did not bind current tenant, collector and bus lane")
	}
	if p.packet {
		p.preparePacketTag(t, agent)
		p.preparePacketIdentity(t, cli, agent, hostname, ca, evidenceAddr, env)
	}
	listener, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.LocalAddr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	env["PROBECTL_FLOW_NETFLOW_ENABLED"] = "true"
	env["PROBECTL_FLOW_NETFLOW_LISTEN"] = address
	env["PROBECTL_FLOW_NETFLOW_ALLOWED_SOURCES"] = "127.0.0.1/32"
	env["PROBECTL_FLOW_IPFIX_ENABLED"] = "false"
	env["PROBECTL_FLOW_SFLOW_ENABLED"] = "false"
	if p.packet {
		env["PROBECTL_FLOW_NETFLOW_ENABLED"] = "false"
		env["PROBECTL_FLOW_IPFIX_ENABLED"] = "true"
		env["PROBECTL_FLOW_IPFIX_LISTEN"] = address
		env["PROBECTL_FLOW_IPFIX_ALLOWED_SOURCES"] = "127.0.0.1/32"
	}
	env["PROBECTL_FLOW_FLUSH_INTERVAL"] = "100ms"
	env["PROBECTL_FLOW_BUS_MODE"] = "kafka"
	env["PROBECTL_FLOW_BUS_BROKERS"] = "localhost:" + stack.envValue("PROBECTL_DEV_KAFKA_PORT")
	env["PROBECTL_FLOW_METRICS_ADDR"] = "127.0.0.1:" + freeTCPPort(t)
	env["PROBECTL_FLOW_METRICS_TLS_CERT_FILE"] = cert
	env["PROBECTL_FLOW_METRICS_TLS_KEY_FILE"] = key
	values := collectorBusEnv("PROBECTL_FLOW", ca, secrets)
	for name, value := range env {
		values = append(values, name+"="+value)
	}
	label := "release-report-collector-"
	if p.packet {
		label = "release-packet-collector-"
	}
	log, stop, exited := startProc(t, work, label+strconv.Itoa(i), collector, nil, values)
	waitFor(t, "registered release flow collector listener", 30*time.Second, func() bool {
		if err := exited(); err != nil {
			t.Fatal("release flow collector exited before input", err)
		}
		raw, err := os.ReadFile(log)
		return err == nil && bytes.Contains(raw, []byte("flow: listening"))
	})
	return address, stop, exited
}

func (p *releaseFlowReport) plan(at time.Time) map[string]any {
	groups := []string{"src_addr", "exporter"}
	metrics := []map[string]string{{"measure": "bytes", "calculation": "total", "role": "primary"}, {"measure": "flows", "calculation": "total", "role": "additional"}}
	if p.packet {
		groups = append(groups, "protocol", "tag.packet_customer", "tag.packet_prefix_customer")
		metrics = append(metrics, map[string]string{"measure": "packets", "calculation": "total", "role": "additional"})
	}
	return map[string]any{"from": at.Add(-time.Minute).Format(time.RFC3339Nano), "to": at.Add(5 * time.Minute).Format(time.RFC3339Nano),
		"view": "table", "group_by": groups, "row_limit": 350, "page_size": 350, "bucket_seconds": 60,
		"metrics": metrics,
		"filter":  map[string]any{"conditions": []map[string]any{{"field": "src_addr", "op": "eq", "values": []string{p.address}}}}}
}

func (p *releaseFlowReport) send(t *testing.T, address string, lane int) {
	t.Helper()
	var packet bytes.Buffer
	now := time.Now()
	ip := net.ParseIP(p.address).To4()
	if ip == nil {
		t.Fatal("invalid fixed release source address")
	}
	for _, value := range []any{uint16(5), uint16(1), uint32(60000), releaseProtocolUint32(t, now.Unix()), releaseProtocolUint32(t, int64(now.Nanosecond())), uint32(0),
		uint8(0), uint8(0), uint16(0), []byte(ip), [][4]byte{{192, 0, 2, 10}, {192, 0, 2, 11}}[lane], [4]byte{},
		uint16(1), uint16(2), uint32(10), p.quantity, uint32(59000), uint32(59900), uint16(41001), uint16(443),
		uint8(0), uint8(0x18), uint8(6), uint8(0), uint16(64512), uint16(64513), uint8(24), uint8(24), uint16(0)} {
		if err := binary.Write(&packet, binary.BigEndian, value); err != nil {
			t.Fatal("encode fixed release NetFlow input")
		}
	}
	connection, err := net.Dial("udp", address)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if n, err := connection.Write(packet.Bytes()); err != nil || n != packet.Len() {
		t.Fatal("send complete fixed release NetFlow input")
	}
}

func (p *releaseFlowReport) verify(t *testing.T, body []byte) {
	t.Helper()
	reader := csv.NewReader(bytes.NewReader(body))
	reader.FieldsPerRecord = -1
	detail := false
	address, quantity := -1, -1
	packetColumns := map[string]int{}
	rows, totals := 0, 0
	for {
		row, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal("release source CSV is incomplete")
		}
		if len(row) == 0 {
			continue
		}
		switch row[0] {
		case "table_tenant_scope":
			if len(row) != 2 || row[1] != p.tenant {
				t.Fatal("release source report crossed tenant")
			}
		case "table_id":
			if len(row) != 2 || !strings.HasPrefix(row[1], p.source+"/") {
				t.Fatal("release source report changed saved source identity")
			}
			detail = strings.HasSuffix(row[1], "/detail")
		}
		if !detail {
			continue
		}
		if row[0] == "record_type" {
			for i, name := range row {
				packetColumns[name] = i
				if name == "src_addr" {
					address = i
				}
				if name == "bytes:total" {
					quantity = i
				}
			}
			continue
		}
		if row[0] != "detail" && row[0] != "totals" {
			continue
		}
		if quantity < 0 || quantity >= len(row) || address < 0 || address >= len(row) || row[quantity] != strconv.FormatUint(uint64(p.quantity), 10) {
			t.Fatal("release source report lost exact counter/schema")
		}
		if p.packet {
			p.verifyPacketCSVCells(t, row, packetColumns)
		}
		if row[0] == "detail" {
			if row[address] != p.address {
				t.Fatal("release report changed own source address")
			}
			rows++
		} else {
			totals++
		}
	}
	if rows != 1 || totals != 1 {
		t.Fatal("release source report lost complete selected detail/total")
	}
}

func (p *releaseFlowReport) runCLI(t *testing.T, binary, ca string, args ...string) ([]byte, int) {
	t.Helper()
	command := exec.CommandContext(t.Context(), binary, append([]string{"--json"}, args...)...)
	command.Env = append(os.Environ(), "PROBECTL_API_URL="+p.api.base, "PROBECTL_API_TOKEN="+p.api.token, "PROBECTL_CA_FILE="+ca)
	var out bytes.Buffer
	command.Stdout = &out
	if err := command.Run(); err != nil {
		return out.Bytes(), 1
	}
	return out.Bytes(), 0
}

func (p *releaseFlowReport) recheck(t *testing.T) {
	t.Helper()
	for path, want := range map[string][]byte{"/v1/dashboard-report-artifacts/" + p.artifact: p.body,
		"/v1/explorer/flow-snapshots/" + p.snapshot + "/csv": p.frozen} {
		if code, body := p.api.do(t, http.MethodGet, path, nil); code != http.StatusOK || !bytes.Equal(body, want) {
			t.Fatal("release restart changed persisted report/object bytes", code)
		}
	}
}

func releaseProtocolUint32(t *testing.T, value int64) uint32 {
	t.Helper()
	if value < 0 || value > 4294967295 {
		t.Fatal("fixed NetFlow timestamp is outside its unsigned32 protocol range")
		return 0
	}
	return uint32(value)
}
