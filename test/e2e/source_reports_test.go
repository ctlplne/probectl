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
	api                                                                         api
	tenant, address, source, version, snapshot, artifact, dashboard, sourceName string
	quantity                                                                    uint32
	body, frozen                                                                []byte
}

// Generated NetFlow wire -> actual registered collector -> TLS/SASL Kafka ->
// HTTPS ClickHouse reader -> release-image source reports and encrypted FS
// snapshots. The distinct mTLS probe/TLS Prometheus proof remains mandatory.
// This is production-transport software evidence, not hardware-exporter proof.
func proveReleaseSourceReports(t *testing.T, root, work, ca, cert, key string, stack composeStack, secrets storeSecrets,
	cli func(...string) string, readers []api) []releaseFlowReport {
	t.Helper()
	collector, command := filepath.Join(work, "probectl-flow-agent"), filepath.Join(work, "probectl-report-cli")
	runCmd(t, root, nil, "go", "build", "-o", collector, "./cmd/probectl-flow-agent")
	runCmd(t, root, nil, "go", "build", "-o", command, "./cmd/probectl")
	proofs := []releaseFlowReport{
		{api: readers[0], tenant: tenantA, address: "10.211.1.1", quantity: 31337},
		{api: readers[1], tenant: tenantB, address: "10.212.1.1", quantity: 77331},
	}
	at := time.Now().UTC()
	for i := range proofs {
		p := &proofs[i]
		agent := fmt.Sprintf("a7000000-0000-4000-8000-%012d", 7+i)
		token := mintEnrollTokenTTL(t, cli, p.tenant, agent, "release-report-source", "10m")
		var registration struct {
			TenantID string `json:"tenant_id"`
			AgentID  string `json:"agent_id"`
			Config   struct {
				Env map[string]string `json:"env"`
			} `json:"config"`
		}
		p.api.json(t, http.StatusCreated, http.MethodPost, "/v1/collectors/register",
			map[string]string{"token": token, "plane": "flow", "hostname": "release-report-source"}, &registration)
		env := registration.Config.Env
		if registration.TenantID != p.tenant || registration.AgentID != agent || env["PROBECTL_FLOW_TENANT"] != p.tenant ||
			env["PROBECTL_FLOW_AGENT_ID"] != agent || env["PROBECTL_FLOW_BUS_NAMESPACE"] == "" {
			t.Fatal("release flow registration did not bind current tenant, collector and bus lane")
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
		log, stop, exited := startProc(t, work, "release-report-collector-"+strconv.Itoa(i), collector, nil, values)
		defer stop()
		waitFor(t, "registered release flow collector listener", 30*time.Second, func() bool {
			if err := exited(); err != nil {
				t.Fatal("release flow collector exited before input", err)
			}
			raw, err := os.ReadFile(log)
			return err == nil && bytes.Contains(raw, []byte("flow: listening"))
		})
		p.send(t, address, i)
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
			map[string]any{"definition": map[string]any{"name": "Release source " + strconv.Itoa(i), "visibility": "private", "time": map[string]string{"mode": "absolute"}, "plan": plan}}, &view)
		if view.ID == "" || view.Version == "" {
			t.Fatal("release source lost its pinned saved identity")
		}
		p.source, p.version = view.ID, view.Version
		p.sourceName = "Release source " + strconv.Itoa(i)
		var dashboard struct {
			ID       string
			TenantID string `json:"tenant_id"`
		}
		p.api.json(t, http.StatusCreated, http.MethodPost, "/v1/dashboards", map[string]any{
			"name": "Release collector source " + strconv.Itoa(i), "preset": "operator", "shared": false,
			"definition": map[string]any{"flow_sources": []map[string]string{{"id": view.ID, "version": view.Version}},
				"provenance":      []string{"actual compiled collector; generated NetFlowv5; verified TLS/SASL bus and HTTPS stores"},
				"redaction_state": "tenant-scoped", "coverage_limitations": []string{"software protocol fixture, no hardware-exporter claim"}}}, &dashboard)
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
		for _, path := range []string{"/v1/dashboard-report-artifacts/" + p.artifact, "/v1/explorer/flow-snapshots/" + p.snapshot + "/csv",
			"/v1/explorer/flow-views/" + p.source} {
			if status, _ := foreign.api.do(t, http.MethodGet, path, nil, "X-Probectl-Tenant", p.tenant); status != http.StatusNotFound {
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
	t.Log("release profile source reports: actual registered collectors, TLS/SASL Kafka, HTTPS ClickHouse, encrypted snapshot objects and Postgres report publication, paired API/builtCLI and foreign refusals passed; generated NetFlow provenance retained")
	return proofs
}

func (p *releaseFlowReport) plan(at time.Time) map[string]any {
	return map[string]any{"from": at.Add(-time.Minute).Format(time.RFC3339Nano), "to": at.Add(5 * time.Minute).Format(time.RFC3339Nano),
		"view": "table", "group_by": []string{"src_addr", "exporter"}, "row_limit": 350, "page_size": 350, "bucket_seconds": 60,
		"metrics": []map[string]string{{"measure": "bytes", "calculation": "total", "role": "primary"}, {"measure": "flows", "calculation": "total", "role": "additional"}},
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
