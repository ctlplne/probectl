// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package control

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/fairness"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport"
	"github.com/ctlplne/probectl/internal/testsupport/chtest"
)

const completeSourceParts = 10
const completeSourcePartRows = 50000

// Actual PG/ClickHouse/public TLS source proof. Rows are explicitly seeded;
// release binaries, real publishers and four-store acceptance remain separate.
func TestReportRealFlowSourcesPublishCompleteFiveHundredThousandRowCSV(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		f := newTagImportSubjectFixture(t)
		endpoint := os.Getenv("PROBECTL_FLOWSTORE_URL")
		if endpoint == "" {
			testsupport.SkipOrFatal(t, "PROBECTL_FLOWSTORE_URL required for complete source report")
		}
		source, err := flowstore.NewClickHouse(endpoint, 0)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = source.Close() })
		readerUser, reader := chtest.ProvisionReader(t, endpoint, "fx3_complete_report_reader")
		reader, readTrace := observeCompleteSourceReads(reader)
		source.WithTenantScoping(true).WithReader(reader)
		if err := source.EnsureReaderRowPolicy(t.Context(), readerUser); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			for _, tenant := range []string{f.a, f.b} {
				if _, err := source.DeleteTenant(ctx, tenant); err != nil {
					t.Error("owned complete source cleanup", err)
				}
			}
		})
		perSource := flowstore.DefaultExplorerBudget()
		budget := perSource
		budget.ExecutionLimit = 120 * time.Second
		// All ten result sets remain live while the projection copies complete
		// records. Its accounted five-column rows exceed the old165MiB share;
		// size this whole workload profile for those retained representations.
		budget.MemoryBytes = 16 << 30
		// Each source selects the already-supported complete 50,000-row result.
		// PlanBatch divides retained allowances across its declared sources, so
		// reserve a full standalone allowance for each, rather than shrinking
		// those results to fit the old aggregate test profile.
		budget.ResponseBytes = perSource.ResponseBytes * completeSourceParts
		budget.IntermediateGroups = perSource.IntermediateGroups * completeSourceParts
		budget.InterfaceItems = perSource.InterfaceItems * completeSourceParts
		budget.ReadRows = perSource.ReadRows * completeSourceParts
		budget.ReadBytes = 8 << 30
		if err := flowstore.AttachExplorerBudget(source, budget); err != nil {
			t.Fatal(err)
		}
		t.Logf("complete source operator profile: sources=%d read_rows=%d read_bytes=%d response_bytes=%d intermediate_groups=%d interface_items=%d memory_bytes=%d execution=%s", completeSourceParts, budget.ReadRows, budget.ReadBytes, budget.ResponseBytes, budget.IntermediateGroups, budget.InterfaceItems, budget.MemoryBytes, budget.ExecutionLimit)
		views := flow.NewPostgresQueryViewStore(f.db.Pool(), 0, audit.TenantRecord)
		f.srv.WithFlowStore(source).WithFlowQueryViews(views).WithFlowQueryFilters(flow.NewPostgresQueryFilterStore(f.db.Pool(), 0, audit.TenantRecord))
		policy := fairness.DefaultPolicy()
		policy.QueryConcurrency, policy.QueriesPerMin = 1, 10000
		f.srv.WithFairness(fairness.NewGate(policy, nil))
		at := time.Now().UTC().Truncate(time.Minute).Add(-2 * time.Minute)
		f.srv.cfg.AuthMode = ""
		socket := httptest.NewTLSServer(f.srv.Handler())
		defer socket.Close()
		for lane, tenant := range []string{f.a, f.b} {
			actor := completeSourceIdentity(t, f, tenant)
			seedCompleteSourceRows(t, source, tenant, f.agents[tenant], at, lane)
			ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
			ctx, err := f.srv.withFlowViewVocabulary(ctx, actor)
			if err != nil {
				t.Fatal(err)
			}
			refs := make([]reportFlowSourceRef, 0, completeSourceParts)
			for part := 0; part < completeSourceParts; part++ {
				definition := flow.QueryViewDefinition{Name: fmt.Sprintf("Disjoint source %02d", part), Visibility: "private", Time: flow.QueryViewTime{Mode: "absolute"}, TagIDs: map[string]string{"tag.role": f.tagID}, Plan: flow.QueryPlan{From: at.Add(-time.Minute), To: at.Add(time.Minute), View: "table", GroupBy: []string{"tag.role", "src_addr"}, Metrics: []flow.QueryMetric{{Measure: "bytes", Calculation: "total", Role: "primary"}}, RowLimit: completeSourcePartRows, PageSize: 1, DataSeries: "raw", Filter: &flow.QueryFilterGroup{Conditions: []flow.QueryPredicate{{Field: "src_port", Op: flow.QueryEqual, Values: []string{strconv.Itoa(20000 + part)}}}}}}
				saved, err := views.SaveQueryView(ctx, tenant, actor.UserID, flow.SaveQueryView{Definition: definition})
				if err != nil {
					t.Fatal("save disjoint complete source", err)
				}
				refs = append(refs, reportFlowSourceRef{ID: saved.ID, Version: saved.Version})
			}
			token, err := auth.RandomToken()
			if err != nil {
				t.Fatal(err)
			}
			if _, err := store.NewMCPTokens(f.db.Pool()).CreateWithLifetime(ctx, tenant, actor.UserID, "complete-source-report", crypto.Hash([]byte(token)), time.Now().Add(time.Hour), nil); err != nil {
				t.Fatal(err)
			}
			created := completeSourcePost[store.DashboardView](t, socket, token, "/v1/dashboards", dashboardCreateRequest{Name: "Complete selected sources", Preset: "operator", Definition: dashboardDefinition{FlowSources: refs, Provenance: []string{"ten disjoint current saved source results"}, RedactionState: "current source policy", CoverageLimitations: []string{"seeded PG/ClickHouse component; not release sender proof"}}})
			runtime.GC()
			var baseline runtime.MemStats
			runtime.ReadMemStats(&baseline)
			var peak atomic.Uint64
			peak.Store(baseline.Alloc)
			stop, stopped := make(chan struct{}), make(chan struct{})
			go func() {
				defer close(stopped)
				ticker := time.NewTicker(10 * time.Millisecond)
				defer ticker.Stop()
				for {
					select {
					case <-stop:
						return
					case <-ticker.C:
						var current runtime.MemStats
						runtime.ReadMemStats(&current)
						if current.Alloc > peak.Load() {
							peak.Store(current.Alloc)
						}
					}
				}
			}()
			var stopOnce sync.Once
			stopSampler := func() { stopOnce.Do(func() { close(stop); <-stopped }) }
			defer stopSampler()
			started := time.Now()
			artifact := func() reportArtifactView {
				readTrace.begin()
				defer func() {
					readTrace.finish(t)
					t.Logf("complete source generation elapsed_observation=%s", time.Since(started))
				}()
				return completeSourcePost[reportArtifactView](t, socket, token, "/v1/dashboard-reports", reportGenerateRequest{DashboardID: created.ID, Format: "csv"})
			}()
			stopSampler()
			elapsed := time.Since(started)
			path, digest, size := downloadCompleteSourceCSV(t, socket, token, artifact.ID)
			verifyCompleteSourceCSV(t, path, tenant, refs, lane)
			if size <= 2<<20 {
				t.Fatal("complete source report did not exceed the old inline representation")
			}
			delta := peak.Load() - baseline.Alloc
			if delta > uint64(budget.MemoryBytes) {
				t.Fatal("complete source generation exceeded its finite operation heap envelope", delta)
			}
			t.Logf("complete source CSV lane=%d distinct_sources=%d selected_detail_rows=%d bytes=%d sha256=%s observed_generation_heap_delta=%d memory_ceiling=%d response_ceiling=%d execution_ceiling=%s elapsed_observation=%s", lane, len(refs), completeSourceParts*completeSourcePartRows, size, digest, delta, budget.MemoryBytes, budget.ResponseBytes, budget.ExecutionLimit, elapsed)
		}
	})
}

func completeSourceIdentity(t *testing.T, f *tagImportSubjectFixture, tenant string) *auth.Principal {
	t.Helper()
	var actor *auth.Principal
	if err := tenancy.InTenant(tenancy.WithTenant(t.Context(), tenancy.ID(tenant)), f.db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
		user, err := (store.Users{}).Create(ctx, sc, "complete-report@"+tenant+".invalid", "Complete report owner")
		if err != nil {
			return err
		}
		role, err := (store.Roles{}).Create(ctx, sc, "complete-report-owner", "Complete report owner", "Bounded source output proof")
		if err != nil {
			return err
		}
		for _, permission := range []string{permAIQuery, permFlowRead, permTagsRead, "metrics.read", permMetricsWrite} {
			if err := (store.Roles{}).AddPermission(ctx, sc, role.ID, permission); err != nil {
				return err
			}
		}
		if err := (store.RoleBindings{}).Bind(ctx, sc, "user", user.ID, role.ID); err != nil {
			return err
		}
		grants, err := (store.Permissions{}).ForSubject(ctx, sc, "user", user.ID)
		if err != nil {
			return err
		}
		actor = auth.PrincipalWithPermissionGrants(&auth.Principal{TenantID: tenant, UserID: user.ID, Email: user.Email}, grants)
		_, err = sc.Q.Exec(ctx, `INSERT INTO tenant_tag_assignments(tenant_id,context_id,id,tag_id,target_kind,exporter_agent_id,exporter_source_kind,exporter_source_ref,value,source) VALUES($1,$2,$3,$4,'exporter',$5,'flow_exporter','192.0.2.10',$6,'manual')`, tenant, f.contextID, uuid(t), f.tagID, f.agents[tenant], "OWN-"+tenant)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return actor
}

func seedCompleteSourceRows(t *testing.T, source flowstore.Store, tenant, agent string, at time.Time, lane int) {
	t.Helper()
	const batch = 5000
	for part := 0; part < completeSourceParts; part++ {
		for offset := 0; offset < completeSourcePartRows; offset += batch {
			rows := make([]flowstore.Row, 0, batch)
			for n := offset; n < offset+batch; n++ {
				value := uint64(100 + lane)
				if n == 0 {
					value = 9007199254740993 + uint64(lane)
				}
				rows = append(rows, flowstore.Row{TenantID: tenant, AgentID: agent, Exporter: "192.0.2.10", Protocol: "ipfix", TS: at, StartTS: at.Add(-time.Second), SrcAddr: fmt.Sprintf("10.%d.%d.%d", part, n/256, n%256), DstAddr: "192.0.2.20", SrcPort: uint16(20000 + part), DstPort: 443, Transport: "tcp", Sampling: 1, Bytes: value, BytesScaled: value, Packets: 1, PacketsScaled: 1})
			}
			if err := source.Insert(t.Context(), rows); err != nil {
				t.Fatal("insert bounded complete source batch", err)
			}
		}
	}
}

func completeSourcePost[T any](t *testing.T, socket *httptest.Server, token, path string, input any) T {
	t.Helper()
	var result T
	data, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, socket.URL+path, bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/json")
	client := socket.Client()
	client.Timeout = 150 * time.Second
	response, err := client.Do(request)
	if err != nil {
		t.Fatal("complete source public request", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		t.Fatal("complete source publication refused", response.StatusCode, string(body))
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&result); err != nil {
		t.Fatal(err)
	}
	return result
}

func downloadCompleteSourceCSV(t *testing.T, socket *httptest.Server, token, id string) (string, string, int64) {
	t.Helper()
	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, socket.URL+"/v1/dashboard-report-artifacts/"+id, nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+token)
	client := socket.Client()
	client.Timeout = 150 * time.Second
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.Header.Get("Cache-Control") != "no-store" {
		t.Fatal("complete source download failed", response.StatusCode)
	}
	file, err := os.CreateTemp(t.TempDir(), "complete-source-*.csv")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	n, err := io.CopyBuffer(file, response.Body, make([]byte, 64<<10))
	if err != nil {
		t.Fatal(err)
	}
	if n != response.ContentLength {
		t.Fatal("complete source download length disagrees", n, response.ContentLength)
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	digest, err := crypto.HashReader(file)
	if err != nil {
		t.Fatal(err)
	}
	encoded := hex.EncodeToString(digest)
	if encoded != response.Header.Get("X-Report-SHA256") {
		t.Fatal("independent complete CSV digest disagrees")
	}
	return file.Name(), encoded, n
}

func verifyCompleteSourceCSV(t *testing.T, path, tenant string, refs []reportFlowSourceRef, lane int) {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	reader := csv.NewReader(file)
	reader.FieldsPerRecord = -1
	sourceParts := make(map[string]int, len(refs))
	for i, ref := range refs {
		sourceParts[ref.ID] = i
	}
	seen := make([]bool, completeSourceParts*completeSourcePartRows)
	part, details, totals := 0, 0, 0
	detailTable := false
	tagColumn, addressColumn, bytesColumn := -1, -1, -1
	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal("parse complete source CSV", err)
		}
		if len(record) == 0 {
			continue
		}
		if record[0] == "table_tenant_scope" && (len(record) != 2 || record[1] != tenant) {
			t.Fatal("complete CSV section crossed tenant scope")
		}
		if record[0] == "table_id" {
			if len(record) != 2 {
				t.Fatal("invalid complete source section")
			}
			segments := strings.Split(record[1], "/")
			var ok bool
			part, ok = sourceParts[segments[0]]
			if !ok {
				t.Fatal("complete CSV has an unselected source")
			}
			detailTable = strings.HasSuffix(record[1], "/detail")
			continue
		}
		if detailTable && record[0] == "record_type" {
			tagColumn, addressColumn, bytesColumn = -1, -1, -1
			for i, name := range record {
				switch name {
				case "tag.role":
					tagColumn = i
				case "src_addr":
					addressColumn = i
				case "bytes:total":
					bytesColumn = i
				}
			}
			if tagColumn < 0 || addressColumn < 0 || bytesColumn < 0 {
				t.Fatal("complete source detail schema omitted selected fields")
			}
			continue
		}
		if !detailTable || record[0] != "detail" && record[0] != "totals" {
			continue
		}
		if tagColumn < 0 || addressColumn < 0 || bytesColumn < 0 {
			t.Fatal("complete source data preceded its schema")
		}
		if len(record) != 5 {
			t.Fatal("complete detail schema changed", len(record))
		}
		if record[0] == "totals" {
			expected := uint64(9007199254740993+lane) + uint64((completeSourcePartRows-1)*(100+lane))
			if record[bytesColumn] != strconv.FormatUint(expected, 10) {
				t.Fatal("complete source total lost exact integer precision")
			}
			totals++
			continue
		}
		address, err := netip.ParseAddr(record[addressColumn])
		if err != nil || !address.Is4() {
			t.Fatal("complete CSV invalid source address")
		}
		octets := address.As4()
		sequence := int(octets[2])*256 + int(octets[3])
		if octets[0] != 10 || int(octets[1]) != part || sequence >= completeSourcePartRows || record[tagColumn] != "OWN-"+tenant {
			t.Fatal("complete CSV source selection overlaps or crossed scope")
		}
		index := part*completeSourcePartRows + sequence
		if seen[index] {
			t.Fatal("complete CSV repeated a selected detail row")
		}
		seen[index] = true
		expected := uint64(100 + lane)
		if sequence == 0 {
			expected = 9007199254740993 + uint64(lane)
		}
		if record[bytesColumn] != strconv.FormatUint(expected, 10) {
			t.Fatal("complete CSV changed an exact detail integer")
		}
		details++
	}
	if details != len(seen) || totals != completeSourceParts {
		t.Fatal("complete CSV omitted selected detail rows or totals", details, totals)
	}
	for _, present := range seen {
		if !present {
			t.Fatal("complete CSV selected row absent")
		}
	}
}
