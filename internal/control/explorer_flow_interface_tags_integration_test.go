// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package control

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/ai"
	"github.com/ctlplne/probectl/internal/ai/mcp"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/objectstore"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowsnapshot"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tags"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/tenantcrypto"
	"github.com/ctlplne/probectl/internal/tenantlife"
)

// Real PostgreSQL/evidence writer/RLS/ABAC/shared encrypted cache; flow rows
// and the NetBox HTTP source are simulated. The separate required real source
// and ClickHouse proofs still do not replace the release/four-store receipt.
func TestExplorerInterfaceTagsUseAttestedIndicesUnderOwnedExporter(t *testing.T) {
	f := newTagImportSubjectFixture(t)
	rows := &snapshotAPISource{Memory: flowstore.NewMemory()}
	f.srv.WithFlowStore(rows)
	objects, err := objectstore.NewFS(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	key, err := crypto.Random(32)
	if err != nil {
		t.Fatal(err)
	}
	sealer, err := tenantcrypto.NewEnvelopeSealer("interface-tag-fixture", base64.StdEncoding.EncodeToString(key))
	crypto.Zeroize(key)
	if err != nil {
		t.Fatal(err)
	}
	tenantcrypto.SetPrimary(sealer)
	t.Cleanup(tenantcrypto.Reset)
	engine := tenantlife.New(f.db.Pool(), rows, objects, nil, nil, "test fixture has no backups", nil)
	f.srv.WithTenantLife(engine).WithFlowSnapshotStorage(FlowSnapshotStorage{
		Pool: f.db.Pool(), Objects: objects, Router: tenancy.PooledRouter{},
		Fence: tenancy.NewPostgresWriterFence(f.db.Pool()), Cache: flowsnapshot.Config{TempDir: t.TempDir()},
	})
	writePoll := func(tenant, configured string, withInput bool) {
		t.Helper()
		at := time.Now().UTC().Truncate(time.Microsecond)
		source := entity.SourceKey{AgentID: f.agents[tenant], Kind: entity.DeviceTarget, SourceRef: configured}
		claims := []entity.Observation{{ID: uuid(t), Source: source, Alias: entity.AliasKey{Kind: entity.AddressAlias, Value: "192.0.2.10"}, SourceRef: "snmp:configured-target", ObservedAt: at}}
		if withInput {
			claims = append(claims, entity.Observation{ID: uuid(t), Source: source, Alias: entity.AliasKey{Kind: entity.SNMPInterfaceAlias, Value: "7"}, SourceRef: "snmp:ifIndex:7", InterfaceName: "input-port", ObservedAt: at},
				entity.Observation{ID: uuid(t), Source: source, Alias: entity.AliasKey{Kind: entity.AddressAlias, Value: "192.0.2.10"}, SourceRef: "snmp:ifIndex:7", ObservedAt: at})
		}
		claims = append(claims, entity.Observation{ID: uuid(t), Source: source, Alias: entity.AliasKey{Kind: entity.SNMPInterfaceAlias, Value: "8"}, SourceRef: "snmp:ifIndex:8", InterfaceName: "output-port", ObservedAt: at})
		accepted, unresolved, err := writeEntityEvidenceBatchForTest(tenancy.WithTenant(t.Context(), tenancy.ID(tenant)), store.NewEntityRegistry(f.db.Pool()), f.agents[tenant], f.serials[tenant], claims)
		if err != nil || accepted != len(claims) || unresolved != 0 {
			t.Fatalf("current interface poll: %d/%d %v", accepted, unresolved, err)
		}
	}
	at := time.Now().UTC().Truncate(time.Minute).Add(-time.Minute)
	if err := rows.Insert(t.Context(), []flowstore.Row{
		{TenantID: f.a, TS: at, Exporter: "192.0.2.10", AgentID: f.agents[f.b], InIf: 7, OutIf: 8, BytesScaled: 100},
		{TenantID: f.a, TS: at, Exporter: "192.0.2.10", AgentID: f.agents[f.b], InIf: 0, OutIf: 0, BytesScaled: 200},
		{TenantID: f.b, TS: at, Exporter: "192.0.2.10", AgentID: f.agents[f.a], InIf: 7, OutIf: 8, BytesScaled: 900},
	}); err != nil {
		t.Fatal(err)
	}
	root := "/v1/entity-contexts/" + f.contextID
	rules := map[string]tags.Rule{}
	for _, tenant := range []string{f.a, f.b} {
		writePoll(tenant, "target", true)
		// Review and apply a source annotation before using it as a dimension.
		previewResponse := apiReq(t, f.srv.Handler(), http.MethodPost, root+"/tag-imports/netbox/preview", tenant, f.input(tenant, "interface"))
		var preview netBoxTagPreview
		if previewResponse.Code != http.StatusOK || json.Unmarshal(previewResponse.Body.Bytes(), &preview) != nil {
			t.Fatalf("interface preview: %d %s", previewResponse.Code, previewResponse.Body.String())
		}
		if applied := apiReq(t, f.srv.Handler(), http.MethodPost, root+"/tag-imports/netbox/apply", tenant, netBoxTagApplyRequest{Confirmed: true, Preview: preview}); applied.Code != http.StatusOK {
			t.Fatalf("interface reviewed import: %d %s", applied.Code, applied.Body.String())
		}
		created := apiReq(t, f.srv.Handler(), http.MethodPost, root+"/tag-rules", tenant, map[string]any{
			"tag_id": f.tagID, "target_kind": "interface", "match_kind": "snmp_field", "snmp_field": "if_name", "snmp_value": "output-port", "value": "rule-" + tenant,
		})
		var rule tags.Rule
		if created.Code != http.StatusCreated || json.Unmarshal(created.Body.Bytes(), &rule) != nil {
			t.Fatalf("interface rule: %d %s", created.Code, created.Body.String())
		}
		rules[tenant] = rule
	}
	plan := flow.QueryPlan{From: at.Add(-time.Minute), To: at.Add(time.Minute), GroupBy: []string{"tag.in_interface.role", "tag.out_interface.role"}, Metrics: []flow.QueryMetric{{Measure: "bytes", Calculation: "total", Role: "primary"}}}
	read := func(tenant string, selected flow.QueryPlan) explorerResult {
		t.Helper()
		response := apiReq(t, f.srv.Handler(), http.MethodPost, "/v1/explorer/query", tenant, ai.ExplorerQuery{Source: ai.ExplorerFlow, Flow: &selected})
		var out explorerResult
		if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &out) != nil || out.Flow == nil {
			t.Fatalf("interface native query: %d %s", response.Code, response.Body.String())
		}
		return out
	}
	check := func(tenant, input, output, total, matched string) {
		t.Helper()
		out := read(tenant, plan).Flow
		if out.Totals["bytes:total"] != total {
			t.Fatalf("interface metadata changed raw traffic: %+v", out)
		}
		found := false
		for _, row := range out.Rows {
			if row.Metrics["bytes:total"] != matched {
				continue
			}
			found = true
			if row.Group[plan.GroupBy[0]] != input || row.Group[plan.GroupBy[1]] != output {
				t.Fatalf("interface side/tenant/authority mismatch: %+v", row)
			}
		}
		if !found {
			t.Fatalf("expected interface group %s missing: %+v", matched, out)
		}
	}
	check(f.a, "import-7", "rule-"+f.a, "300", "100")
	check(f.b, "import-8", "rule-"+f.b, "900", "900")
	// A rule edit retags the same old rows; no flow insert is performed here.
	rule := rules[f.a]
	updated := apiReq(t, f.srv.Handler(), http.MethodPut, root+"/tag-rules/"+rule.ID, f.a, map[string]any{
		"tag_id": f.tagID, "target_kind": "interface", "match_kind": "snmp_field", "snmp_field": "if_name", "snmp_value": "output-port", "value": "changed-" + f.a,
	})
	if updated.Code != http.StatusOK {
		t.Fatalf("interface rule history edit: %d %s", updated.Code, updated.Body.String())
	}
	check(f.a, "import-7", "changed-"+f.a, "300", "100")
	if err := tenancy.InTenant(tenancy.WithTenant(t.Context(), tenancy.ID(f.a)), f.db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
		_, err := (store.TagAssignments{}).CreateManual(ctx, sc, store.ManualTagAssignmentInput{Scope: tags.Scope{TenantID: f.a, ContextID: f.contextID}, TagID: f.tagID, TargetKind: "interface", TargetID: f.interfaces[f.a], Value: "manual-" + f.a})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	check(f.a, "manual-"+f.a, "changed-"+f.a, "300", "100")
	p := &auth.Principal{TenantID: f.a, UserID: "dev", Permissions: map[string]bool{permAIQuery: true, permFlowRead: true, permTagsRead: true, "metrics.read": true}}
	backend := nativeMCPFlowBackend{f.srv}
	if result, err := backend.FlowQuery(t.Context(), p, plan); err != nil || len(result.Flow.Rows) != 2 {
		t.Fatalf("native MCP interface query: %v", err)
	}
	delete(p.Permissions, "metrics.read")
	if _, err := backend.FlowQuery(t.Context(), p, plan); err == nil {
		t.Fatal("interface query bypassed source grant")
	}
	p.Permissions["metrics.read"] = true
	paged := plan
	paged.PageSize = 1
	frozen := read(f.a, paged)
	if frozen.FlowPaging == nil || !frozen.FlowPaging.More {
		t.Fatal("interface query did not create frozen continuation")
	}
	comparison, err := backend.FlowCompare(t.Context(), p, mcp.NativeFlowCompareInput{Plan: paged, PreviousFrom: at.Add(-2 * time.Hour), PreviousTo: at.Add(-time.Hour)})
	if err != nil || comparison.Paging == nil || !comparison.Paging.More {
		t.Fatalf("interface comparison continuation: %v", err)
	}
	var policy *auth.Policy
	if err := tenancy.InTenant(tenancy.WithTenant(t.Context(), tenancy.ID(f.a)), f.db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
		var err error
		policy, err = (store.ABACPolicies{}).Create(ctx, sc, auth.Policy{Name: "withhold interface context", Enabled: true, Effect: auth.PolicyDeny, Permission: "metrics.read", Resource: map[string]string{"context_id": f.contextID}, Priority: 100})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	f.srv.abac.invalidate(f.a)
	check(f.a, "", "", "300", "300")
	check(f.b, "import-8", "rule-"+f.b, "900", "900")
	if denied := apiReq(t, f.srv.Handler(), http.MethodPost, "/v1/explorer/query", f.a, ai.ExplorerQuery{Source: ai.ExplorerFlow, Flow: &flow.QueryPlan{Cursor: frozen.FlowPaging.NextCursor}}); denied.Code != http.StatusForbidden {
		t.Fatal("interface context deny exposed frozen REST page")
	}
	if _, err := backend.FlowPage(t.Context(), p, frozen.FlowPaging.NextCursor); err == nil {
		t.Fatal("interface context deny exposed frozen MCP page")
	}
	if _, err := backend.FlowComparisonPage(t.Context(), p, comparison.Paging.NextCursor); err == nil {
		t.Fatal("interface context deny exposed comparison continuation")
	}
	for _, id := range []string{frozen.FlowPaging.SnapshotID, comparison.Paging.SnapshotID} {
		if denied := apiReq(t, f.srv.Handler(), http.MethodGet, "/v1/explorer/flow-snapshots/"+id+"/csv", f.a, nil); denied.Code != http.StatusForbidden || strings.Contains(denied.Body.String(), "manual-") {
			t.Fatal("interface context deny exposed CSV")
		}
	}
	if err := tenancy.InTenant(tenancy.WithTenant(t.Context(), tenancy.ID(f.a)), f.db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
		return (store.ABACPolicies{}).Delete(ctx, sc, policy.ID)
	}); err != nil {
		t.Fatal(err)
	}
	f.srv.abac.invalidate(f.a)
	// A second current canonical ID at the same device/index must withhold,
	// even when that competing interface has no annotation.
	if err := tenancy.InTenant(tenancy.WithTenant(t.Context(), tenancy.ID(f.a)), f.db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
		return store.NewEntityRegistry(f.db.Pool()).AssignEntitySource(ctx, sc, entity.SourceKey{AgentID: f.agents[f.a], Kind: entity.DeviceTarget, SourceRef: "target-second"}, f.contextID, f.device)
	}); err != nil {
		t.Fatal(err)
	}
	writePoll(f.a, "target-second", true)
	check(f.a, "", "", "300", "300") // Both 7 and 8 now have competing current IDs.
	if _, err := f.db.Pool().Exec(t.Context(), `UPDATE entity_source_contexts SET expires_at=transaction_timestamp() WHERE tenant_id=$1 AND agent_id=$2 AND source_kind='device_target' AND source_ref='target-second'`, f.a, f.agents[f.a]); err != nil {
		t.Fatal(err)
	}
	check(f.a, "manual-"+f.a, "changed-"+f.a, "300", "100")
	writePoll(f.a, "target", false)
	check(f.a, "", "changed-"+f.a, "300", "100")
	check(f.b, "import-8", "rule-"+f.b, "900", "900")
	// The annotation persists; omission rather than deletion stopped its use.
	var retained int
	if err := f.db.Pool().QueryRow(t.Context(), `SELECT count(*) FROM tenant_tag_assignments WHERE tenant_id=$1 AND target_kind='interface' AND entity_id=$2 AND source='manual'`, f.a, f.interfaces[f.a]).Scan(&retained); err != nil || retained != 1 {
		t.Fatal("current poll proof deleted the old annotation")
	}
	if _, err := f.db.Pool().Exec(t.Context(), `UPDATE agent_identities SET revoked_at=now() WHERE tenant_id=$1 AND agent_id=$2 AND spiffe_id=$3`, f.a, f.agents[f.a], crypto.EntitySPIFFEID(f.a, f.agents[f.a])); err != nil {
		t.Fatal(err)
	}
	check(f.a, "", "", "300", "300")
}
