// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package cmdb

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/store/migrate"
	"github.com/ctlplne/probectl/internal/tags"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport"
	"github.com/ctlplne/probectl/internal/testsupport/chtest"
	"github.com/ctlplne/probectl/migrations"
)

// Real source, RLS storage and policy-reader query composition. Operator
// bindings/flow rows are explicit fixtures; this is not the release/bus receipt.
func liveNetBoxStoredPrefixProof(t *testing.T, resolver *Resolver, prefixes map[string]string) {
	t.Helper()
	ctx := t.Context()
	if os.Getenv("GITHUB_ACTIONS") != "true" {
		t.Fatal("source/store/query proof runs only in its owned CI fixtures")
	}
	if os.Getenv("PROBECTL_DATABASE_URL") == "" || os.Getenv("PROBECTL_FLOWSTORE_URL") == "" {
		t.Fatal("required source/store/query services are not configured")
	}
	pool, err := pgxpool.New(ctx, testsupport.PostgresDSN())
	if err != nil {
		t.Fatal("required product database configuration is invalid")
	}
	t.Cleanup(pool.Close)
	if err := pool.Ping(ctx); err != nil {
		t.Fatal("required product database is unavailable")
	}
	if _, err := migrate.New(migrations.FS, nil).Apply(ctx, pool); err != nil {
		t.Fatal("required product schema could not migrate")
	}
	testsupport.LockPostgresPublicCatalog(t, pool)
	var created []string
	t.Cleanup(func() {
		if _, err := pool.Exec(context.Background(), `DELETE FROM tenants WHERE id=ANY($1::uuid[])`, created); err != nil {
			t.Error("source/query fixture tenant cleanup failed")
		}
	})
	contextID, prefixID, roleID, customerID := uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString()
	tenants := map[string]string{"a": netBoxTenantA, "b": netBoxTenantB}
	rules := map[string]tags.Rule{}
	fallbacks := map[string]tags.Rule{}
	mutate := func(tenant string, fn func(context.Context, tenancy.Scope) error) {
		t.Helper()
		if err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenant)), pool, fn); err != nil {
			t.Fatalf("owned metadata transaction failed: %v", err)
		}
	}
	for _, lane := range []string{"a", "b"} {
		tenant := tenants[lane]
		if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,slug,name) VALUES ($1,$2,$3)`, tenant, "netbox-query-"+lane, "NetBox query "+lane); err != nil {
			t.Fatal("owned source/query tenant could not be created")
		}
		created = append(created, tenant)
		mutate(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			agent := uuid.NewString()
			for _, statement := range []struct {
				sql  string
				args []any
			}{
				{`INSERT INTO entity_contexts(tenant_id,id,site_id,vrf_id,site_label,vrf_label) VALUES ($1,$2,$3,$4,'source-site','source-vrf')`, []any{tenant, contextID, uuid.NewString(), uuid.NewString()}},
				{`INSERT INTO entity_agent_contexts(tenant_id,agent_id,context_id) VALUES ($1,$2,$3)`, []any{tenant, agent, contextID}},
				{`INSERT INTO entity_source_contexts(tenant_id,agent_id,source_kind,source_ref,context_id) VALUES ($1,$2,'flow_exporter','192.0.2.10',$3)`, []any{tenant, agent, contextID}},
				{`INSERT INTO entities(tenant_id,context_id,id,kind,label,network_prefix) VALUES ($1,$2,$3,'prefix','explicit-source-prefix','192.0.2.0/24')`, []any{tenant, contextID, prefixID}},
				{`INSERT INTO tenant_tag_definitions(tenant_id,id,key) VALUES ($1,$2,'role'),($1,$3,'customer')`, []any{tenant, roleID, customerID}},
			} {
				if _, err := sc.Q.Exec(ctx, statement.sql, statement.args...); err != nil {
					return err
				}
			}
			fallback, err := (store.TagRules{}).Create(ctx, sc, tags.Rule{Scope: tags.Scope{TenantID: tenant, ContextID: contextID}, TagID: roleID, TargetKind: "prefix", Match: "cidr", AddressSide: "prefix", CIDR: "192.0.2.0/24", Value: "fallback-" + tenant})
			if err != nil {
				return err
			}
			fallbacks[tenant] = fallback
			if _, err := audit.TenantAppend(ctx, sc, "netbox-query-fixture", "tag.rule.created", fallback.ID, map[string]any{"context_id": contextID}); err != nil {
				return err
			}
			rule, err := (store.TagRules{}).Create(ctx, sc, tags.Rule{Scope: tags.Scope{TenantID: tenant, ContextID: contextID}, TagID: customerID, TargetKind: "prefix", Match: "cidr", AddressSide: "prefix", CIDR: "192.0.2.0/24", Value: "rule-old-" + tenant})
			if err != nil {
				return err
			}
			rules[tenant] = rule
			_, err = audit.TenantAppend(ctx, sc, "netbox-query-fixture", "tag.rule.created", rule.ID, map[string]any{"context_id": contextID})
			return err
		})
	}
	endpoint := os.Getenv("PROBECTL_FLOWSTORE_URL")
	ch, err := flowstore.NewClickHouse(endpoint, 0)
	if err != nil {
		t.Fatal("required product ClickHouse could not initialize")
	}
	t.Cleanup(func() { _ = ch.Close() })
	user, reader := chtest.ProvisionReader(t, endpoint, "netbox_prefix")
	ch.WithTenantScoping(true).WithReader(reader)
	if err := ch.EnsureReaderRowPolicy(ctx, user); err != nil {
		t.Fatal("required query row policy could not initialize")
	}
	if err := ch.VerifyReaderIsolation(ctx, user); err != nil {
		t.Fatal("required query row policy could not be verified")
	}
	t.Cleanup(func() {
		for _, tenant := range created {
			if _, err := ch.DeleteTenant(context.Background(), tenant); err != nil {
				t.Error("source/query flow cleanup failed")
			}
		}
	})
	memory := flowstore.NewMemory()
	at := time.Now().UTC().Truncate(time.Minute).Add(-time.Minute)
	for i, lane := range []string{"a", "b"} {
		row := flowstore.Row{TenantID: tenants[lane], AgentID: "untrusted-sender", TS: at, StartTS: at.Add(-time.Second), Exporter: "192.0.2.10", SrcAddr: "192.0.2.20", DstAddr: "192.0.2.200", Protocol: "ipfix", BytesScaled: uint64(100 * (1 + i*8)), PacketsScaled: 1}
		unknown := row
		unknown.Exporter, unknown.BytesScaled = "192.0.2.11", row.BytesScaled*2
		for _, backend := range []flowstore.Store{ch, memory} {
			if err := backend.Insert(ctx, []flowstore.Row{row, unknown}); err != nil {
				t.Fatal("owned flow inputs could not be inserted")
			}
		}
	}
	revisions := map[string]int64{}
	prove := func(phase string, imported, edited bool) {
		t.Helper()
		for i, lane := range []string{"a", "b"} {
			tenant := tenants[lane]
			owned := tenancy.WithTenant(ctx, tenancy.ID(tenant))
			snapshot, err := store.NewTagSnapshots(pool).LoadTenant(owned, 4<<20, "prefix")
			if err != nil {
				t.Fatalf("current owned prefix snapshot failed: %v", err)
			}
			revision, err := snapshot.Revision()
			if err != nil || revision <= revisions[tenant] {
				t.Fatal("fresh historical query reused an old metadata revision")
			}
			revisions[tenant] = revision
			definitions, err := snapshot.Definitions()
			if err != nil {
				t.Fatal(err)
			}
			allowed := map[string]bool{contextID: true}
			roots, err := snapshot.ProjectAuthorizedExportersContext(owned, allowed, 4<<20, map[string]map[string]bool{"prefix": allowed})
			if err != nil {
				t.Fatal(err)
			}
			ranges, err := snapshot.ProjectAuthorizedPrefixesContext(owned, allowed, allowed, 4<<20)
			if err != nil {
				t.Fatal(err)
			}
			lookup, err := flowstore.NewTagQueryData(tenant, revision, definitions, roots, 4<<20, flowstore.TagQuerySources{Context: owned, Prefixes: ranges})
			if err != nil {
				t.Fatal(err)
			}
			customer, role := "rule-old-"+tenant, "fallback-"+tenant
			if edited {
				customer = "rule-new-" + tenant
			}
			if imported {
				role = "ipam-role-" + lane
			}
			rootContext := len(roots) == 1 && roots[0].ContextID == contextID && roots[0].Exporter == "192.0.2.10" && len(roots[0].Values) == 0
			rangeScope := len(ranges) == 1 && ranges[0].TenantID == tenant && ranges[0].ContextID == contextID && ranges[0].ID == prefixID
			snapshotRole, snapshotCustomer := false, false
			if rangeScope {
				snapshotRole, snapshotCustomer = ranges[0].Values["role"] == role, ranges[0].Values["customer"] == customer
			}
			t.Logf("prefix source checkpoint phase=%s imported=%t edited=%t roots=%d ranges=%d root_context=%t range_scope=%t role_match=%t customer_match=%t", phase, imported, edited, len(roots), len(ranges), rootContext, rangeScope, snapshotRole, snapshotCustomer)
			count := uint64(100 * (1 + i*8))
			for _, source := range []string{"raw", "rollup"} {
				plan := flow.QueryPlan{From: at.Add(-time.Minute), To: at.Add(time.Minute), View: "table", DataSeries: source,
					GroupBy: []string{"tag.src_prefix.role", "tag.dst_prefix.role", "tag.src_prefix.customer", "tag.dst_prefix.customer"},
					Metrics: []flow.QueryMetric{{Measure: "bytes", Calculation: "total", Role: "primary"}}}
				referencePlan := plan
				referencePlan.DataSeries = "raw"
				reference, err := memory.ExplorePlan(owned, flowstore.PlanQuery{TenantID: tenant, Plan: referencePlan, Tags: lookup})
				if err != nil {
					t.Fatal("owned prefix memory reference could not execute")
				}
				result, err := ch.ExplorePlan(owned, flowstore.PlanQuery{TenantID: tenant, Plan: plan, Tags: lookup})
				if err != nil || result.Source != source || len(result.Rows) != 2 || result.Totals["bytes:total"] != strconv.FormatUint(count*3, 10) || result.TagTenantID != tenant || result.TagRevision != revision || result.TagIDs["tag.src_prefix.role"] != roleID || result.TagIDs["tag.dst_prefix.customer"] != customerID {
					t.Fatalf("real-source historical query lost exact owned totals: %s %v", source, err)
				}
				for _, row := range result.Rows {
					wantRole, wantCustomer := role, customer
					if row.Metrics["bytes:total"] == strconv.FormatUint(count*2, 10) {
						wantRole, wantCustomer = "", ""
					} else if row.Metrics["bytes:total"] != strconv.FormatUint(count, 10) {
						t.Fatal("real-source join multiplied or crossed flow rows")
					}
					for _, side := range []string{"src_prefix", "dst_prefix"} {
						if row.Group["tag."+side+".role"] != wantRole || row.Group["tag."+side+".customer"] != wantCustomer {
							t.Fatalf("real-source import/rule selected foreign or unknown-exporter metadata: phase=%s imported=%t edited=%t source=%s side=%s known_row=%t role_equal=%t customer_equal=%t role_empty=%t customer_empty=%t reference_equal=%t snapshot_role=%t snapshot_customer=%t root_context=%t", phase, imported, edited, source, side, row.Metrics["bytes:total"] == strconv.FormatUint(count, 10), row.Group["tag."+side+".role"] == wantRole, row.Group["tag."+side+".customer"] == wantCustomer, row.Group["tag."+side+".role"] == "", row.Group["tag."+side+".customer"] == "", reflect.DeepEqual(result.Rows, reference.Rows), snapshotRole, snapshotCustomer, rootContext)
						}
					}
				}
				if !rootContext || !rangeScope || !snapshotRole || !snapshotCustomer || !reflect.DeepEqual(result.Rows, reference.Rows) || !reflect.DeepEqual(result.Totals, reference.Totals) {
					t.Fatal("real-source output lacks the current owned snapshot or independent reference")
				}
				if imported {
					plan.Filter = &flow.QueryFilterGroup{Conditions: []flow.QueryPredicate{{Field: "tag.src_prefix.role", Op: flow.QueryEqual, Values: []string{role}}}}
					filtered, err := ch.ExplorePlan(owned, flowstore.PlanQuery{TenantID: tenant, Plan: plan, Tags: lookup})
					if err != nil || len(filtered.Rows) != 1 || filtered.Totals["bytes:total"] != strconv.FormatUint(count, 10) {
						t.Fatal("actual imported prefix value did not filter exact historical traffic")
					}
				}
			}
			other := netBoxTenantA
			if tenant == other {
				other = netBoxTenantB
			}
			if _, err := ch.ExplorePlan(owned, flowstore.PlanQuery{TenantID: other, Plan: flow.QueryPlan{}, Tags: lookup}); err == nil {
				t.Fatal("foreign query accepted the source tenant snapshot")
			}
		}
	}
	prove("initial-rule", false, false)
	for _, lane := range []string{"a", "b"} {
		tenant := tenants[lane]
		owned := tenancy.WithTenant(ctx, tenancy.ID(tenant))
		var target store.NetBoxTagTarget
		var facts store.TagImportFacts
		if err := tenancy.InTenantReadSnapshot(owned, pool, func(ctx context.Context, sc tenancy.Scope) error {
			var err error
			target, facts, err = (store.TagAssignments{}).NetBoxSubjectTarget(ctx, sc, contextID, roleID, store.TagSubjectReference{Kind: "prefix", ID: prefixID}, 4<<20)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		other := "a"
		if lane == other {
			other = "b"
		}
		if _, err := resolver.PreviewNetBoxSubjectTag(owned, NetBoxTagFacts{Prefix: facts.Prefix}, "role", prefixes[other]); err == nil {
			t.Fatal("foreign source prefix authorized a local reviewed import")
		}
		selected, err := resolver.PreviewNetBoxSubjectTag(owned, NetBoxTagFacts{Prefix: facts.Prefix}, "role", prefixes[lane])
		if err != nil || selected.Candidate().Value != "ipam-role-"+lane {
			t.Fatal("actual mapped source prefix preview failed")
		}
		fresh, err := resolver.RecheckNetBoxSubjectTag(owned, NetBoxTagFacts{Prefix: facts.Prefix}, selected.Candidate())
		if err != nil || fresh.Candidate() != selected.Candidate() {
			t.Fatal("actual mapped source prefix changed before reviewed apply")
		}
		mutate(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			candidate := fresh.Candidate()
			record, err := (store.TagAssignments{}).ApplyNetBoxTag(ctx, sc, target, candidate.Value, candidate.SourceRef, 4<<20,
				func(current store.TagImportFacts) bool { return fresh.Matches(NetBoxTagFacts{Prefix: current.Prefix}) })
			if err != nil {
				return err
			}
			if record.Source != "netbox" || record.ReviewedAt == nil || record.Value != "ipam-role-"+lane {
				return errors.New("persisted source annotation lost reviewed provenance")
			}
			_, err = audit.TenantAppend(ctx, sc, "netbox-query-fixture", "tag.assignment.imported", record.ID, map[string]any{"source": "netbox", "context_id": contextID})
			return err
		})
	}
	// A reviewed source value remains an imported suggestion: the matching
	// operator rule wins until it is deliberately removed. Both observations
	// use the same historical traffic and preserve exact counters.
	prove("reviewed-import-under-rule", false, false)
	for _, lane := range []string{"a", "b"} {
		tenant := tenants[lane]
		mutate(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			rule := fallbacks[tenant]
			if err := (store.TagRules{}).Delete(ctx, sc, contextID, rule.ID); err != nil {
				return err
			}
			_, err := audit.TenantAppend(ctx, sc, "netbox-query-fixture", "tag.rule.deleted", rule.ID, map[string]any{"context_id": contextID})
			return err
		})
	}
	prove("reviewed-import-exposed", true, false)
	for _, lane := range []string{"a", "b"} {
		tenant := tenants[lane]
		mutate(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			rule := rules[tenant]
			rule.Value = "rule-new-" + tenant
			changed, err := (store.TagRules{}).Update(ctx, sc, rule)
			if err != nil {
				return err
			}
			_, err = audit.TenantAppend(ctx, sc, "netbox-query-fixture", "tag.rule.updated", changed.ID, map[string]any{"context_id": contextID})
			return err
		})
	}
	prove("customer-rule-edited", true, true)
	// Keep the network/address witness private; only source/proof outcomes and
	// the exact checked-out candidate go to the retained nonsecret receipt.
	head, err := exec.CommandContext(ctx, "git", "rev-parse", "HEAD").Output()
	if err != nil || len(strings.TrimSpace(string(head))) != 40 {
		t.Fatal("cannot bind source/query receipt to its candidate")
	}
	proof := struct {
		Candidate string   `json:"candidate_sha"`
		Scope     string   `json:"scope"`
		Checks    []string `json:"checks"`
	}{strings.TrimSpace(string(head)), "real NetBox, product RLS and ClickHouse component; release/bus receipt remains required", []string{"paired same-ID tenant prefixes", "fresh attested reviewed import and audit", "matching rule wins before audited removal exposes reviewed import", "rule and imported dimensions over identical historical inputs", "raw and complete retained exact counters and filters", "unknown exporter and foreign snapshot refuse metadata", "rule edit re-tags history without rewriting telemetry"}}
	raw, err := json.MarshalIndent(proof, "", "  ")
	if err != nil {
		t.Fatal("cannot encode the nonsecret source/query receipt")
	}
	liveNetBoxWriteReceipt(t, "source-query-proof.json", raw)
}

// Atomic publication never follows a pre-existing destination symlink. The
// existing CI fixture creates its private directory before any source proof.
func liveNetBoxWriteReceipt(t *testing.T, name string, payload []byte) {
	t.Helper()
	if name != "source-query-proof.json" && name != "provider-proof.json" {
		t.Fatal("unknown source receipt name")
	}
	const directory = "/tmp/probectl-qa-beta-netbox"
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		t.Fatal("source receipt directory is not private")
	}
	file, err := os.CreateTemp(directory, ".receipt-*")
	if err != nil {
		t.Fatal("cannot create a private source receipt")
	}
	temporary := file.Name()
	defer os.Remove(temporary)
	defer file.Close()
	if _, err := file.Write(append(payload, '\n')); err != nil {
		t.Fatal("cannot write source receipt")
	}
	if err := file.Sync(); err != nil {
		t.Fatal("cannot flush source receipt")
	}
	if err := file.Close(); err != nil {
		t.Fatal("cannot close source receipt")
	}
	if err := os.Rename(temporary, filepath.Join(directory, name)); err != nil {
		t.Fatal("cannot publish source receipt")
	}
}
