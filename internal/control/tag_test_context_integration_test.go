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
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/otel"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tags"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// The caller owns the real authenticated TLS MCP client, consent/audit path
// and public-catalog lock. This is PG/API/native/cache component evidence;
// release binaries, senders and the four-store receipt remain required.
func proveTestTagContextFromResults(t *testing.T, core *Server, pool *pgxpool.Pool, tenants []string, contextID string, native func(string, any, bool) json.RawMessage) {
	t.Helper()
	ctx := t.Context()
	definition, wideDefinition := uuid.NewString(), uuid.NewString()
	ids := map[string]string{}
	rules := map[string]tags.Rule{}
	wants := map[string]string{}
	wideValue := strings.Repeat("🌐", tags.MaxValueCharacters)
	latest := NewLatestResults(16)
	core.WithLatestResults(latest)
	cleanup := func() {
		for _, tenant := range tenants {
			if err := tenancy.InTenant(tenancy.WithTenant(context.Background(), tenancy.ID(tenant)), pool, func(ctx context.Context, sc tenancy.Scope) error {
				if _, err := sc.Q.Exec(ctx, `DELETE FROM tenant_tag_definitions WHERE tenant_id=$1 AND id=ANY($2::uuid[])`, tenant, []string{definition, wideDefinition}); err != nil {
					return err
				}
				if ids[tenant] == "" {
					return nil
				}
				_, err := sc.Q.Exec(ctx, `DELETE FROM tests WHERE tenant_id=$1 AND id=$2`, tenant, ids[tenant])
				return err
			}); err != nil {
				t.Error("owned test context fixture cleanup failed")
			}
		}
	}
	t.Cleanup(cleanup)
	defer cleanup()
	for _, tenant := range tenants {
		ids[tenant], wants[tenant] = uuid.NewString(), "owned-"+tenant
		if err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenant)), pool, func(ctx context.Context, sc tenancy.Scope) error {
			if _, err := sc.Q.Exec(ctx, `INSERT INTO tests(tenant_id,id,name,target) VALUES ($1,$2,'same-probe','https://192.0.2.10/health')`, tenant, ids[tenant]); err != nil {
				return err
			}
			if err := store.NewEntityRegistry(pool).AssignPathTestContext(ctx, sc, ids[tenant], contextID); err != nil {
				return err
			}
			if _, err := sc.Q.Exec(ctx, `INSERT INTO tenant_tag_definitions(tenant_id,id,key) VALUES ($1,$2,'test_customer'),($1,$3,'test_site')`, tenant, definition, wideDefinition); err != nil {
				return err
			}
			rule, err := (store.TagRules{}).Create(ctx, sc, tags.Rule{Scope: tags.Scope{TenantID: tenant, ContextID: contextID}, TagID: definition, TargetKind: "test", Match: "name_pattern", NamePattern: "^same-probe$", Value: wants[tenant]})
			if err != nil {
				return err
			}
			rules[tenant] = rule
			_, err = (store.TagRules{}).Create(ctx, sc, tags.Rule{Scope: tags.Scope{TenantID: tenant, ContextID: contextID}, TagID: wideDefinition, TargetKind: "test", Match: "name_pattern", NamePattern: "^same-probe$", Value: wideValue})
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	for lane, tenant := range tenants {
		foreign := tenants[1-lane]
		for i, id := range []string{ids[tenant], ids[foreign], ""} {
			latest.Record(tenant, ResultView{AgentID: []string{"owned-fixture", "untrusted-claim", "legacy"}[i], Type: "http", Target: "https://192.0.2.10/health", Success: true, ObservedAt: time.Now().UTC().Add(-time.Hour), Metrics: map[string]float64{"http.total.ms": 42}, Attributes: map[string]string{otel.AttrTestID: id}})
		}
	}
	before := map[string][]ResultView{}
	inputFor := func(tenant string) tags.TestContextInput {
		t.Helper()
		rec := apiReq(t, core.Handler(), http.MethodGet, "/v1/results/latest", tenant, nil)
		var response struct {
			Items []ResultView `json:"items"`
		}
		if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &response) != nil || len(response.Items) != 3 {
			t.Fatal("test metadata proof did not read actual tenant result-cache IDs")
		}
		input := tags.TestContextInput{TestIDs: []string{}}
		for _, row := range response.Items {
			if id := row.Attributes[otel.AttrTestID]; id != "" {
				input.TestIDs = append(input.TestIDs, id)
			}
		}
		return input
	}
	read := func(tenant string, visible bool) tags.TestContextResolution {
		t.Helper()
		input := inputFor(tenant)
		input.TestIDs = append(input.TestIDs, ids[tenant], uuid.NewString(), "https://192.0.2.10/health")
		rec := apiReq(t, core.Handler(), http.MethodPost, "/v1/tags/tests/resolve", tenant, input)
		var out, nativeOut tags.TestContextResolution
		if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &out) != nil || out.TagRevision == "" || out.AsOf == "" {
			t.Fatal("public test context read failed")
		}
		if json.Unmarshal(native(tenant, input, true), &nativeOut) != nil || nativeOut.TagRevision != out.TagRevision || nativeOut.AsOf == "" || len(nativeOut.Items) != len(out.Items) {
			t.Fatal("actual native test context lost the shared snapshot contract")
		}
		if !visible {
			if len(out.Items) != 0 {
				t.Fatal("current context deny disclosed test metadata")
			}
			return out
		}
		if len(out.Items) != 1 || out.Items[0].TargetID != ids[tenant] || out.Items[0].ContextID != contextID || out.Items[0].TagRevision != out.TagRevision || out.Items[0].AsOf != out.AsOf || len(out.Items[0].Items) != 2 || !reflect.DeepEqual(out.Items[0].Items, nativeOut.Items[0].Items) || nativeOut.Items[0].TargetID != ids[tenant] {
			t.Fatal("test context crossed ownership, duplicated IDs or drifted between transports")
		}
		values := map[string]string{}
		for _, item := range out.Items[0].Items {
			values[item.Key] = item.Value
		}
		if values["test_customer"] != wants[tenant] || values["test_site"] != wideValue || strings.Contains(rec.Body.String(), "192.0.2.10") || strings.Contains(rec.Body.String(), "same-probe") {
			t.Fatal("test context lost exact wide/current values or exposed private facts")
		}
		return out
	}
	for _, tenant := range tenants {
		before[tenant] = latest.List(tenant)
		original := read(tenant, true)
		for _, withheld := range []string{permTagsRead, "test.read"} {
			body, err := json.Marshal(inputFor(tenant))
			if err != nil {
				t.Fatal(err)
			}
			req := httptest.NewRequest(http.MethodPost, "/v1/tags/tests/resolve", strings.NewReader(string(body)))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Probectl-Tenant", tenant)
			req.Header.Set(testWithholdPermissionsHeader, withheld)
			rec := httptest.NewRecorder()
			core.Handler().ServeHTTP(rec, req)
			if rec.Code != http.StatusForbidden || strings.Contains(rec.Body.String(), wants[tenant]) {
				t.Fatal("missing global test/tag read grant disclosed metadata")
			}
		}
		for _, hint := range []string{"tenant_id", "context_id", "name", "target", "addresses"} {
			input := map[string]any{"test_ids": []string{ids[tenant]}, hint: "forged"}
			if rec := apiReq(t, core.Handler(), http.MethodPost, "/v1/tags/tests/resolve", tenant, input); rec.Code != http.StatusBadRequest {
				t.Fatal("public test context accepted a scope or fact hint")
			}
			native(tenant, input, false)
		}
		wants[tenant] = "changed-" + tenant
		if err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenant)), pool, func(ctx context.Context, sc tenancy.Scope) error {
			rule := rules[tenant]
			rule.Value = wants[tenant]
			_, err := (store.TagRules{}).Update(ctx, sc, rule)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		fresh := read(tenant, true)
		oldRevision, oldErr := strconv.ParseInt(original.TagRevision, 10, 64)
		newRevision, newErr := strconv.ParseInt(fresh.TagRevision, 10, 64)
		if oldErr != nil || newErr != nil || newRevision <= oldRevision || !reflect.DeepEqual(before[tenant], latest.List(tenant)) {
			t.Fatal("current rule did not retag unchanged historical result IDs")
		}
	}
	var policyID string
	if err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenants[0])), pool, func(ctx context.Context, sc tenancy.Scope) error {
		policy, err := (store.ABACPolicies{}).Create(ctx, sc, auth.Policy{Name: "deny current test tags", Enabled: true, Effect: auth.PolicyDeny, Permission: "test.read", Resource: map[string]string{"context_id": contextID}, Priority: 100})
		if err == nil {
			policyID = policy.ID
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	core.abac.invalidate(tenants[0])
	read(tenants[0], false)
	read(tenants[1], true)
	if err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenants[0])), pool, func(ctx context.Context, sc tenancy.Scope) error {
		return (store.ABACPolicies{}).Delete(ctx, sc, policyID)
	}); err != nil {
		t.Fatal(err)
	}
	core.abac.invalidate(tenants[0])
}
