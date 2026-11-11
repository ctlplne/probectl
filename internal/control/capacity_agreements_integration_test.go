// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration || isolation

package control

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/cli"
	"github.com/ctlplne/probectl/internal/fairness"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/pkg/sdk"
)

// Actual TLS PostgreSQL/application-role RLS and verified HTTPS/current bearer
// auth. Source inventory is modeled; this is financial configuration, not a
// counter, physical sender, forecast or full silo acceptance proof.
func TestCapacityAgreementAPIKeepsCurrentFinancialAuthorityAndTenantStorage(t *testing.T) {
	f := newRoleExplanationAPIFixture(t)
	f.server.cfg.FlowQueryLibraryBytes = 256 << 20
	f.server.WithFairness(fairness.NewGate(fairness.DefaultPolicy(), nil))
	grant := func(tenant, permission string, present bool) {
		t.Helper()
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			if present {
				return (store.Roles{}).AddPermission(ctx, sc, f.roles[tenant], permission)
			}
			_, err := sc.Q.Exec(ctx, `DELETE FROM role_permissions WHERE tenant_id=$1 AND role_id=$2 AND permission_key=$3`, tenant, f.roles[tenant], permission)
			return err
		})
	}
	for _, tenant := range f.tenants {
		grant(tenant, permFlowAgreementsRead, true)
		grant(tenant, permFlowAgreementsWrite, true)
	}
	socket := httptest.NewTLSServer(f.server.Handler())
	t.Cleanup(socket.Close)
	caFile := filepath.Join(t.TempDir(), "served-ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: socket.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	clients := map[string]*sdk.Client{}
	for _, tenant := range f.tenants {
		clients[tenant] = sdk.NewClient(socket.URL, sdk.WithHTTPClient(socket.Client()), sdk.WithToken(f.tokens[tenant]))
	}
	a, b := f.tenants[0], f.tenants[1]
	definition := sdk.CapacityAgreementDefinition{Name: "WAN terms", Reference: "recorded contract", ValidFrom: "2026-11-01T00:00:00.123456789Z", Target: sdk.CapacityTarget{Kind: "interface", ContextId: f.contextID, InterfaceId: f.interfaceID}, BillingDay: 31, Timezone: "Asia/Kathmandu", Direction: "max_directional_percentiles", Currency: "USD", CommitBps: "100000000000", UnitBps: "1000000", UnitPrice: "1.250000000000000001"}
	items := map[string]*sdk.CapacityAgreement{}
	for _, tenant := range f.tenants {
		item, err := clients[tenant].CreateCapacityAgreement(t.Context(), sdk.CreateCapacityAgreementRequest{Body: &sdk.CapacityAgreementInput{Definition: definition}})
		if err != nil || item == nil || item.Version != "1" || !item.TargetPresent || !reflect.DeepEqual(item.Definition, definition) {
			t.Fatal("actual financial create lost exact terms or canonical tenant reference", tenant, item, err)
		}
		items[tenant] = item
		var stdout, stderr bytes.Buffer
		getenv := func(key string) string {
			return map[string]string{"PROBECTL_API_URL": socket.URL, "PROBECTL_API_TOKEN": f.tokens[tenant], "PROBECTL_CA_FILE": caFile}[key]
		}
		if code := cli.RunWithStdin([]string{"--json", "capacity-agreements", "get", item.Id}, getenv, strings.NewReader(""), &stdout, &stderr); code != 0 {
			t.Fatal("actual financial CLI lost verified TLS/current authority", code, stderr.String())
		}
		var native flow.CapacityAgreement
		if err := json.Unmarshal(stdout.Bytes(), &native); err != nil || native.ID != item.Id || native.Definition.UnitPrice != definition.UnitPrice || native.Definition.ValidFrom != definition.ValidFrom {
			t.Fatal("actual CLI altered exact financial terms", err)
		}
	}
	request := func(tenant, method, path, body string) (int, []byte) {
		t.Helper()
		r, err := http.NewRequestWithContext(t.Context(), method, socket.URL+path, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set("Authorization", "Bearer "+f.tokens[tenant])
		r.Header.Set("Content-Type", "application/json")
		response, err := socket.Client().Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		raw, err := io.ReadAll(response.Body)
		if err != nil {
			t.Fatal(err)
		}
		return response.StatusCode, raw
	}
	const base = "/v1/flows/capacity/agreements"
	limit := 1001
	for _, tenant := range f.tenants {
		page, err := clients[tenant].ListCapacityAgreements(t.Context(), sdk.ListCapacityAgreementsRequest{Limit: &limit})
		if err != nil || page == nil || len(page.Items) != 1 || page.Items[0].Id != items[tenant].Id || page.HasMore || page.Next != "" || page.AsOf == "" {
			t.Fatal("financial catalog lost its whole tenant page or imposed a fixed1000 cap", tenant, page, err)
		}
		other := a
		if tenant == a {
			other = b
		}
		for _, suffix := range []string{"", "/revisions"} {
			if status, _ := request(tenant, http.MethodGet, base+"/"+items[other].Id+suffix, ""); status != http.StatusNotFound {
				t.Fatal("foreign financial terms or revisions did not match unknown identity", status)
			}
		}
		if status, _ := request(tenant, http.MethodDelete, base+"/"+items[other].Id+"?version=1", ""); status != http.StatusNotFound {
			t.Fatal("foreign financial delete escaped tenant storage", status)
		}
	}
	revised := definition
	revised.ValidFrom, revised.UnitPrice = "2026-12-01T00:00:00.123456789Z", "2.500000000000000003"
	updated, err := clients[a].UpdateCapacityAgreement(t.Context(), sdk.UpdateCapacityAgreementRequest{Id: items[a].Id, Body: &sdk.CapacityAgreementInput{Version: "1", Definition: revised}})
	if err != nil || updated == nil || updated.Version != "2" || !reflect.DeepEqual(updated.Definition, revised) {
		t.Fatal("actual compare-and-revise did not preserve exact complete terms", updated, err)
	}
	one := "1"
	original, err := clients[a].GetCapacityAgreement(t.Context(), sdk.GetCapacityAgreementRequest{Id: items[a].Id, Version: &one})
	if err != nil || original == nil || original.Version != "1" || original.CurrentVersion != "2" || !reflect.DeepEqual(original.Definition, definition) {
		t.Fatal("financial replacement mutated immutable original terms", original, err)
	}
	at := "2026-11-30T23:59:59.999999999Z"
	if item, err := clients[a].GetCapacityAgreement(t.Context(), sdk.GetCapacityAgreementRequest{Id: items[a].Id, At: &at}); err != nil || item == nil || item.Version != "1" {
		t.Fatal("actual effective lookup lost original nanosecond boundary", item, err)
	}
	if status, _ := request(a, http.MethodGet, base+"/"+items[a].Id+"?at=0001-01-01T00:00:00Z", ""); status != http.StatusNotFound {
		t.Fatal("valid year-one effective lookup must report missing terms, not an invalid instant", status)
	}
	pageSize := 1
	page, err := clients[a].ListCapacityAgreementRevisions(t.Context(), sdk.ListCapacityAgreementRevisionsRequest{Id: items[a].Id, Limit: &pageSize})
	if err != nil || page == nil || len(page.Items) != 1 || page.Items[0].Version != "2" || !page.HasMore || page.Next != "2" {
		t.Fatal("actual revision page lost recording order or continuation", page, err)
	}
	page, err = clients[a].ListCapacityAgreementRevisions(t.Context(), sdk.ListCapacityAgreementRevisionsRequest{Id: items[a].Id, Limit: &pageSize, After: &page.Next})
	if err != nil || page == nil || len(page.Items) != 1 || page.Items[0].Version != "1" || page.HasMore {
		t.Fatal("actual revision continuation omitted the oldest terms", page, err)
	}
	body, _ := json.Marshal(sdk.CapacityAgreementInput{Version: "1", Definition: revised})
	if status, _ := request(a, http.MethodPut, base+"/"+items[a].Id, string(body)); status != http.StatusConflict {
		t.Fatal("stale agreement replacement did not fail compare-and-swap", status)
	}
	if status, _ := request(a, http.MethodPut, base+"/"+items[b].Id, string(body)); status != http.StatusNotFound {
		t.Fatal("foreign replacement escaped tenant storage", status)
	}
	grant(a, permFlowAgreementsWrite, false)
	if status, _ := request(a, http.MethodGet, base+"/"+items[a].Id, ""); status != http.StatusOK {
		t.Fatal("independent financial read was removed with write permission", status)
	}
	if status, _ := request(a, http.MethodDelete, base+"/"+items[a].Id+"?version=2", ""); status != http.StatusForbidden {
		t.Fatal("withdrawn current write grant still deleted financial history", status)
	}
	// Capture a preflight-approved operation, then remove its grant. The
	// repository must re-read authority in the terms snapshot, not trust the
	// principal/preflight that created this operation.
	var actor *auth.Principal
	f.in(a, func(ctx context.Context, sc tenancy.Scope) error {
		grants, err := (store.Permissions{}).ForSubject(ctx, sc, "user", f.users[a])
		actor = auth.PrincipalWithPermissionGrants(&auth.Principal{TenantID: a, UserID: f.users[a], ViaBearerToken: true}, grants)
		return err
	})
	r := httptest.NewRequest(http.MethodGet, base+"/"+items[a].Id, nil).WithContext(auth.WithPrincipal(tenancy.WithTenant(t.Context(), tenancy.ID(a)), actor))
	op, err := f.server.beginCapacityAgreement(r)
	if err != nil {
		t.Fatal(err)
	}
	defer op.done()
	grant(a, permFlowAgreementsRead, false)
	if item, err := op.store.GetCapacityAgreement(op.request.Context(), actor.UserID, items[a].Id, ""); err == nil || !reflect.DeepEqual(item, flow.CapacityAgreement{}) {
		t.Fatal("stale approved operation read terms after current authority withdrawal", item, err)
	}
	if status, raw := request(a, http.MethodGet, base+"/"+items[a].Id, ""); status != http.StatusForbidden || strings.Contains(string(raw), definition.UnitPrice) {
		t.Fatal("withdrawn financial read grant exposed terms", status)
	}
	if item, err := clients[b].GetCapacityAgreement(t.Context(), sdk.GetCapacityAgreementRequest{Id: items[b].Id}); err != nil || item == nil || !reflect.DeepEqual(item.Definition, definition) {
		t.Fatal("tenant financial refusal changed sibling history", item, err)
	}
	if err := clients[b].DeleteCapacityAgreement(t.Context(), sdk.DeleteCapacityAgreementRequest{Id: items[b].Id, Version: &one}); err != nil {
		t.Fatal("actual observed compare-and-delete failed", err)
	}
	if status, _ := request(b, http.MethodGet, base+"/"+items[b].Id, ""); status != http.StatusNotFound {
		t.Fatal("deleted agreement remained readable", status)
	}
}
