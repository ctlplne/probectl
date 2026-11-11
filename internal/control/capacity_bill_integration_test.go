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
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/cli"
	"github.com/ctlplne/probectl/internal/fairness"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/pkg/sdk"
)

// Real TLS PostgreSQL/application RLS and verified HTTPS/generated SDK/CLI.
// A full month of counter words and original receipt rows is seeded/modeled;
// this root does not claim physical SNMP, issued mTLS or actual ClickHouse.
func TestCapacityAgreementBillServesCompleteMonthAndCurrentTwoTenantAuthority(t *testing.T) {
	f := newRoleExplanationAPIFixture(t)
	f.server.cfg.FlowQueryLibraryBytes = 256 << 20
	f.server.WithFairness(fairness.NewGate(fairness.DefaultPolicy(), nil))
	probe := &capacityCounterHistoryProbe{Memory: flowstore.NewMemory()}
	f.server.flowStore = probe
	from, to := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC), time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	for _, tenant := range f.tenants {
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			for _, permission := range []string{permFlowAgreementsRead, permFlowAgreementsWrite} {
				if err := (store.Roles{}).AddPermission(ctx, sc, f.roles[tenant], permission); err != nil {
					return err
				}
			}
			return nil
		})
		seedCapacityBillingMonth(f, probe.Memory, tenant, from, to)
	}
	socket := httptest.NewTLSServer(f.server.Handler())
	t.Cleanup(socket.Close)
	ca := filepath.Join(t.TempDir(), "served-ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: socket.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	clients, ids := map[string]*sdk.Client{}, map[string]string{}
	for _, tenant := range f.tenants {
		client := sdk.NewClient(socket.URL, sdk.WithHTTPClient(socket.Client()), sdk.WithToken(f.tokens[tenant]))
		clients[tenant] = client
		item, err := client.CreateCapacityAgreement(t.Context(), sdk.CreateCapacityAgreementRequest{Body: &sdk.CapacityAgreementInput{Definition: sdk.CapacityAgreementDefinition{
			Name: "Recorded interface terms", Reference: "operator contract", ValidFrom: from.Format(time.RFC3339Nano), Target: sdk.CapacityTarget{Kind: "interface", ContextId: f.contextID, InterfaceId: f.interfaceID},
			BillingDay: 1, Timezone: "UTC", Direction: "in", Currency: "USD", CommitBps: "1000", UnitBps: "1000", UnitPrice: "0.250000000000000001"}}})
		if err != nil || item == nil {
			t.Fatal(err)
		}
		ids[tenant] = item.Id
	}
	body := flow.CapacityBillRequest{Version: "1", At: "2026-10-15T12:00:00Z", MaximumPollGap: "5m", Invoiced: "3.8000000000000000152",
		PhysicalBounds: []flow.CapacityPhysicalBound{{ContextID: f.contextID, InterfaceID: f.interfaceID, MaxBPS: "1000000"}}}
	raw, _ := json.Marshal(body)
	var sdkBody sdk.CapacityBillInput
	if err := json.Unmarshal(raw, &sdkBody); err != nil {
		t.Fatal(err)
	}

	for _, tenant := range f.tenants {
		result, err := clients[tenant].CheckCapacityAgreementBill(t.Context(), sdk.CheckCapacityAgreementBillRequest{Id: ids[tenant], Body: &sdkBody})
		if err != nil || result == nil {
			t.Fatal("actual SDK measured billing failed", tenant, err)
		}
		encoded, _ := json.Marshal(result)
		var got flow.CapacityAgreementBill
		if err := json.Unmarshal(encoded, &got); err != nil {
			t.Fatal(err)
		}
		assertCapacityMonthBill(t, got, from, to)
		var stdout, stderr bytes.Buffer
		getenv := func(key string) string {
			return map[string]string{"PROBECTL_API_URL": socket.URL, "PROBECTL_API_TOKEN": f.tokens[tenant], "PROBECTL_CA_FILE": ca}[key]
		}
		if code := cli.RunWithStdin([]string{"--json", "capacity-agreements", "check", ids[tenant], "--body-file", "-"}, getenv, bytes.NewReader(raw), &stdout, &stderr); code != 0 {
			t.Fatal("actual verified-TLS bill CLI failed", code, stderr.String())
		}
		if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
			t.Fatal(err)
		}
		assertCapacityMonthBill(t, got, from, to)
	}
	a, b := f.tenants[0], f.tenants[1]
	f.in(a, func(ctx context.Context, sc tenancy.Scope) error {
		naked := flow.NewPostgresCapacityAgreements(f.pool, 256<<20, 2<<30, 256<<20, nil)
		if got, err := naked.CapacityAgreementInScope(ctx, sc, f.users[a], ids[a], "1", nil); err == nil || got.ID != "" {
			t.Fatal("scoped financial join without a serving authorizer returned terms", got, err)
		}
		return nil
	})
	request := func(tenant, id string) (int, flow.CapacityAgreementBill, string) {
		t.Helper()
		r, err := http.NewRequestWithContext(t.Context(), http.MethodPost, socket.URL+"/v1/flows/capacity/agreements/"+id+"/check", bytes.NewReader(raw))
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
		encoded, err := io.ReadAll(response.Body)
		if err != nil {
			t.Fatal(err)
		}
		var got flow.CapacityAgreementBill
		_ = json.Unmarshal(encoded, &got)
		return response.StatusCode, got, string(encoded)
	}
	if status, _, _ := request(a, ids[b]); status != http.StatusNotFound {
		t.Fatal("foreign financial target was distinguishable from an unknown agreement", status)
	}
	original, err := clients[a].GetCapacityAgreement(t.Context(), sdk.GetCapacityAgreementRequest{Id: ids[a]})
	if err != nil {
		t.Fatal(err)
	}
	midPeriod, err := clients[a].CreateCapacityAgreement(t.Context(), sdk.CreateCapacityAgreementRequest{Body: &sdk.CapacityAgreementInput{Definition: original.Definition}})
	if err != nil {
		t.Fatal(err)
	}
	revised := original.Definition
	revised.ValidFrom = "2026-10-15T00:00:00Z"
	if _, err := clients[a].UpdateCapacityAgreement(t.Context(), sdk.UpdateCapacityAgreementRequest{Id: midPeriod.Id, Body: &sdk.CapacityAgreementInput{Version: "1", Definition: revised}}); err != nil {
		t.Fatal(err)
	}
	calls := probe.calls
	if status, _, _ := request(a, midPeriod.Id); status != http.StatusUnprocessableEntity || probe.calls != calls {
		t.Fatal("mid-period terms were applied as one whole-month rate or reached source history", status)
	}
	probe.transform = func(rows []flowstore.CounterRow) ([]flowstore.CounterRow, error) {
		for i := range rows {
			rows[i].TenantID = b
		}
		return rows, nil
	}
	if status, _, encoded := request(a, ids[a]); status != http.StatusServiceUnavailable || strings.Contains(encoded, "4750000000000000019") {
		t.Fatal("foreign counter backend rows produced a measured result", status)
	}
	probe.transform = func(rows []flowstore.CounterRow) ([]flowstore.CounterRow, error) {
		missing := from.Add(100 * 5 * time.Minute)
		out := rows[:0]
		for _, row := range rows {
			if row.Name != "probectl.device.if.in.octets" || !row.PollStartedAt.Equal(missing) {
				out = append(out, row)
			}
		}
		return out, nil
	}
	if status, got, _ := request(a, ids[a]); status != http.StatusOK || got.Percentile.Complete || got.Percentile.ExpectedSamples != 8928 || got.Percentile.MissingSamples != 2 || got.Bill.Complete || got.Bill.ChargeNumerator != "" {
		t.Fatal("missing source point shortened the month or generated a charge", status, got)
	}
	probe.transform = nil
	probe.after = func() {
		f.in(a, func(ctx context.Context, sc tenancy.Scope) error {
			_, err := sc.Q.Exec(ctx, `DELETE FROM role_permissions WHERE tenant_id=$1 AND role_id=$2 AND permission_key=$3`, a, f.roles[a], permFlowAgreementsRead)
			return err
		})
	}
	if status, _, encoded := request(a, ids[a]); status != http.StatusForbidden || strings.Contains(encoded, "4750000000000000019") {
		t.Fatal("current financial read withdrawal published a measured charge", status)
	}
	probe.after = nil
	if status, got, _ := request(b, ids[b]); status != http.StatusOK {
		t.Fatal("tenant refusal damaged the sibling month", status)
	} else {
		assertCapacityMonthBill(t, got, from, to)
	}
	probe.after = func() {
		f.in(b, func(ctx context.Context, sc tenancy.Scope) error {
			_, err := sc.Q.Exec(ctx, `UPDATE mcp_tokens SET revoked_at=clock_timestamp() WHERE tenant_id=$1 AND user_id=$2`, b, f.users[b])
			return err
		})
	}
	if status, _, encoded := request(b, ids[b]); status != http.StatusUnauthorized || strings.Contains(encoded, "4750000000000000019") {
		t.Fatal("token revoked during counter IO still published a measured bill", status)
	}
}

func assertCapacityMonthBill(t *testing.T, got flow.CapacityAgreementBill, from, to time.Time) {
	t.Helper()
	if !got.Percentile.Complete || !got.Bill.Complete || got.Percentile.ExpectedSamples != 8928 || got.Percentile.ObservedSamples != 8928 || got.Percentile.MissingSamples != 0 ||
		got.Percentile.BPSNumerator != "15200" || got.Percentile.BPSDenominator != "1" || got.Bill.OverageNumerator != "14200" ||
		got.Bill.ChargeNumerator != "4750000000000000019" || got.Bill.ChargeDenominator != "1250000000000000000" || !got.Bill.InvoiceCompared || got.Bill.InvoiceDifferenceNumerator != "0" ||
		!got.Period.From.Equal(from) || !got.Period.To.Equal(to) || got.MembershipBasis != "current_member_set_applied_to_complete_period" || len(got.Members) != 1 {
		t.Fatal("complete-month hand percentile/exact bill disagreed or lost its explicit assumptions", got)
	}
}
