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
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	gouuid "github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/cli"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/fairness"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testspec"
	"github.com/ctlplne/probectl/pkg/sdk"
)

// Actual issued mTLS, PostgreSQL app-role/FORCE-RLS and HTTPS/SDK/CLI/native;
// original packet observations are modeled. The current calendar month remains
// unfinished, so this proves original selection and authority, not a completed
// physical month or a legally payable claim.
func TestCarrierSLAMonthServesRecordedSourcesAndCurrentTwoTenantAuthority(t *testing.T) {
	var diagnostics bytes.Buffer
	f := newRoleExplanationAPIFixture(t, slog.New(slog.NewTextHandler(&diagnostics, nil)))
	defer func() {
		if t.Failed() {
			t.Log(diagnostics.String())
		}
	}()
	f.server.cfg.FlowQueryLibraryBytes = 256 << 20
	f.server.WithFairness(fairness.NewGate(fairness.DefaultPolicy(), nil))
	key, _, err := crypto.GenerateEd25519KeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	f.server.evidenceSigningKey = key
	public, err := crypto.PublicPEMFromPrivate(key)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint := "sha256:" + fmt.Sprintf("%x", crypto.Hash(public))
	sender := newVerdictEvidenceSender(t, f)
	now := time.Now().UTC()
	from := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	ids := map[string]string{}
	agreements := map[string]flow.CapacityAgreement{}
	reports := map[string]string{}
	proofs := map[string]carrierSLAReportProof{}
	agents := map[string]string{}
	tests := map[string]string{}
	for lane, tenant := range f.tenants {
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			for _, permission := range []string{permFlowAgreementsRead, permFlowAgreementsWrite, permTestRead, "entities.read", "metrics.read", permMetricsWrite} {
				if err := (store.Roles{}).AddPermission(ctx, sc, f.roles[tenant], permission); err != nil {
					return err
				}
			}
			return nil
		})
		agent := gouuid.NewString()
		agents[tenant] = agent
		definition := seedVerdictCarrierTest(t, f, tenant, agent, "198.51.100.10")
		tests[tenant] = definition.ID
		client := sender(tenant, agent)
		digest, err := testspec.DefinitionHash(definition)
		if err != nil {
			t.Fatal(err)
		}
		at := f.observedAt(tenant)
		rtts := []uint64{100}
		if lane == 1 {
			rtts = append(rtts, 300)
		}
		m := &entity.ICMPMeasurement{Version: 3, DefinitionHash: digest, StartedAt: at, CompletedAt: at.Add(time.Microsecond), Requested: 3, Attempted: 3, Transmitted: 3, Replies: uint32(len(rtts)), Responders: []string{definition.Target}, ReadComplete: true, RoundTrips: &entity.ICMPRoundTrips{Nanos: rtts, ExecutionNanos: 1000}}
		claim := entity.Observation{ID: gouuid.NewString(), Source: entity.SourceKey{AgentID: agent, Kind: entity.PathAgent, SourceRef: definition.ID}, Alias: entity.AliasKey{Kind: entity.AddressAlias, Value: definition.Target}, SourceRef: "icmp:configured-test", ObservedAt: m.CompletedAt, ICMP: m}
		if n, unresolved, err := client.Submit(t.Context(), []entity.Observation{claim}); err != nil || n != 1 || unresolved != 0 {
			t.Fatal("owned original receipt refused", n, unresolved, err)
		}
		terms := flow.CapacityAgreementDefinition{Name: "SLA circuit", Reference: "operator contract", ValidFrom: from.Format(time.RFC3339Nano), Target: flow.CapacityTarget{Kind: "interface", ContextID: f.contextID, InterfaceID: f.interfaceID}, BillingDay: 1, Timezone: "UTC", Direction: "in", Currency: "USD", CommitBPS: "0", UnitBPS: "1", UnitPrice: "0", SLA: &flow.CarrierSLATerms{Carrier: "operator carrier", CircuitID: "operator circuit", Currency: "USD", MonthlyCharge: "100.125", CreditCapRatio: "1.25", Aggregation: "maximum", Sources: []flow.CarrierSLASource{{AgentID: agent, TestID: definition.ID}}, Rules: []flow.CarrierSLARule{{ID: "loss", Metric: "loss", Basis: "original_packet_ratio", GoodWhen: "at_most", Threshold: "0.01", CreditBands: []flow.CarrierSLACreditBand{{From: "0.01", CreditRatio: "0.1"}}}}}}
		repository := flow.NewPostgresCapacityAgreements(f.pool, 1<<30, 8<<20, 8<<20, audit.TenantRecord)
		item, err := repository.SaveCapacityAgreement(tenancy.WithTenant(t.Context(), tenancy.ID(tenant)), f.users[tenant], flow.SaveCapacityAgreement{Definition: terms})
		if err != nil {
			t.Fatal(err)
		}
		ids[tenant] = item.ID
		agreements[tenant] = item
		if delay := time.Until(m.CompletedAt); delay > 0 {
			if delay > 5*time.Second {
				t.Fatal("fixture clock exceeds sender skew")
			}
			time.Sleep(delay)
		}
	}

	for _, tenant := range f.tenants {
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			selected := []store.IncidentConfiguredTest{{TenantID: tenant, AgentID: agents[tenant], TestID: tests[tenant]}}
			authorize := func(context.Context, entity.ContextRecord, store.IncidentImpactEntity, string) error { return nil }
			registry := store.NewEntityRegistry(f.pool)
			if rows, err := registry.CarrierSLAConfiguredTestsInScope(ctx, sc, ids[tenant], "1", selected, 8<<20, authorize); err == nil || rows != nil {
				t.Fatal("metadata lookup accepted a plain unfenced write transaction")
			}
			if err := audit.LockTenantStream(ctx, sc.Q, tenant); err != nil {
				return err
			}
			rows, err := registry.CarrierSLAConfiguredTestsInScope(ctx, sc, ids[tenant], "1", selected, 8<<20, authorize)
			if err != nil {
				return err
			}
			if len(rows) != 1 || rows[0].TenantID != tenant || rows[0].AgentID != agents[tenant] {
				t.Fatal("canonical audit-locked report metadata lost tenant identity")
			}
			return nil
		})
	}
	socket := httptest.NewTLSServer(f.server.Handler())
	t.Cleanup(socket.Close)
	caFile := filepath.Join(t.TempDir(), "served-ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: socket.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	input := sdk.CarrierSLAInput{Version: "1", At: now.Format(time.RFC3339Nano)}
	for lane, tenant := range f.tenants {
		client := sdk.NewClient(socket.URL, sdk.WithHTTPClient(socket.Client()), sdk.WithToken(f.tokens[tenant]))
		result, err := client.CalculateCarrierSla(t.Context(), sdk.CalculateCarrierSlaRequest{Id: ids[tenant], Body: &input})
		if err != nil || result == nil || len(result.Sources) != 1 {
			t.Fatal("served current SLA unavailable", err)
		}
		p := result.Sources[0]
		if p.AgentId != agents[tenant] || p.Originals != "1" || p.Transmitted != "3" || p.Lost != strconv.Itoa(2-lane) || len(p.Digest) != 64 || result.Credit.Complete || result.Credit.ExactCredit != "" || !result.HumanReviewRequired {
			t.Fatal("tenant originals were substituted, shortened or promoted to a finished month", result)
		}
		var stdout, stderr bytes.Buffer
		body, _ := json.Marshal(input)
		getenv := func(key string) string {
			return map[string]string{"PROBECTL_API_URL": socket.URL, "PROBECTL_API_TOKEN": f.tokens[tenant], "PROBECTL_CA_FILE": caFile}[key]
		}
		code := cli.RunWithStdin([]string{"--json", "capacity-agreements", "sla", ids[tenant], "--body-file", "-"}, getenv, bytes.NewReader(body), &stdout, &stderr)
		var cliResult flow.CarrierSLAStatement
		if code != 0 || json.Unmarshal(stdout.Bytes(), &cliResult) != nil || len(cliResult.Sources) != 1 || cliResult.Sources[0].Digest != p.Digest {
			t.Fatal("CLI lost complete original population", code, stderr.String())
		}
		proofs[tenant] = proveCarrierSLASignedReport(t, client, ids[tenant], input.At, p.Digest, fingerprint)
		reports[tenant] = proofs[tenant].CSV
		proveReportRevokedCredential(t, f, tenant, reports[tenant])
		otherReportClient := sdk.NewClient(socket.URL, sdk.WithHTTPClient(socket.Client()), sdk.WithToken(f.tokens[f.tenants[1-lane]]))
		for _, artifact := range []string{proofs[tenant].CSV, proofs[tenant].PDF} {
			if _, err := otherReportClient.DownloadDashboardReportArtifact(t.Context(), sdk.DownloadDashboardReportArtifactRequest{Id: artifact}); err == nil {
				t.Fatal("foreign tenant downloaded signed financial report")
			}
		}
		selection := sdk.CarrierSLASelection{AgreementId: ids[tenant], Version: "1", At: input.At}
		claimInput := sdk.CarrierSLAClaimInput{Selections: []sdk.CarrierSLASelection{selection}}
		draft, err := client.PrepareCarrierSlaClaim(t.Context(), sdk.PrepareCarrierSlaClaimRequest{Body: &claimInput})
		if err != nil || draft == nil || len(draft.Groups) != 1 || len(draft.Groups[0].Circuits) != 1 || draft.Groups[0].Circuits[0].Sources[0].Digest != p.Digest || draft.Groups[0].Complete || draft.SubmissionState != "not_submitted" {
			t.Fatal("grouped draft lost the complete current owned source or invented an exact total", err)
		}
		claimInput.Selections = append(claimInput.Selections, selection)
		if _, err := client.PrepareCarrierSlaClaim(t.Context(), sdk.PrepareCarrierSlaClaimRequest{Body: &claimInput}); err == nil {
			t.Fatal("the same recorded circuit period was counted twice")
		}
		other := f.tenants[1-lane]
		if _, err := client.CalculateCarrierSla(t.Context(), sdk.CalculateCarrierSlaRequest{Id: ids[other], Body: &input}); err == nil {
			t.Fatal("foreign financial revision crossed storage tenant")
		}
		claimInput.Selections[1].AgreementId = ids[other]
		if draft, err := client.PrepareCarrierSlaClaim(t.Context(), sdk.PrepareCarrierSlaClaimRequest{Body: &claimInput}); err == nil || draft != nil {
			t.Fatal("foreign selection crossed tenant or returned a successful partial group")
		}
	}
	seedInterfaceRoleMCPConsent(f)
	nativeReports := newClientReportNativeProof(t, f, socket)
	for lane, tenant := range f.tenants {
		nativeReports.proveCarrier(t, tenant, f.tenants[1-lane], proofs[tenant], ids[tenant], fingerprint)
	}
	nativeReports.crossTenant()
	call := interfaceRoleNativeTLSCaller(t, f, "2025-11-25")
	for _, tenant := range f.tenants {
		var result flow.CarrierSLAStatement
		call(tenant, "capacity_agreement_sla", map[string]any{"id": ids[tenant], "version": "1", "at": input.At}, &result, true)
		if len(result.Sources) != 1 || result.Sources[0].Transmitted != "3" || result.Credit.Complete {
			t.Fatal("native source population or incomplete-month semantics changed")
		}
		var draft flow.CarrierSLAClaimDraft
		call(tenant, "capacity_sla_claim", map[string]any{"claim": flow.CarrierSLAClaimRequest{Selections: []flow.CarrierSLASelection{{AgreementID: ids[tenant], Version: "1", At: input.At}}}}, &draft, true)
		if len(draft.Groups) != 1 || len(draft.Groups[0].Circuits) != 1 || draft.Groups[0].Complete {
			t.Fatal("native grouping dropped a circuit or promoted unknown credit")
		}
	}
	a, b := f.tenants[0], f.tenants[1]
	func() {
		request := httptest.NewRequest(http.MethodPost, "/v1/flows/capacity/sla-claims", nil)
		request.Header.Set("Authorization", "Bearer "+f.tokens[a])
		actor := f.server.resolvePrincipal(request)
		if actor == nil {
			t.Fatal("actual source-publication caller did not authenticate")
		}
		request = request.WithContext(auth.WithPrincipal(request.Context(), actor))
		op, err := f.server.beginCapacityAgreementMode(request, false)
		if err != nil {
			t.Fatal(err)
		}
		defer op.done()
		_, publication, err := f.server.prepareCarrierSLAClaim(op, flow.CarrierSLAClaimRequest{Selections: []flow.CarrierSLASelection{{AgreementID: ids[a], Version: "1", At: input.At}}})
		if err != nil || publication(op.request.Context()) != nil {
			t.Fatal("valid current source-publication control failed", err)
		}
		f.in(a, func(ctx context.Context, sc tenancy.Scope) error {
			_, err := sc.Q.Exec(ctx, `DELETE FROM entity_source_contexts WHERE tenant_id=$1 AND agent_id=$2 AND source_kind='path_agent'`, a, agents[a])
			return err
		})
		if err := publication(op.request.Context()); err == nil {
			t.Fatal("late source retirement survived grouped publication")
		}
	}()
	nativeReports.carrierReadAllowed(t, a, false)
	nativeReports.carrierReadAllowed(t, b, true)
	for _, tenant := range []string{a, b} {
		client := sdk.NewClient(socket.URL, sdk.WithHTTPClient(socket.Client()), sdk.WithToken(f.tokens[tenant]))
		for _, artifact := range []string{proofs[tenant].CSV, proofs[tenant].PDF} {
			_, err := client.DownloadDashboardReportArtifact(t.Context(), sdk.DownloadDashboardReportArtifactRequest{Id: artifact})
			if (tenant == a && err == nil) || (tenant == b && err != nil) {
				t.Fatal("stored signed report source retirement boundary failed", tenant, err)
			}
		}
	}
	for _, tenant := range []string{a, b} {
		client := sdk.NewClient(socket.URL, sdk.WithHTTPClient(socket.Client()), sdk.WithToken(f.tokens[tenant]))
		_, err := client.CalculateCarrierSla(t.Context(), sdk.CalculateCarrierSlaRequest{Id: ids[tenant], Body: &input})
		if (tenant == a) != (err != nil) {
			t.Fatal("source retirement crossed tenant or stale source remained readable", err)
		}
		claimInput := sdk.CarrierSLAClaimInput{Selections: []sdk.CarrierSLASelection{{AgreementId: ids[tenant], Version: "1", At: input.At}}}
		_, err = client.PrepareCarrierSlaClaim(t.Context(), sdk.PrepareCarrierSlaClaimRequest{Body: &claimInput})
		if (tenant == a) != (err != nil) {
			t.Fatal("grouped source retirement crossed tenant or retained a stale source", err)
		}
	}
	proveCarrierFinancialReportAuthority(t, f, socket, nativeReports, b, proofs[b], agreements[b])
	f.in(b, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `DELETE FROM role_permissions WHERE tenant_id=$1 AND role_id=$2 AND permission_key=$3`, b, f.roles[b], permTestRead)
		return err
	})
	client := sdk.NewClient(socket.URL, sdk.WithHTTPClient(socket.Client()), sdk.WithToken(f.tokens[b]))
	if _, err := client.CalculateCarrierSla(t.Context(), sdk.CalculateCarrierSlaRequest{Id: ids[b], Body: &input}); err == nil {
		t.Fatal("financial read bypassed current test grant withdrawal")
	}
	nativeReports.carrierReadAllowed(t, b, false)
}
