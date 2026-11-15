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
	"encoding/base64"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http/httptest"
	"regexp"
	"strconv"
	"testing"
	"time"

	gouuid "github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/evidence"
	"github.com/ctlplne/probectl/internal/fairness"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testspec"
	"github.com/ctlplne/probectl/pkg/sdk"
)

// Backdated observations and daily credential windows are modeled lab inputs,
// not a month of physical packets. The complete source reader, current issued
// sender, application-role RLS, signing, rendering, chunks and HTTPS are real.
func TestCarrierSLAFullMonthReportKeepsCompleteOriginalWorkloadAndTenant(t *testing.T) {
	var diagnostics bytes.Buffer
	f := newRoleExplanationAPIFixture(t, slog.New(slog.NewTextHandler(&diagnostics, nil)))
	t.Cleanup(func() {
		if t.Failed() {
			t.Log(diagnostics.String())
		}
	})
	f.server.cfg.FlowQueryLibraryBytes = 256 << 20
	f.server.WithFairness(fairness.NewGate(fairness.DefaultPolicy(), nil))
	private, public, err := crypto.GenerateEd25519KeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	f.server.evidenceSigningKey = private
	fingerprint := "sha256:" + hex.EncodeToString(crypto.Hash(public))
	sender := newVerdictEvidenceSender(t, f)
	now := time.Now().UTC()
	to := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	from := to.AddDate(0, -1, 0)
	count := int(to.Sub(from) / time.Minute)
	socket := httptest.NewTLSServer(f.server.Handler())
	t.Cleanup(socket.Close)
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
		definition := seedVerdictCarrierTest(t, f, tenant, agent, "198.51.100.10")
		digest, err := testspec.DefinitionHash(definition)
		if err != nil {
			t.Fatal(err)
		}
		client := sender(tenant, agent)
		originalAt := f.observedAt(tenant)
		claim := entity.Observation{ID: gouuid.NewString(), Source: entity.SourceKey{AgentID: agent, Kind: entity.PathAgent, SourceRef: definition.ID}, Alias: entity.AliasKey{Kind: entity.AddressAlias, Value: definition.Target}, SourceRef: "icmp:configured-test", ObservedAt: originalAt.Add(time.Microsecond), ICMP: &entity.ICMPMeasurement{Version: 3, DefinitionHash: digest, StartedAt: originalAt, CompletedAt: originalAt.Add(time.Microsecond), Requested: 3, Attempted: 3, Transmitted: 3, Replies: 3, ReadComplete: true, Responders: []string{definition.Target}, RoundTrips: &entity.ICMPRoundTrips{Nanos: []uint64{100, 200, 300}, ExecutionNanos: 1000}}}
		if accepted, unresolved, err := client.Submit(t.Context(), []entity.Observation{claim}); err != nil || accepted != 1 || unresolved != 0 {
			t.Fatal("live issued source control failed", accepted, unresolved, err)
		}
		lossEvery := 10 * (lane + 1)
		seedCarrierMonthWorkload(t, f, tenant, agent, claim.ID, from, to, count, lossEvery)
		terms := flow.CapacityAgreementDefinition{Name: "Complete monthly circuit", Reference: "Modeled historical workload", ValidFrom: from.Format(time.RFC3339Nano), Target: flow.CapacityTarget{Kind: "interface", ContextID: f.contextID, InterfaceID: f.interfaceID}, BillingDay: 1, Timezone: "UTC", Direction: "in", Currency: "USD", CommitBPS: "0", UnitBPS: "1", UnitPrice: "0", SLA: &flow.CarrierSLATerms{Carrier: "Lab carrier", CircuitID: "Monthly circuit", Currency: "USD", MonthlyCharge: "100.125", CreditCapRatio: "1", Aggregation: "maximum", Sources: []flow.CarrierSLASource{{AgentID: agent, TestID: definition.ID}}, Rules: []flow.CarrierSLARule{{ID: "loss", Metric: "loss", Basis: "original_packet_ratio", GoodWhen: "at_most", Threshold: "0.01", CreditBands: []flow.CarrierSLACreditBand{{From: "0.01", CreditRatio: "0.1"}}}}}}
		repository := flow.NewPostgresCapacityAgreements(f.pool, 1<<30, 8<<20, 8<<20, audit.TenantRecord)
		agreement, err := repository.SaveCapacityAgreement(tenancy.WithTenant(t.Context(), tenancy.ID(tenant)), f.users[tenant], flow.SaveCapacityAgreement{Definition: terms})
		if err != nil {
			t.Fatal(err)
		}
		sdkClient := sdk.NewClient(socket.URL, sdk.WithHTTPClient(socket.Client()), sdk.WithToken(f.tokens[tenant]))
		at := from.Add(time.Hour).Format(time.RFC3339Nano)
		analysis, err := sdkClient.CalculateCarrierSla(t.Context(), sdk.CalculateCarrierSlaRequest{Id: agreement.ID, Body: &sdk.CarrierSLAInput{Version: "1", At: at}})
		if err != nil || analysis == nil || len(analysis.Sources) != 1 {
			t.Fatal("complete monthly source population refused", err)
		}
		expectedLost := 3 * count / lossEvery
		pop := analysis.Sources[0]
		if pop.Originals != strconv.Itoa(count) || pop.Transmitted != strconv.Itoa(3*count) || pop.Lost != strconv.Itoa(expectedLost) || pop.RttSamples != strconv.Itoa(3*count-expectedLost) || !analysis.Credit.Complete || analysis.Credit.ExactCredit != "801/80" {
			t.Fatal("complete month was shortened, approximated or mixed across tenants", pop, analysis.Credit)
		}
		// Two independently recorded circuit selections exercise a carrier
		// group, including cumulative source/replay and complete output cost.
		terms.SLA.CircuitID = "Second recorded circuit"
		second, err := repository.SaveCapacityAgreement(tenancy.WithTenant(t.Context(), tenancy.ID(tenant)), f.users[tenant], flow.SaveCapacityAgreement{Definition: terms})
		if err != nil {
			t.Fatal(err)
		}
		agreements := map[string]bool{agreement.ID: true, second.ID: true}
		input := sdk.DashboardCreateRequest{Name: "Complete monthly claim", Preset: "operator", Definition: sdk.DashboardDefinition{CarrierClaim: &sdk.CarrierSLAReportDefinition{Selections: []sdk.CarrierSLAReportSelection{{AgreementId: agreement.ID, Version: "1", At: at}, {AgreementId: second.ID, Version: "1", At: at}}}, Provenance: []string{"complete modeled historical population on actual RLS"}, RedactionState: "tenant policy", CoverageLimitations: []string{"modeled original clocks; no physical-month or continuous-coverage assertion"}}}
		view, err := sdkClient.CreateDashboard(t.Context(), sdk.CreateDashboardRequest{Body: &input})
		if err != nil {
			t.Fatal(err)
		}
		for _, format := range []string{"csv", "pdf"} {
			start := time.Now()
			request := map[string]any{"dashboard_id": view.Id, "format": format}
			artifact, err := sdkClient.GenerateDashboardReport(t.Context(), sdk.GenerateDashboardReportRequest{Body: &request})
			if err != nil {
				t.Fatal("complete intended monthly artifact refused", format, err)
			}
			var body bytes.Buffer
			if _, err := sdkClient.DownloadDashboardReportArtifactTo(t.Context(), sdk.DownloadDashboardReportArtifactRequest{Id: artifact.Id}, &body, 1<<30); err != nil {
				t.Fatal(err)
			}
			signed := carrierMonthWorkloadPackage(t, format, body.Bytes())
			verifyCarrierMonthWorkload(t, signed, fingerprint, definition.ID, agreements, from, count, lossEvery)
			other := sdk.NewClient(socket.URL, sdk.WithHTTPClient(socket.Client()), sdk.WithToken(f.tokens[f.tenants[1-lane]]))
			if raw, err := other.DownloadDashboardReportArtifact(t.Context(), sdk.DownloadDashboardReportArtifactRequest{Id: artifact.Id}); err == nil || len(raw) > 0 {
				t.Fatal("complete monthly artifact crossed tenant")
			}
			t.Logf("real-integration modeled originals_per_circuit=%d circuits=2 format=%s body_bytes=%d signed_bytes=%d duration=%s", count, format, body.Len(), len(signed), time.Since(start))
		}
	}
}

func seedCarrierMonthWorkload(t *testing.T, f *roleExplanationAPIFixture, tenant, agent, observation string, from, to time.Time, count, lossEvery int) {
	t.Helper()
	f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
		for _, sql := range []string{`UPDATE entity_contexts SET created_at=$2 WHERE tenant_id=$1`, `UPDATE entities SET created_at=$2 WHERE tenant_id=$1`, `UPDATE tests SET updated_at=$2,created_at=$2 WHERE tenant_id=$1`, `UPDATE entity_test_contexts SET assigned_at=$2 WHERE tenant_id=$1`, `UPDATE entity_path_test_contexts SET assigned_at=$2 WHERE tenant_id=$1`, `UPDATE entity_source_contexts SET assigned_at=$2 WHERE tenant_id=$1`, `UPDATE entity_agent_contexts SET assigned_at=$2 WHERE tenant_id=$1`} {
			if _, err := sc.Q.Exec(ctx, sql, tenant, from.Add(-24*time.Hour)); err != nil {
				return err
			}
		}
		// Model one separate, expired 24-hour source credential for each day.
		// Keep the real current identity active; historic expiry is not revocation.
		_, err := sc.Q.Exec(ctx, `INSERT INTO agent_identities(tenant_id,agent_id,spiffe_id,serial,issued_at,not_after)
 SELECT $1::uuid,$2,'spiffe://probectl/tenant/'||$1::text||'/entity/'||$2,
 base.sender_serial||lpad(to_hex(day),4,'0'),$4::timestamptz+day*interval '1 day',$4::timestamptz+(day+1)*interval '1 day'
 FROM entity_evidence base CROSS JOIN generate_series(0,($5::date-$4::date)-1) day
 WHERE base.tenant_id=$1::uuid AND base.agent_id=$2 AND base.observation_id=$3::uuid`, tenant, agent, observation, from, to)
		if err != nil {
			return err
		}
		tag, err := sc.Q.Exec(ctx, `INSERT INTO entity_evidence
 SELECT (jsonb_populate_record(NULL::entity_evidence,to_jsonb(base)||jsonb_build_object(
 'id',gen_random_uuid(),'observation_id',gen_random_uuid(),
 'sender_serial',base.sender_serial||lpad(to_hex(seq/1440),4,'0'),
 'observed_at',$4::timestamptz+seq*interval '1 minute'+interval '1 microsecond',
 'expires_at',$4::timestamptz+seq*interval '1 minute'+interval '1 hour',
 'icmp_measurement',base.icmp_measurement||jsonb_build_object(
 'started_at',to_char(($4::timestamptz+seq*interval '1 minute') AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS"Z"'),
 'completed_at',to_char(($4::timestamptz+seq*interval '1 minute'+interval '1 microsecond') AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
 'replies',CASE WHEN seq%$6::int=0 THEN 0 ELSE 3 END,
 'responders',CASE WHEN seq%$6::int=0 THEN '[]'::jsonb ELSE base.icmp_measurement->'responders' END,
 'round_trips',jsonb_build_object('execution_nanos',1000,'nanos',CASE WHEN seq%$6::int=0 THEN '[]'::jsonb ELSE '[100,200,300]'::jsonb END))))).*
 FROM entity_evidence base CROSS JOIN generate_series(0,$5::int-1) seq
 WHERE base.tenant_id=$1::uuid AND base.agent_id=$2 AND base.observation_id=$3::uuid`, tenant, agent, observation, from, count, lossEvery)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != int64(count) {
			return fmt.Errorf("complete monthly fixture rows=%d expected=%d", tag.RowsAffected(), count)
		}
		_, err = sc.Q.Exec(ctx, `DELETE FROM entity_evidence WHERE tenant_id=$1 AND agent_id=$2 AND observation_id=$3`, tenant, agent, observation)
		return err
	})
}

func carrierMonthWorkloadPackage(t *testing.T, format string, body []byte) []byte {
	t.Helper()
	if format == "csv" {
		return carrierSLAWorkloadCSVPackage(t, body)
	}
	match := regexp.MustCompile(`/Type /EmbeddedFile /Subtype /application#2Fjson /Params << /Size ([0-9]+) >> /Length ([0-9]+) >>\nstream\n`).FindSubmatchIndex(body)
	if match == nil {
		t.Fatal("complete monthly PDF omitted signed attachment")
	}
	size, err := strconv.ParseInt(string(body[match[4]:match[5]]), 10, 64)
	if err != nil || size <= 0 || size > int64(len(body)-match[1]) {
		t.Fatal("complete PDF attachment length changed", err)
	}
	return body[match[1] : match[1]+int(size)]
}

func verifyCarrierMonthWorkload(t *testing.T, raw []byte, fingerprint, test string, agreements map[string]bool, from time.Time, count, lossEvery int) {
	t.Helper()
	manifest, err := evidence.Verify(raw)
	if err != nil || manifest.Profile != "carrier-sla" {
		t.Fatal("complete monthly package cannot verify offline", err)
	}
	var pkg evidence.Package
	if err := json.Unmarshal(raw, &pkg); err != nil || len(pkg.Attachments) != 2 || pkg.Signing.Fingerprint != fingerprint {
		t.Fatal("complete monthly attachment/signer set changed", err)
	}
	var draft flow.CarrierSLAClaimDraft
	if err := json.Unmarshal(pkg.Attachments[0].Content, &draft); err != nil || len(draft.Groups) != 1 || len(draft.Groups[0].Circuits) != len(agreements) || draft.Groups[0].ExactCredit == nil || *draft.Groups[0].ExactCredit != "801/40" {
		t.Fatal("complete carrier group lost exact independent circuit totals", err)
	}
	seenAgreements := map[string]bool{}
	decoder := json.NewDecoder(bytes.NewReader(pkg.Attachments[1].Content))
	// Stream the complete typed original array, including successful executions.
	// No last-page, breach-only, substring count or source digest substitutes it.
	originals := 0
	var seen map[string]bool
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		key, ok := token.(string)
		if ok && key == "agreement_id" {
			id, err := decoder.Token()
			if err != nil {
				t.Fatal(err)
			}
			value, ok := id.(string)
			if !ok || !agreements[value] || seenAgreements[value] {
				t.Fatal("complete originals changed a selected agreement")
			}
			seenAgreements[value] = true
		}
		if !ok || key != "measurements" {
			continue
		}
		start, err := decoder.Token()
		if err != nil || start != json.Delim('[') {
			t.Fatal("original measurement array missing", err)
		}
		seen = map[string]bool{}
		within := 0
		for decoder.More() {
			var item struct {
				EvidenceID string    `json:"evidence_id"`
				TestID     string    `json:"test_id"`
				ObservedAt time.Time `json:"observed_at"`
				ICMP       struct {
					Version     int    `json:"version"`
					Transmitted uint32 `json:"transmitted"`
					Replies     uint32 `json:"replies"`
					RoundTrips  struct {
						Nanos          []string `json:"nanos"`
						ExecutionNanos string   `json:"execution_nanos"`
					} `json:"round_trips"`
				} `json:"icmp"`
			}
			if err := decoder.Decode(&item); err != nil {
				t.Fatal(err)
			}
			replies := 3
			if within%lossEvery == 0 {
				replies = 0
			}
			if within >= count || item.TestID != test || item.EvidenceID == "" || seen[item.EvidenceID] || !item.ObservedAt.Equal(from.Add(time.Duration(within)*time.Minute+time.Microsecond)) || item.ICMP.Version != 3 || item.ICMP.Transmitted != 3 || item.ICMP.Replies != uint32(replies) || len(item.ICMP.RoundTrips.Nanos) != replies || item.ICMP.RoundTrips.ExecutionNanos != "1000" {
				t.Fatal("complete monthly output changed or omitted an original", originals)
			}
			for index, nanos := range item.ICMP.RoundTrips.Nanos {
				if nanos != strconv.Itoa((index+1)*100) {
					t.Fatal("complete month changed exact RTT")
				}
			}
			seen[item.EvidenceID] = true
			originals++
			within++
		}
		if within != count {
			t.Fatal("complete circuit original population was shortened", within, count)
		}
		if _, err := decoder.Token(); err != nil {
			t.Fatal(err)
		}
	}
	if originals != count*len(agreements) || len(seenAgreements) != len(agreements) {
		t.Fatal("monthly output was truncated", originals, count)
	}
}

func carrierSLAWorkloadCSVPackage(t *testing.T, body []byte) []byte {
	t.Helper()
	reader := csv.NewReader(bytes.NewReader(body))
	reader.FieldsPerRecord = -1
	var signed bytes.Buffer
	for {
		row, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if len(row) == 6 && len(row[0]) > 4 && row[0][:4] == "pkg_" {
			raw, err := base64.StdEncoding.DecodeString(row[5])
			if err != nil {
				t.Fatal(err)
			}
			signed.Write(raw)
		}
	}
	return signed.Bytes()
}
