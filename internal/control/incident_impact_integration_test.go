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
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	gouuid "github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/evidence"
	"github.com/ctlplne/probectl/internal/fairness"
	flowv1 "github.com/ctlplne/probectl/internal/gen/probectl/flow/v1"
	"github.com/ctlplne/probectl/internal/incident"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/store/sourceepoch"
	"github.com/ctlplne/probectl/internal/tenancy"
)

const (
	incidentImpactFlowAgent    = "impact-flow"
	incidentImpactFlowExporter = "192.0.2.1"
)

func recordIncidentImpactFlowExporter(t *testing.T, f *roleExplanationAPIFixture, tenant string) {
	t.Helper()
	claim := entity.Observation{ID: gouuid.NewString(),
		Source:    entity.SourceKey{AgentID: incidentImpactFlowAgent, Kind: entity.FlowExporter, SourceRef: incidentImpactFlowExporter},
		Alias:     entity.AliasKey{Kind: entity.FlowExporterAlias, Value: incidentImpactFlowExporter + "/ipfix/4294967295"},
		SourceRef: "flow:ipfix:domain:4294967295", ObservedAt: f.observedAt(tenant)}
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
	accepted, unresolved, err := writeEntityEvidenceBatchForTest(ctx, store.NewEntityRegistry(f.pool), incidentImpactFlowAgent,
		f.serials[tenant+incidentImpactFlowAgent], []entity.Observation{claim})
	if err != nil || accepted != 1 || unresolved != 0 {
		t.Fatal("impact source observation was not accepted", accepted, unresolved, err)
	}
}

func seedIncidentImpactFlowFixture(t *testing.T) (*roleExplanationAPIFixture, map[string]string) {
	t.Helper()
	return seedIncidentImpactWindows(t, false)
}

func seedIncidentImpactWindows(t *testing.T, includePrevious bool, logs ...*slog.Logger) (*roleExplanationAPIFixture, map[string]string) {
	t.Helper()
	f := newRoleExplanationAPIFixture(t, logs...)
	key, _, err := crypto.GenerateEd25519KeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	f.server.WithEvidenceSigningKey(key)
	flows := flowstore.NewMemory()
	f.server.WithFlowStore(flows).WithFairness(fairness.NewGate(fairness.DefaultPolicy(), nil))
	incidents := map[string]string{}
	const agent = incidentImpactFlowAgent
	const exporter = incidentImpactFlowExporter
	windows := []int{0}
	if includePrevious {
		windows = append(windows, 1)
	}
	for lane, tenant := range f.tenants {
		id, prefix, tag := gouuid.NewString(), gouuid.NewString(), gouuid.NewString()
		incidents[tenant] = id
		serial := strings.ReplaceAll(gouuid.NewString(), "-", "")
		if err := store.NewAgentIdentities(f.pool).Record(t.Context(), tenant, agent, crypto.EntitySPIFFEID(tenant, agent), serial, time.Now().Add(time.Hour), ""); err != nil {
			t.Fatal(err)
		}
		f.serials[tenant+agent] = serial
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			for _, permission := range []string{"incident.read", "flow.read", "tags.read", "ai.query"} {
				if err := (store.Roles{}).AddPermission(ctx, sc, f.roles[tenant], permission); err != nil {
					return err
				}
			}
			var boundAt time.Time
			if err := sc.Q.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&boundAt); err != nil {
				return err
			}
			if includePrevious {
				// Model the same continuously bound device before both windows.
				boundAt = boundAt.Add(-8 * 24 * time.Hour)
				if _, err := sc.Q.Exec(ctx, `UPDATE entities SET created_at=$4 WHERE tenant_id=$1 AND context_id=$2 AND id=$3`,
					tenant, f.contextID, f.routerID, boundAt); err != nil {
					return err
				}
			}
			if _, err := sc.Q.Exec(ctx, `INSERT INTO entity_agent_contexts(tenant_id,agent_id,context_id,assigned_at) VALUES($1,$2,$3,$4)`, tenant, agent, f.contextID, boundAt); err != nil {
				return err
			}
			if _, err := sc.Q.Exec(ctx, `INSERT INTO entity_source_contexts(tenant_id,agent_id,source_kind,source_ref,context_id,anchor_entity_id,assigned_at) VALUES($1,$2,'flow_exporter',$3,$4,$5,$6)`, tenant, agent, exporter, f.contextID, f.routerID, boundAt); err != nil {
				return err
			}
			if _, err := sc.Q.Exec(ctx, `INSERT INTO incidents(tenant_id,id,title,entity_context_id,entity_id,identity_lookup_attempted) VALUES($1,$2,'owned impact',$3,$4,true)`, tenant, id, f.contextID, f.routerID); err != nil {
				return err
			}
			if _, err := sc.Q.Exec(ctx, `INSERT INTO entities(tenant_id,context_id,id,kind,label,network_prefix) VALUES($1,$2,$3,'prefix','customer prefix','203.0.113.0/24')`, tenant, f.contextID, prefix); err != nil {
				return err
			}
			if _, err := sc.Q.Exec(ctx, `INSERT INTO tenant_tag_definitions(tenant_id,id,key) VALUES($1,$2,'customer')`, tenant, tag); err != nil {
				return err
			}
			_, err := sc.Q.Exec(ctx, `INSERT INTO tenant_tag_assignments(tenant_id,context_id,id,tag_id,target_kind,entity_kind,entity_id,value,source) VALUES($1,$2,$3,$4,'prefix','prefix',$5,$6,'manual')`, tenant, f.contextID, gouuid.NewString(), tag, prefix, "customer-"+tenant)
			return err
		})
		recordIncidentImpactFlowExporter(t, f, tenant)
		for _, weeksAgo := range windows {
			// The modeled exporter clock can describe retained traffic from last
			// week. Receipt clocks and identity bindings still come from Postgres.
			var observed time.Time
			if weeksAgo > 0 {
				observed = f.observedAt(tenant).Add(-time.Duration(weeksAgo) * 7 * 24 * time.Hour)
			}
			recordModeledIncidentImpactFlow(t, f, tenant, 7, uint16(443+lane), uint64(100+lane-30*weeksAgo), observed,
				flowv1.FlowClockBasis_FLOW_CLOCK_BASIS_EXPORTER_INTERVAL)
		}
	}
	return f, incidents
}

func recordModeledIncidentImpactFlow(t *testing.T, f *roleExplanationAPIFixture, tenant string, ifIndex uint32, port uint16, observedBytes uint64, observed time.Time, clockBasis flowv1.FlowClockBasis) {
	t.Helper()
	const source, destination = "203.0.113.1", "203.0.113.2"
	var raw [32]byte
	copy(raw[:], crypto.Hash([]byte("modeled authenticated impact observation "+gouuid.NewString())))
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
	ref, err := store.NewBGPRoutingFlowCaptures(f.pool).CaptureAuthenticated(ctx, incidentImpactFlowAgent, raw,
		store.BGPRoutingFlowInput{Exporter: netip.MustParseAddr(incidentImpactFlowExporter), Source: netip.MustParseAddr(source), Destination: netip.MustParseAddr(destination), Protocol: "ipfix", Domain: ^uint32(0)},
		store.BGPRoutingBudget{MemoryBytes: 128 << 20, WorkUnits: 128 << 20, StateBytes: 128 << 20})
	if err != nil {
		t.Fatal(err)
	}
	if observed.IsZero() {
		observed = ref.CapturedAt
	}
	row := flowstore.Row{TenantID: tenant, AgentID: incidentImpactFlowAgent, Exporter: incidentImpactFlowExporter, Protocol: "ipfix", ObsDomain: ^uint32(0), TS: observed, StartTS: observed, ClockBasis: clockBasis,
		SrcAddr: source, DstAddr: destination, DstPort: port, InIf: ifIndex, OutIf: ifIndex, Bytes: observedBytes, Packets: 7, Sampling: 3,
		RawFlowDigest: hex.EncodeToString(raw[:]), RoutingCaptureKey: hex.EncodeToString(ref.Key[:]), RoutingCapturedUnixNanos: ref.CapturedAt.UnixNano()}
	if err := f.server.flowStore.Insert(ctx, []flowstore.Row{row}); err != nil {
		t.Fatal(err)
	}
}

func TestIncidentImpactServesCompleteCurrentSourcesAndTenantIsolation(t *testing.T) {
	f, incidents := seedIncidentImpactWindows(t, true)
	socket := httptest.NewTLSServer(f.server.Handler())
	t.Cleanup(socket.Close)
	input := incident.ImpactInput{From: time.Now().UTC().Add(-time.Minute), To: time.Now().UTC(), CustomerTagKey: "customer"}
	request := func(tenant, id string) (int, []byte) {
		t.Helper()
		body, err := json.Marshal(input)
		if err != nil {
			t.Fatal(err)
		}
		req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, socket.URL+"/v1/incidents/"+id+"/impact", bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+f.tokens[tenant])
		req.Header.Set("Content-Type", "application/json")
		response, err := socket.Client().Do(req)
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
	export := func(tenant, id string) (int, []byte) {
		t.Helper()
		body, err := json.Marshal(incidentEvidenceExportInput{Impact: &input})
		if err != nil {
			t.Fatal(err)
		}
		req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, socket.URL+"/v1/incidents/"+id+"/exports", bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+f.tokens[tenant])
		req.Header.Set("Content-Type", "application/json")
		res, err := socket.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		data, err := io.ReadAll(res.Body)
		if err != nil {
			t.Fatal(err)
		}
		return res.StatusCode, data
	}
	for lane, tenant := range f.tenants {
		status, raw := request(tenant, incidents[tenant])
		var out incident.ImpactResponse
		if status != http.StatusOK || json.Unmarshal(raw, &out) != nil {
			t.Fatal("HTTPS impact comparison was unavailable", status, string(raw))
		}
		assertIncidentImpactWeeks(t, out, incidents[tenant], lane)
		if !out.Previous.From.Equal(input.From.Add(-7*24*time.Hour)) || !out.Previous.To.Equal(input.To.Add(-7*24*time.Hour)) ||
			out.Customers[0].Value != "customer-"+tenant {
			t.Fatal("HTTPS impact used the wrong prior window or customer")
		}
		if status, raw := request(tenant, incidents[f.tenants[1-lane]]); status != http.StatusNotFound || bytes.Contains(raw, []byte("customer-"+f.tenants[1-lane])) {
			t.Fatal("foreign incident disclosed source/customer information", status, string(raw))
		}
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			_, err := sc.Q.Exec(ctx, `DELETE FROM role_permissions WHERE tenant_id=$1 AND role_id=$2 AND permission_key='ai.query'`, tenant, f.roles[tenant])
			return err
		})
		if status, raw := request(tenant, incidents[tenant]); status != http.StatusOK {
			t.Fatal("deterministic impact acquired an AI-query requirement", status, string(raw))
		}
		if status, raw := export(tenant, incidents[tenant]); status == http.StatusOK || bytes.Contains(raw, []byte("\"signing\"")) {
			t.Fatal("signed RCA/impact export ignored current AI permission withdrawal", status, string(raw))
		}
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			return (store.Roles{}).AddPermission(ctx, sc, f.roles[tenant], "ai.query")
		})
		status, raw = export(tenant, incidents[tenant])
		if status != http.StatusOK {
			t.Fatal("served signed impact export failed", status, string(raw))
		}
		verified, err := evidence.Verify(raw)
		if err != nil {
			t.Fatal("served impact package did not verify offline", err)
		}
		if verified.TenantScopeDigest == "" || bytes.Contains(raw, []byte(tenant)) {
			var document any
			if err := json.Unmarshal(raw, &document); err != nil {
				t.Fatal(err)
			}
			var paths []string
			var inspect func(any, string)
			inspect = func(value any, path string) {
				switch v := value.(type) {
				case string:
					if strings.Contains(v, tenant) {
						paths = append(paths, path)
					}
				case map[string]any:
					for key, child := range v {
						inspect(child, path+"."+key)
					}
				case []any:
					for i, child := range v {
						inspect(child, path+"["+strconv.Itoa(i)+"]")
					}
				}
			}
			inspect(document, "package")
			t.Fatal("served package lost its private tenant binding; raw identity field paths", paths)
		}
		var pkg evidence.Package
		if err := json.Unmarshal(raw, &pkg); err != nil {
			t.Fatal(err)
		}
		found := false
		for _, record := range verified.Evidence {
			if record.Kind == "incident.impact" {
				for _, attachment := range pkg.Attachments {
					if attachment.Digest == record.AttachmentDigest {
						var retained incident.ImpactResponse
						if err := json.Unmarshal(attachment.Content, &retained); err != nil {
							t.Fatal(err)
						}
						assertIncidentImpactWeeks(t, retained, incidents[tenant], lane)
						found = true
					}
				}
			}
		}
		if !found {
			t.Fatal("signed package omitted the requested impact attachment")
		}
		if status, raw := export(tenant, incidents[f.tenants[1-lane]]); status != http.StatusNotFound || bytes.Contains(raw, []byte("\"signing\"")) {
			t.Fatal("foreign incident received a signed impact export", status, string(raw))
		}
	}
	a, b := f.tenants[0], f.tenants[1]
	f.in(a, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `DELETE FROM role_permissions WHERE tenant_id=$1 AND role_id=$2 AND permission_key='events.read'`, a, f.roles[a])
		return err
	})
	if status, raw := request(a, incidents[a]); status == http.StatusOK || bytes.Contains(raw, []byte("customer-"+a)) {
		t.Fatal("current permission withdrawal reused cached source disclosure", status, string(raw))
	}
	if status, raw := export(a, incidents[a]); status == http.StatusOK || bytes.Contains(raw, []byte("\"signing\"")) {
		t.Fatal("export reused withdrawn current source access", status, string(raw))
	}
	if status, raw := request(b, incidents[b]); status != http.StatusOK {
		t.Fatal("permission withdrawal affected the sibling tenant", status, string(raw))
	}
	f.in(a, func(ctx context.Context, sc tenancy.Scope) error {
		if err := (store.Roles{}).AddPermission(ctx, sc, f.roles[a], "events.read"); err != nil {
			return err
		}
		if err := tenancy.LockTenantAuditStream(ctx, sc.Q, a); err != nil {
			return err
		}
		return sourceepoch.InvalidateSourceGenerationInScope(ctx, sc)
	})
	if status, raw := request(a, incidents[a]); status == http.StatusOK || bytes.Contains(raw, []byte("customer-"+a)) {
		t.Fatal("active observation erasure exposed a provisional impact", status, string(raw))
	}
	if status, raw := export(a, incidents[a]); status == http.StatusOK || bytes.Contains(raw, []byte("\"signing\"")) {
		t.Fatal("active observation erasure exposed a signed impact", status, string(raw))
	}
	if status, raw := request(b, incidents[b]); status != http.StatusOK {
		t.Fatal("observation erasure affected the sibling tenant", status, string(raw))
	}
	f.in(a, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `UPDATE flow_snapshot_epochs SET invalidating=false,observation_erasing=false,transition_token=NULL WHERE tenant_id=$1`, a)
		return err
	})
	t.Log("real-integration: served HTTPS/signed export with app-role PostgreSQL/RLS, current permissions/erasure and authenticated capture storage; observations are modeled, full served population, real sender/week-baseline/native/both-theme qualification remains owed")
}

func assertIncidentImpactWeeks(t *testing.T, out incident.ImpactResponse, id string, lane int) {
	t.Helper()
	current, previous := strconv.Itoa((100+lane)*3), strconv.Itoa((70+lane)*3)
	if out.IncidentID != id || len(out.Customers) != 1 || out.ObservedByteChange != "90" ||
		out.Current.AttestedRecords != 1 || out.Current.ObservedTotals == nil || out.Current.ObservedTotals.ScaledBytes != current ||
		out.Previous.AttestedRecords != 1 || out.Previous.ObservedTotals == nil || out.Previous.ObservedTotals.ScaledBytes != previous ||
		len(out.Current.Captures) != 1 || len(out.Previous.Captures) != 1 || out.Current.Captures[0].Key == out.Previous.Captures[0].Key {
		t.Fatal("comparison lost separate cited periods or exact owned totals", out)
	}
	customer := out.Customers[0]
	if customer.Current == nil || customer.Previous == nil || customer.Current.ScaledBytes != current ||
		customer.Previous.ScaledBytes != previous || len(customer.CaptureKeys) != 2 {
		t.Fatal("comparison lost the customer's two observation windows", customer)
	}
}
