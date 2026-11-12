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
	"github.com/ctlplne/probectl/internal/incident"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/store/sourceepoch"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestIncidentImpactServesCompleteCurrentSourcesAndTenantIsolation(t *testing.T) {
	f := newRoleExplanationAPIFixture(t)
	key, _, err := crypto.GenerateEd25519KeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	f.server.WithEvidenceSigningKey(key)
	flows := flowstore.NewMemory()
	f.server.WithFlowStore(flows).WithFairness(fairness.NewGate(fairness.DefaultPolicy(), nil))
	incidents := map[string]string{}
	const agent = "impact-flow"
	const exporter = "192.0.2.1"
	for lane, tenant := range f.tenants {
		id, prefix, tag := gouuid.NewString(), gouuid.NewString(), gouuid.NewString()
		incidents[tenant] = id
		serial := strings.ReplaceAll(gouuid.NewString(), "-", "")
		if err := store.NewAgentIdentities(f.pool).Record(t.Context(), tenant, agent, crypto.EntitySPIFFEID(tenant, agent), serial, time.Now().Add(time.Hour), ""); err != nil {
			t.Fatal(err)
		}
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			for _, permission := range []string{"incident.read", "flow.read", "tags.read", "ai.query"} {
				if err := (store.Roles{}).AddPermission(ctx, sc, f.roles[tenant], permission); err != nil {
					return err
				}
			}
			if _, err := sc.Q.Exec(ctx, `INSERT INTO entity_agent_contexts(tenant_id,agent_id,context_id) VALUES($1,$2,$3)`, tenant, agent, f.contextID); err != nil {
				return err
			}
			if _, err := sc.Q.Exec(ctx, `INSERT INTO entity_source_contexts(tenant_id,agent_id,source_kind,source_ref,context_id,anchor_entity_id) VALUES($1,$2,'flow_exporter',$3,$4,$5)`, tenant, agent, exporter, f.contextID, f.routerID); err != nil {
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
		claim := entity.Observation{ID: gouuid.NewString(), Source: entity.SourceKey{AgentID: agent, Kind: entity.FlowExporter, SourceRef: exporter}, Alias: entity.AliasKey{Kind: entity.FlowExporterAlias, Value: exporter + "/ipfix/4294967295"}, SourceRef: "flow:ipfix:domain:4294967295", ObservedAt: f.observedAt(tenant)}
		accepted, unresolved, err := writeEntityEvidenceBatchForTest(tenancy.WithTenant(t.Context(), tenancy.ID(tenant)), store.NewEntityRegistry(f.pool), agent, serial, []entity.Observation{claim})
		if err != nil || accepted != 1 || unresolved != 0 {
			t.Fatal("impact source observation was not accepted", accepted, unresolved, err)
		}
		var raw [32]byte
		copy(raw[:], crypto.Hash([]byte("modeled authenticated impact observation "+tenant)))
		ref, err := store.NewBGPRoutingFlowCaptures(f.pool).CaptureAuthenticated(tenancy.WithTenant(t.Context(), tenancy.ID(tenant)), agent, raw,
			store.BGPRoutingFlowInput{Exporter: netip.MustParseAddr(exporter), Source: netip.MustParseAddr("203.0.113.1"), Destination: netip.MustParseAddr("203.0.113.2"), Protocol: "ipfix", Domain: ^uint32(0)}, store.BGPRoutingBudget{MemoryBytes: 128 << 20, WorkUnits: 128 << 20, StateBytes: 128 << 20})
		if err != nil {
			t.Fatal(err)
		}
		if err := flows.Insert(t.Context(), []flowstore.Row{{TenantID: tenant, AgentID: agent, Exporter: exporter, Protocol: "ipfix", ObsDomain: ^uint32(0), TS: ref.CapturedAt, StartTS: ref.CapturedAt,
			SrcAddr: "203.0.113.1", DstAddr: "203.0.113.2", InIf: 7, OutIf: 7, Bytes: uint64(100 + lane), Packets: 7, Sampling: 3, RawFlowDigest: hex.EncodeToString(raw[:]), RoutingCaptureKey: hex.EncodeToString(ref.Key[:]), RoutingCapturedUnixNanos: ref.CapturedAt.UnixNano()}}); err != nil {
			t.Fatal(err)
		}
	}
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
		if status != http.StatusOK || json.Unmarshal(raw, &out) != nil || out.IncidentID != incidents[tenant] || out.Current.AttestedRecords != 1 || out.Current.ObservedTotals == nil || out.Current.ObservedTotals.ScaledBytes != strconv.Itoa((100+lane)*3) || out.Previous.ObservedTotals != nil || len(out.Customers) != 1 || out.Customers[0].Value != "customer-"+tenant || len(out.Customers[0].CaptureKeys) != 1 {
			t.Fatal("HTTPS impact lost exact owned observations, customer union or unavailable baseline", status, string(raw))
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
						if retained.IncidentID != incidents[tenant] || retained.Current.ObservedTotals == nil || retained.Current.ObservedTotals.ScaledBytes != strconv.Itoa((100+lane)*3) || len(retained.Current.Captures) != 1 || len(retained.Customers) != 1 {
							t.Fatal("signed export lost exact owned counters or complete source/customer membership", retained)
						}
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
