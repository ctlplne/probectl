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
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/ctlplne/probectl/internal/ai"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/config"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/entity"
	agentv1 "github.com/ctlplne/probectl/internal/gen/probectl/agent/v1"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/pathstore"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/topology"
)

func TestKubernetesInventorySourceRoutesAreAuditedAndTenantBound(t *testing.T) {
	f := newRoleExplanationAPIFixture(t)
	f.server.WithTopology(topology.NewMemoryStore())
	socket := httptest.NewTLSServer(f.server.Handler())
	t.Cleanup(socket.Close)
	path := strings.ReplaceAll(kubernetesSourcePath, "{context_id}", f.contextID)
	cluster := uuid(t)
	agents, sources := [2]string{uuid(t), uuid(t)}, [2]store.KubernetesInventorySource{}
	request := func(lane int, method, path string, body *store.KubernetesInventorySourceInput, want int) []byte {
		t.Helper()
		var payload []byte
		if body != nil {
			var err error
			payload, err = json.Marshal(body)
			if err != nil {
				t.Fatal(err)
			}
		}
		ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, method, socket.URL+path, bytes.NewReader(payload))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+f.tokens[f.tenants[lane]])
		res, err := socket.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		if res.StatusCode != want {
			t.Fatalf("%s inventory source for tenant %d returned %d, want %d", method, lane, res.StatusCode, want)
		}
		raw, err := io.ReadAll(res.Body)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	call := func(lane int, method, path string, body *store.KubernetesInventorySourceInput, want int) store.KubernetesInventorySource {
		t.Helper()
		raw := request(lane, method, path, body, want)
		var out store.KubernetesInventorySource
		if want < http.StatusBadRequest {
			if err := json.Unmarshal(raw, &out); err != nil {
				t.Fatal(err)
			}
		}
		return out
	}
	for lane, tenant := range f.tenants {
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			if err := (store.Roles{}).AddPermission(ctx, sc, f.roles[tenant], ai.PermTopologyRead); err != nil {
				return err
			}
			if _, err := (store.Agents{}).Reserve(ctx, sc, agents[lane], "inventory", "fixture", "", crypto.AgentSPIFFEID(tenant, agents[lane]), nil); err != nil {
				return err
			}
			_, err := sc.Q.Exec(ctx, `INSERT INTO entity_agent_contexts(tenant_id,agent_id,context_id) VALUES($1,$2,$3)`,
				tenant, agents[lane], f.contextID)
			return err
		})
		tolerance := int64(lane + 2)
		sources[lane] = call(lane, http.MethodPost, path,
			&store.KubernetesInventorySourceInput{ClusterID: cluster, Namespace: "inventory", AgentID: agents[lane],
				FlowClockErrorMS: &tolerance},
			http.StatusCreated)
		if sources[lane].ID == "" || sources[lane].AgentID != agents[lane] || sources[lane].ContextID != f.contextID ||
			sources[lane].FlowClockErrorMS == nil || *sources[lane].FlowClockErrorMS != tolerance {
			t.Fatal("assignment lost its tenant-owned collector and context", sources[lane])
		}
	}
	topologyPath := "/v1/topology?include_kubernetes=true&context_id=" + f.contextID
	observations := [2][2]time.Time{}
	for lane, tenant := range f.tenants {
		observations[lane][0], observations[lane][1] = seedKubernetesTopologyFixture(t, f, tenant, sources[lane], lane)
	}
	for lane, observed := range observations {
		seenAt, expires := observed[0], observed[1]
		for _, endpoint := range []string{topologyPath, topologyPath + "&at=" + seenAt.UTC().Format(time.RFC3339Nano)} {
			raw := request(lane, http.MethodGet, endpoint, nil, http.StatusOK)
			var graph topology.Viz
			if err := json.Unmarshal(raw, &graph); err != nil {
				t.Fatal(err)
			}
			assertKubernetesTopologyFixture(t, graph, lane, cluster, seenAt, expires)
		}
	}
	seedInterfaceRoleMCPConsent(f)
	mcpConfig := &config.Config{}
	mcpServer := NewMCPServerWithPolicyLoader(mcpConfig, f.server.log, f.pool, pathstore.NewMemory(), 0,
		NewAIEgressGate(mcpConfig, f.server.log, f.pool), nil, nil, f.server.MCPPolicyLoader(), AISources{NativeFlow: f.server})
	authenticator := NewMCPAuthenticator(f.pool, NewTenantStatusCache(f.pool, 0), false)
	const mcpWire = "2026-07-28"
	for lane, tenant := range f.tenants {
		client := openInterfaceRoleStdio(t, mcpServer, authenticator, f.tokens[tenant], mcpWire)
		var graph topology.Viz
		client.call(t, mcpWire, "topology_kubernetes", map[string]any{"context_id": f.contextID}, &graph, true)
		assertKubernetesTopologyFixture(t, graph, lane, cluster, observations[lane][0], observations[lane][1])
	}
	call(0, http.MethodPost, path, &store.KubernetesInventorySourceInput{
		ClusterID: cluster, Namespace: "sibling", AgentID: agents[1],
	}, http.StatusNotFound)
	call(0, http.MethodDelete, path+"/"+sources[1].ID, nil, http.StatusNotFound)
	var policyID string
	f.in(f.tenants[0], func(ctx context.Context, sc tenancy.Scope) error {
		policy, err := (store.ABACPolicies{}).Create(ctx, sc, auth.Policy{
			Name: "deny-inventory-collector", Enabled: true, Effect: auth.PolicyDeny, Permission: permAgentWrite,
			Resource: map[string]string{"agent_id": agents[0]}, Priority: 100,
		})
		policyID = policy.ID
		return err
	})
	call(0, http.MethodDelete, path+"/"+sources[0].ID, nil, http.StatusForbidden)
	f.in(f.tenants[0], func(ctx context.Context, sc tenancy.Scope) error {
		var active bool
		if err := sc.Q.QueryRow(ctx, `SELECT closed_at IS NULL FROM kubernetes_inventory_sources
WHERE tenant_id=$1 AND context_id=$2 AND id=$3`, f.tenants[0], f.contextID, sources[0].ID).Scan(&active); err != nil {
			return err
		}
		if !active {
			t.Fatal("source revocation survived the collector policy check")
		}
		return (store.ABACPolicies{}).Delete(ctx, sc, policyID)
	})
	for lane, tenant := range f.tenants {
		out := call(lane, http.MethodDelete, path+"/"+sources[lane].ID, nil, http.StatusOK)
		if out.ID != sources[lane].ID || out.AgentID != agents[lane] || out.ClosedAt == nil {
			t.Fatal("revocation did not close the exact owned source", out)
		}
		var graph topology.Viz
		if err := json.Unmarshal(request(lane, http.MethodGet, topologyPath, nil, http.StatusOK), &graph); err != nil ||
			len(graph.Nodes) != 0 || len(graph.Edges) != 0 {
			t.Fatal("revoked topology authority remained visible", err, graph)
		}
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			var assigned, revoked, all int
			if err := sc.Q.QueryRow(ctx, `
SELECT count(*) FILTER (WHERE action='kubernetes.inventory_source.assigned' AND target=$2),
       count(*) FILTER (WHERE action='kubernetes.inventory_source.revoked' AND target=$2),count(*)
FROM audit_events WHERE tenant_id=$1 AND action IN ('kubernetes.inventory_source.assigned','kubernetes.inventory_source.revoked')`,
				tenant, sources[lane].ID).Scan(&assigned, &revoked, &all); err != nil {
				return err
			}
			if assigned != 1 || revoked != 1 || all != 2 {
				return fmt.Errorf("unexpected source assignment or revocation audits: %d/%d/%d", assigned, revoked, all)
			}
			return nil
		})
	}
}

func seedKubernetesTopologyFixture(t *testing.T, fixture *roleExplanationAPIFixture, tenant string,
	source store.KubernetesInventorySource, lane int) (time.Time, time.Time) {
	t.Helper()
	const (
		pod   = agentv1.KubernetesInventoryKind_KUBERNETES_INVENTORY_KIND_POD
		svc   = agentv1.KubernetesInventoryKind_KUBERNETES_INVENTORY_KIND_SERVICE
		slice = agentv1.KubernetesInventoryKind_KUBERNETES_INVENTORY_KIND_ENDPOINT_SLICE
	)
	serial := strings.ReplaceAll(uuid(t), "-", "")
	if err := store.NewAgentIdentities(fixture.pool).Record(t.Context(), tenant, source.AgentID,
		crypto.EntitySPIFFEID(tenant, source.AgentID), serial, time.Now().Add(time.Hour), ""); err != nil {
		t.Fatal(err)
	}
	generation := uuid(t)
	var from, until time.Time
	fixture.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
		if err := sc.Q.QueryRow(ctx, `WITH sampled AS MATERIALIZED (SELECT clock_timestamp() AS at)
SELECT at,at+interval '24 milliseconds' FROM sampled`).Scan(&from, &until); err != nil {
			return err
		}
		if _, err := sc.Q.Exec(ctx, `SELECT pg_sleep(0.03)`); err != nil {
			return err
		}
		object := func(window uint32, kind agentv1.KubernetesInventoryKind, uid, name string) *agentv1.KubernetesInventoryRow {
			return &agentv1.KubernetesInventoryRow{WindowIndex: window, Record: &agentv1.KubernetesInventoryRow_Object{
				Object: &agentv1.KubernetesInventoryObject{Kind: kind, Uid: uid, Name: name},
			}}
		}
		rows := []*agentv1.KubernetesInventoryRow{
			object(0, pod, "shared-pod", fmt.Sprintf("pod-%d", lane)), object(1, svc, "shared-svc", fmt.Sprintf("service-%d", lane)),
			object(2, slice, "shared-slice", "owned-slice"),
			{WindowIndex: 0, Record: &agentv1.KubernetesInventoryRow_Address{Address: &agentv1.KubernetesInventoryAddress{
				Kind: pod, Uid: "shared-pod", Address: "10.244.0.15",
			}}},
			{WindowIndex: 2, Record: &agentv1.KubernetesInventoryRow_Relationship{Relationship: &agentv1.KubernetesInventoryRelationship{
				Relation: agentv1.KubernetesInventoryRelationshipKind_KUBERNETES_INVENTORY_RELATIONSHIP_KIND_SERVICE_BACKEND,
				FromKind: svc, FromUid: "shared-svc", ToKind: pod, ToUid: "shared-pod", EndpointSliceUid: "shared-slice",
			}}},
		}
		part := &agentv1.KubernetesInventoryPart{Rows: rows}
		wire := proto.MarshalOptions{Deterministic: true}
		partBytes, err := wire.Marshal(part)
		if err != nil {
			return err
		}
		manifest := &agentv1.KubernetesInventoryManifest{Parts: 1, Rows: uint64(len(rows)), PayloadBytes: uint64(len(partBytes))}
		for _, kind := range []agentv1.KubernetesInventoryKind{pod, svc, slice} {
			manifest.Windows = append(manifest.Windows, &agentv1.KubernetesInventoryWindow{
				Kind: kind, FirstListVersion: "10", LastListVersion: "10",
				FirstReadCompleteUnixNano: from.UnixNano(), LastReadStartUnixNano: until.UnixNano(),
			})
		}
		manifestBytes, err := wire.Marshal(manifest)
		if err != nil {
			return err
		}
		digest, err := entity.HashKubernetesInventory(manifestBytes, entity.FrameKubernetesInventoryRecord(partBytes))
		if err != nil {
			return err
		}
		upload := &agentv1.KubernetesInventoryUpload{BindingId: source.ID, GenerationId: generation,
			Operation: &agentv1.KubernetesInventoryUpload_Begin{Begin: &agentv1.KubernetesInventoryBegin{Manifest: manifest, PayloadDigest: digest}}}
		if _, err := store.WriteKubernetesInventoryInScope(ctx, sc, source.AgentID, serial, upload); err != nil {
			return err
		}
		upload.Operation = &agentv1.KubernetesInventoryUpload_Append{Append: part}
		if _, err := store.WriteKubernetesInventoryInScope(ctx, sc, source.AgentID, serial, upload); err != nil {
			return err
		}
		upload.Operation = &agentv1.KubernetesInventoryUpload_Publish{Publish: &agentv1.KubernetesInventoryPublish{}}
		_, err = store.WriteKubernetesInventoryInScope(ctx, sc, source.AgentID, serial, upload)
		return err
	})
	return from, until
}

func assertKubernetesTopologyFixture(t *testing.T, graph topology.Viz, lane int, cluster string, from, until time.Time) {
	t.Helper()
	if len(graph.Nodes) != 2 || len(graph.Edges) != 1 || graph.Edges[0].Kind != "kubernetes_backend" {
		t.Fatal("graph lost the original Service or Pod relationship", graph)
	}
	labels := map[string]string{"shared-pod": fmt.Sprintf("pod-%d", lane), "shared-svc": fmt.Sprintf("service-%d", lane)}
	for _, node := range graph.Nodes {
		object := node.Kubernetes
		if object == nil || node.Label != labels[object.UID] || object.ClusterID != cluster || object.Namespace != "inventory" ||
			object.ObservedAt.Before(from) || !object.ObservedAt.Before(until) || !object.ObservedAt.Equal(graph.Edges[0].ObservedAt) {
			t.Fatal("graph returned another tenant or an incorrect observation time", node)
		}
	}
}
