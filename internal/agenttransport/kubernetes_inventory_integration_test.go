// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package agenttransport_test

import (
	"bytes"
	"context"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/ctlplne/probectl/internal/agent"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/entity"
	agentv1 "github.com/ctlplne/probectl/internal/gen/probectl/agent/v1"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport"
)

func TestKubernetesInventoryMTLSPublishesCompleteOwnedGenerations(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	pool := setup(ctx, t)
	t.Cleanup(pool.Close)
	testsupport.LockPostgresPublicCatalog(t, pool)
	server := startTestServer(ctx, t, pool)
	contextID, clusterID, generation := newUUID(t), newUUID(t), newUUID(t)
	red := seedKubernetesWireLane(ctx, t, pool, server, contextID, clusterID, "red")
	blue := seedKubernetesWireLane(ctx, t, pool, server, contextID, clusterID, "blue")
	var from, until time.Time
	if err := pool.QueryRow(ctx, `SELECT clock_timestamp(),clock_timestamp()+interval '2 milliseconds'`).Scan(&from, &until); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `SELECT pg_sleep(0.005)`); err != nil {
		t.Fatal(err)
	}
	for _, lane := range []kubernetesWireLane{red, blue} {
		begin, parts := kubernetesWireInventory(t, lane.name, from, until)
		upload := &agentv1.KubernetesInventoryUpload{BindingId: lane.binding, GenerationId: generation}
		upload.Operation = &agentv1.KubernetesInventoryUpload_Begin{Begin: begin}
		foreign := blue
		if lane.tenant == blue.tenant {
			foreign = red
		}
		if _, err := foreign.client.SubmitKubernetesInventory(ctx, upload); status.Code(err) != codes.PermissionDenied {
			t.Fatalf("foreign certificate reached inventory binding: %v", err)
		}
		send := func(want codes.Code) *agentv1.KubernetesInventoryReceipt {
			t.Helper()
			ack, err := lane.client.SubmitKubernetesInventory(ctx, upload)
			if status.Code(err) != want {
				t.Fatalf("tenant %s operation %T: got %v, want %v", lane.name, upload.Operation, err, want)
			}
			return ack
		}
		if ack := send(codes.OK); ack.Published || ack.NextPart != 0 {
			t.Fatal("begin published or skipped a part", ack)
		}
		upload.Operation = &agentv1.KubernetesInventoryUpload_Publish{Publish: &agentv1.KubernetesInventoryPublish{}}
		send(codes.FailedPrecondition)
		assertKubernetesWireRows(ctx, t, pool, lane, 0)
		upload.Operation = &agentv1.KubernetesInventoryUpload_Append{Append: parts[1]}
		send(codes.FailedPrecondition)
		upload.Operation = &agentv1.KubernetesInventoryUpload_Append{Append: parts[0]}
		for range 2 {
			if ack := send(codes.OK); ack.NextPart != 1 || ack.RetainedRows != 1 {
				t.Fatal("exact replay advanced the stage twice", ack)
			}
		}
		altered := proto.CloneOf(parts[0])
		altered.Rows[0].GetAddress().Address = "10.244.0.5"
		upload.Operation = &agentv1.KubernetesInventoryUpload_Append{Append: altered}
		send(codes.AlreadyExists)
		upload.Operation = &agentv1.KubernetesInventoryUpload_Append{Append: parts[1]}
		send(codes.OK)
		assertKubernetesWireRows(ctx, t, pool, lane, 0)
		upload.Operation = &agentv1.KubernetesInventoryUpload_Publish{Publish: &agentv1.KubernetesInventoryPublish{}}
		for range 2 {
			if ack := send(codes.OK); !ack.Published || ack.RetainedRows != 2 || !bytes.Equal(ack.PayloadDigest, begin.PayloadDigest) {
				t.Fatal("receipt lost the complete retained generation", ack)
			}
		}
		assertKubernetesWireRows(ctx, t, pool, lane, 1)
	}
	assertKubernetesWireRows(ctx, t, pool, red, 1)
	closeSource := func(tenant, source string) error {
		return tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenant)), pool, func(ctx context.Context, sc tenancy.Scope) error {
			_, err := store.RevokeKubernetesInventorySourceInScope(ctx, sc, contextID, source)
			return err
		})
	}
	if err := closeSource(blue.tenant, red.binding); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatal("sibling tenant reached a source assignment", err)
	}
	if err := closeSource(red.tenant, red.binding); err != nil {
		t.Fatal(err)
	}
	for _, lane := range []kubernetesWireLane{red, blue} {
		ack, err := lane.client.SubmitKubernetesInventory(ctx, &agentv1.KubernetesInventoryUpload{
			BindingId: lane.binding, GenerationId: generation,
			Operation: &agentv1.KubernetesInventoryUpload_Publish{Publish: &agentv1.KubernetesInventoryPublish{}},
		})
		if lane.tenant == red.tenant {
			if status.Code(err) != codes.PermissionDenied {
				t.Fatal("a revoked source retained publication authority", err)
			}
		} else if err != nil || !ack.GetPublished() {
			t.Fatal("revoking one tenant changed its sibling's authority", err)
		}
	}
	assertKubernetesWireRead(ctx, t, pool, contextID, red, from, until, false)
	assertKubernetesWireRead(ctx, t, pool, contextID, blue, from, until, true)
}

type kubernetesWireLane struct {
	name, tenant, binding string
	client                *agent.EvidenceClient
}

func seedKubernetesWireLane(ctx context.Context, t *testing.T, pool *pgxpool.Pool, server testServer,
	contextID, clusterID, name string) kubernetesWireLane {
	t.Helper()
	tenant, err := store.NewTenants(pool).Create(ctx, fmt.Sprintf("k8s-evidence-%s-%d", name, time.Now().UnixNano()), name)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := pool.Exec(context.Background(), `DELETE FROM tenants WHERE id=$1`, tenant.ID); err != nil {
			t.Error(err)
		}
	})
	collector := newUUID(t)
	var binding string
	spiffe := crypto.EntitySPIFFEID(tenant.ID, collector)
	cert, key, err := server.ca.IssueClientCert(collector, spiffe, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(cert)
	if block == nil {
		t.Fatal("no issued evidence certificate")
	}
	leaf, err := crypto.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.NewAgentIdentities(pool).Record(ctx, tenant.ID, collector, spiffe, leaf.SerialNumber.Text(16), leaf.NotAfter, ""); err != nil {
		t.Fatal(err)
	}
	if err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenant.ID)), pool, func(ctx context.Context, scope tenancy.Scope) error {
		if _, err := (store.Agents{}).Reserve(ctx, scope, collector, name, name, "", spiffe, nil); err != nil {
			return err
		}
		if _, err := scope.Q.Exec(ctx, `INSERT INTO entity_contexts(tenant_id,id,site_id,vrf_id,site_label,vrf_label)
VALUES ($1,$2,$3,$4,'kubernetes','lab')`, tenant.ID, contextID, newUUID(t), newUUID(t)); err != nil {
			return err
		}
		if _, err := scope.Q.Exec(ctx, `INSERT INTO entity_agent_contexts(tenant_id,agent_id,context_id) VALUES($1,$2,$3)`, tenant.ID, collector, contextID); err != nil {
			return err
		}
		source, err := store.CreateKubernetesInventorySourceInScope(ctx, scope, contextID,
			store.KubernetesInventorySourceInput{ClusterID: clusterID, Namespace: "inventory", AgentID: collector})
		binding = source.ID
		return err
	}); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	client, err := agent.DialEntityEvidence(server.addr, writeTemp(t, dir, "k8s.crt", cert), writeTemp(t, dir, "k8s.key", key), server.caFile, "localhost")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return kubernetesWireLane{name: name, tenant: tenant.ID, binding: binding, client: client}
}

func kubernetesWireInventory(t *testing.T, name string, from, until time.Time) (*agentv1.KubernetesInventoryBegin, []*agentv1.KubernetesInventoryPart) {
	t.Helper()
	const pod = agentv1.KubernetesInventoryKind_KUBERNETES_INVENTORY_KIND_POD
	parts := []*agentv1.KubernetesInventoryPart{
		{Rows: []*agentv1.KubernetesInventoryRow{{Record: &agentv1.KubernetesInventoryRow_Address{
			Address: &agentv1.KubernetesInventoryAddress{Kind: pod, Uid: "shared-pod", Address: "10.244.0.4"}}}}},
		{Index: 1, Rows: []*agentv1.KubernetesInventoryRow{{Record: &agentv1.KubernetesInventoryRow_Object{
			Object: &agentv1.KubernetesInventoryObject{Kind: pod, Uid: "shared-pod", Name: name}}}}},
	}
	manifest := &agentv1.KubernetesInventoryManifest{Parts: 2, Rows: 2, Windows: []*agentv1.KubernetesInventoryWindow{
		{Kind: pod, FirstListVersion: "184467440737095516160", LastListVersion: "184467440737095516161",
			WatchProgressVersion: "184467440737095516162", FirstReadCompleteUnixNano: from.UnixNano(), LastReadStartUnixNano: until.UnixNano()},
	}}
	marshal := proto.MarshalOptions{Deterministic: true}
	var framed []io.Reader
	for _, part := range parts {
		wire, err := marshal.Marshal(part)
		if err != nil {
			t.Fatal(err)
		}
		manifest.PayloadBytes += uint64(len(wire))
		framed = append(framed, entity.FrameKubernetesInventoryRecord(wire))
	}
	manifestWire, err := marshal.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := entity.HashKubernetesInventory(manifestWire, io.MultiReader(framed...))
	if err != nil {
		t.Fatal(err)
	}
	return &agentv1.KubernetesInventoryBegin{Manifest: manifest, PayloadDigest: digest}, parts
}

func assertKubernetesWireRows(ctx context.Context, t *testing.T, pool *pgxpool.Pool, lane kubernetesWireLane, expected int) {
	t.Helper()
	if err := tenancy.InTenantReadSnapshot(tenancy.WithTenant(ctx, tenancy.ID(lane.tenant)), pool, func(ctx context.Context, scope tenancy.Scope) error {
		var own, all int
		if err := scope.Q.QueryRow(ctx, `SELECT count(*) FILTER (WHERE g.tenant_id=$1 AND o.object_name=$2 AND host(a.ip)='10.244.0.4'),count(*)
FROM kubernetes_inventory_generations g
JOIN kubernetes_inventory_objects o ON (o.tenant_id,o.context_id,o.source_id,o.generation_id)=(g.tenant_id,g.context_id,g.source_id,g.id)
JOIN kubernetes_inventory_addresses a ON (a.tenant_id,a.context_id,a.source_id,a.generation_id,a.window_index,a.object_kind,a.object_uid)=
    (o.tenant_id,o.context_id,o.source_id,o.generation_id,o.window_index,o.object_kind,o.object_uid)`, lane.tenant, lane.name).Scan(&own, &all); err != nil {
			return err
		}
		if own != expected || all != expected {
			return fmt.Errorf("inventory visibility: %d original and %d total rows, expected %d", own, all, expected)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func assertKubernetesWireRead(ctx context.Context, t *testing.T, pool *pgxpool.Pool, contextID string,
	lane kubernetesWireLane, from, until time.Time, allowed bool) {
	t.Helper()
	scope := entity.Scope{TenantID: lane.tenant, ContextID: contextID}
	if err := tenancy.InTenantReadSnapshot(tenancy.WithTenant(ctx, tenancy.ID(lane.tenant)), pool,
		func(ctx context.Context, sc tenancy.Scope) error {
			snapshot, err := store.ReadKubernetesInventoryInScope(ctx, sc, scope, from, until, 64<<10,
				func(source store.KubernetesInventorySource) error {
					if source.ID != lane.binding {
						return errors.New("a sibling inventory source reached the authority check")
					}
					return nil
				})
			if err != nil {
				return err
			}
			if !allowed {
				if len(snapshot.Sources) != 0 || len(snapshot.Facts) != 0 {
					return errors.New("read retained revoked inventory authority")
				}
				return nil
			}
			if len(snapshot.Sources) != 1 || len(snapshot.Facts) != 2 {
				return fmt.Errorf("unexpected owned inventory population %d/%d", len(snapshot.Sources), len(snapshot.Facts))
			}
			names, addresses := 0, 0
			for _, fact := range snapshot.Facts {
				if fact.WitnessUID != "shared-pod" || fact.SourceID != lane.binding {
					return errors.New("read returned an unexpected inventory witness")
				}
				if fact.Name == lane.name {
					names++
				}
				if fact.Address == "10.244.0.4" {
					addresses++
				}
			}
			if names != 1 || addresses != 1 {
				return fmt.Errorf("read did not preserve the authorized original name and address %d/%d", names, addresses)
			}
			projection, err := snapshot.AddressProjection(ctx, 64<<10)
			if err != nil {
				return err
			}
			if projection.Scope != scope || len(projection.Spans) != 1 || projection.Spans[0].Owner.Name != lane.name ||
				projection.Spans[0].Owner.UID != "shared-pod" || projection.Spans[0].Address.String() != "10.244.0.4" {
				return fmt.Errorf("projection lost the tenant-owned historical address: %+v", projection)
			}
			return nil
		}); err != nil {
		t.Fatal(err)
	}
}
