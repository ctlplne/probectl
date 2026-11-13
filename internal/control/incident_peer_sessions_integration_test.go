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
	"encoding/binary"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	gouuid "github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/bgp"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestIncidentPeerSessionHistoryKeepsOriginalBytesAndTenantAuthority(t *testing.T) {
	f := newRoleExplanationAPIFixture(t)
	// Canonical context/router IDs intentionally match in both tenants.
	type lane struct {
		id       string
		actor    *auth.Principal
		from, to time.Time
		snapshot incidentVerdictSnapshot
	}
	lanes := map[string]*lane{}
	raw := make([]byte, 49)
	raw[0], raw[5], raw[48] = 3, 2, 4
	binary.BigEndian.PutUint32(raw[1:5], uint32(len(raw)))
	copy(raw[28:32], []byte{192, 0, 2, 7})
	binary.BigEndian.PutUint32(raw[32:36], 4294967295)
	for _, tenant := range f.tenants {
		value := &lane{id: gouuid.NewString()}
		lanes[tenant] = value
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			for _, permission := range []string{permIncidentRead, permTestRead} {
				if err := (store.Roles{}).AddPermission(ctx, sc, f.roles[tenant], permission); err != nil {
					return err
				}
			}
			if _, err := sc.Q.Exec(ctx, `INSERT INTO incidents(tenant_id,id,title,entity_context_id,entity_id,identity_lookup_attempted) VALUES($1,$2,'original physical session',$3,$4,true)`, tenant, value.id, f.contextID, f.interfaceID); err != nil {
				return err
			}
			current, err := readCurrentUserAuthorityScope(ctx, sc, f.users[tenant])
			if err == nil {
				value.actor = auth.ClonePrincipal(current.principal)
			}
			return err
		})
		at := f.observedAt(tenant)
		value.from, value.to = at, at.Add(time.Nanosecond)
		fact, err := bgp.DecodePhysicalPeerSession(t.Context(), raw, bgp.PeerMessageBudget{MemoryBytes: 1 << 20, WorkUnits: 1 << 20})
		if err != nil {
			t.Fatal(err)
		}
		claim := entity.Observation{ID: gouuid.NewString(), Source: entity.SourceKey{AgentID: "role-listener", Kind: entity.BMPPeer, SourceRef: "role-router"}, Alias: entity.AliasKey{Kind: entity.BMPPeerAlias, Value: "192.0.2.7/as4294967295"}, SourceRef: "bmp:router:role-router:peer-asn:4294967295", OriginSerial: f.serials[tenant+"role-router"], ObservedAt: at, BMPPeerSession: fact}
		accepted, unresolved, err := writeEntityEvidenceBatchForTest(tenancy.WithTenant(t.Context(), tenancy.ID(tenant)), store.NewEntityRegistry(f.pool), "role-listener", f.serials[tenant+"role-listener"], []entity.Observation{claim})
		if err != nil || accepted != 1 || unresolved != 0 {
			t.Fatal("original peer session refused", accepted, unresolved, err)
		}
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
		value.snapshot, err = f.server.loadIncidentVerdictSnapshot(ctx, value.actor, value.id, value.from, value.to, 64<<20, nil)
		if err != nil || len(value.snapshot.peerSessions) != 1 {
			t.Fatal("complete nanosecond peer window was lost", len(value.snapshot.peerSessions), err)
		}
		read := value.snapshot.peerSessions[0]
		if read.TenantID != tenant || read.ContextID != f.contextID || read.RouterID != f.routerID || !read.SourceCurrent || read.Session == nil || read.Session.State != "down" || !bytes.Equal(read.Session.RawFrame, raw) || !read.ObservedAt.Equal(at) || read.CaptureDigest == ([32]byte{}) {
			t.Fatal("peer bytes, current source or compound scope changed")
		}
		if _, err := f.server.loadIncidentVerdictSnapshot(ctx, value.actor, value.id, value.from, value.to, 64<<20, &value.snapshot); err != nil {
			t.Fatal("unchanged original peer selectors refused", err)
		}
	}
	a, b := f.tenants[0], f.tenants[1]
	if got, err := f.server.loadIncidentVerdictSnapshot(tenancy.WithTenant(t.Context(), tenancy.ID(b)), lanes[b].actor, lanes[b].id, lanes[a].from, lanes[a].to, 64<<20, &lanes[a].snapshot); err == nil || !reflect.DeepEqual(got, incidentVerdictSnapshot{}) {
		t.Fatal("foreign originals became a tenant read", err)
	}
	changed := append([]byte(nil), raw...)
	changed[48] = 5
	fact, err := bgp.DecodePhysicalPeerSession(t.Context(), changed, bgp.PeerMessageBudget{MemoryBytes: 1 << 20, WorkUnits: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(fact)
	if err != nil {
		t.Fatal(err)
	}
	f.in(a, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `UPDATE entity_evidence SET bmp_peer_session=$3::jsonb WHERE tenant_id=$1 AND id=$2`, a, lanes[a].snapshot.peerSessions[0].EvidenceID, body)
		return err
	})
	if got, err := f.server.loadIncidentVerdictSnapshot(tenancy.WithTenant(t.Context(), tenancy.ID(a)), lanes[a].actor, lanes[a].id, lanes[a].from, lanes[a].to, 64<<20, &lanes[a].snapshot); err == nil || !reflect.DeepEqual(got, incidentVerdictSnapshot{}) {
		t.Fatal("changed original session retained publication authority", err)
	}
	if _, err := f.server.loadIncidentVerdictSnapshot(tenancy.WithTenant(t.Context(), tenancy.ID(b)), lanes[b].actor, lanes[b].id, lanes[b].from, lanes[b].to, 64<<20, &lanes[b].snapshot); err != nil {
		t.Fatal("one tenant's mutation affected its sibling", err)
	}
	f.in(b, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `UPDATE agent_identities SET revoked_at=clock_timestamp(),revoked_by='operator' WHERE tenant_id=$1 AND agent_id='role-router' AND serial=$2`, b, f.serials[b+"role-router"])
		return err
	})
	if got, err := f.server.loadIncidentVerdictSnapshot(tenancy.WithTenant(t.Context(), tenancy.ID(b)), lanes[b].actor, lanes[b].id, lanes[b].from, lanes[b].to, 64<<20, &lanes[b].snapshot); err == nil || !reflect.DeepEqual(got, incidentVerdictSnapshot{}) {
		t.Fatal("revoked router retained original session publication", err)
	}
	t.Log("real-integration: original whole BMP frames through actual tenant RLS storage and current snapshot/publication readers; frames and issued identities modeled, physical router/mTLS and domain faults remain separate")
}
