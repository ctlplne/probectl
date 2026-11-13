// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration || isolation

package store

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/bgp"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestBMPPeerSessionRetentionReplayAndTenantIsolation(t *testing.T) {
	ctx := context.Background()
	pool := setup(ctx, t)
	defer pool.Close()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	a, err := NewTenants(pool).Create(ctx, "entity-bmp-a-"+suffix, "BMP A")
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewTenants(pool).Create(ctx, "entity-bmp-b-"+suffix, "BMP B")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := pool.Exec(context.Background(),
			`DELETE FROM tenants WHERE id=ANY($1::uuid[])`, []string{a.ID, b.ID}); err != nil {
			t.Errorf("remove BMP entity fixtures: %v", err)
		}
	}()
	const listener, router, address = "listener-auth", "router-auth", "10.42.0.1"
	contextID := uuid.NewString() // same context UUID and RFC1918 IP in both tenants
	serials := map[string]string{a.ID: "ab1234", b.ID: "cd5678"}
	listenerSerials := map[string]string{}
	entities := map[string]string{}
	for _, tenantID := range []string{a.ID, b.ID} {
		listenerSerials[tenantID] = strings.ReplaceAll(uuid.NewString(), "-", "")
		identities := NewAgentIdentities(pool)
		if err := identities.Record(ctx, tenantID, listener,
			crypto.EntitySPIFFEID(tenantID, listener), listenerSerials[tenantID],
			time.Now().Add(time.Hour), ""); err != nil {
			t.Fatal(err)
		}
		if err := identities.Record(ctx, tenantID, router,
			crypto.BMPSPIFFEID(tenantID, router), serials[tenantID],
			time.Now().Add(time.Hour), ""); err != nil {
			t.Fatal(err)
		}
		entities[tenantID] = uuid.NewString()
		inTenant(ctx, t, pool, tenantID, func(ctx context.Context, sc tenancy.Scope) error {
			if _, err := sc.Q.Exec(ctx, `INSERT INTO entity_contexts
				(tenant_id,id,site_id,vrf_id,site_label,vrf_label)
                VALUES ($1,$2,$3,$4,$3::uuid::text,$4::uuid::text)`,
				tenantID, contextID, uuid.NewString(), uuid.NewString()); err != nil {
				return err
			}
			if _, err := sc.Q.Exec(ctx, `INSERT INTO entity_agent_contexts
				(tenant_id,agent_id,context_id) VALUES ($1,$2,$3)`,
				tenantID, listener, contextID); err != nil {
				return err
			}
			if _, err := sc.Q.Exec(ctx, `INSERT INTO entities
				(tenant_id,context_id,id,kind,label) VALUES ($1,$2,$3,'device','router')`,
				tenantID, contextID, entities[tenantID]); err != nil {
				return err
			}
			_, err := sc.Q.Exec(ctx, `INSERT INTO entity_source_contexts
				(tenant_id,agent_id,source_kind,source_ref,context_id,anchor_entity_id)
				VALUES ($1,$2,'bmp_peer',$3,$4,$5)`, tenantID, listener,
				router, contextID, entities[tenantID])
			return err
		})
	}

	repo := NewEntityRegistry(pool)
	raw := make([]byte, 49)
	raw[0], raw[5] = 3, 2
	binary.BigEndian.PutUint32(raw[1:5], uint32(len(raw)))
	copy(raw[28:32], []byte{10, 42, 0, 1})
	binary.BigEndian.PutUint32(raw[32:36], 64500)
	copy(raw[36:40], []byte{10, 42, 0, 1})
	raw[48] = 4
	fact, err := bgp.DecodePhysicalPeerSession(ctx, raw, bgp.PeerMessageBudget{MemoryBytes: 1 << 20, WorkUnits: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	observationID := uuid.NewString()
	claims := map[string]entity.Observation{}
	for _, tenantID := range []string{a.ID, b.ID} {
		claim := entity.Observation{ID: observationID, Source: entity.SourceKey{AgentID: listener, Kind: entity.BMPPeer, SourceRef: router}, Alias: entity.AliasKey{Kind: entity.BMPPeerAlias, Value: address + "/as64500"}, SourceRef: "bmp:router:router-auth:peer-asn:64500", OriginSerial: serials[tenantID], ObservedAt: time.Now().UTC(), BMPPeerSession: fact}
		claim, err = claim.Normalize(time.Now())
		if err != nil {
			t.Fatal(err)
		}
		claims[tenantID] = claim
		receipt, err := repo.WriteEvidenceBatchReceipt(tenancy.WithTenant(ctx, tenancy.ID(tenantID)), listener, listenerSerials[tenantID], []entity.Observation{claim})
		if err != nil || receipt.Accepted != 1 || receipt.BMPPeerSessions != 1 || receipt.Unresolved != 0 {
			t.Fatal("typed session not retained", receipt, err)
		}
	}
	read := func(tenantID string) {
		t.Helper()
		inTenant(ctx, t, pool, tenantID, func(ctx context.Context, sc tenancy.Scope) error {
			rows, err := sc.Q.Query(ctx, `SELECT tenant_id::text,entity_id::text,bmp_peer_session FROM entity_evidence WHERE observation_id=$1`, observationID)
			if err != nil {
				return err
			}
			defer rows.Close()
			count := 0
			for rows.Next() {
				var owner, entityID string
				var body []byte
				if err := rows.Scan(&owner, &entityID, &body); err != nil {
					return err
				}
				var stored entity.BMPPeerSession
				if err := json.Unmarshal(body, &stored); err != nil {
					return err
				}
				if owner != tenantID || entityID != entities[tenantID] || stored.State != "down" || !bytes.Equal(stored.RawFrame, raw) {
					t.Fatal("tenant RLS or original bytes changed")
				}
				count++
			}
			if count != 1 {
				t.Fatal("tenant evidence was missing or leaked", count)
			}
			return rows.Err()
		})
	}
	read(a.ID)
	read(b.ID)
	for _, tenantID := range []string{a.ID, b.ID} {
		resolution, err := repo.ResolveAlias(tenancy.WithTenant(ctx, tenancy.ID(tenantID)), entity.Scope{TenantID: tenantID, ContextID: contextID}, claims[tenantID].Alias)
		if err != nil || resolution.Status != entity.Unresolved {
			t.Fatal("down frame created fresh peer identity", resolution, err)
		}
	}
	claim := claims[a.ID]
	replay, err := repo.WriteEvidenceBatchReceipt(tenancy.WithTenant(ctx, tenancy.ID(a.ID)), listener, listenerSerials[a.ID], []entity.Observation{claim})
	if err != nil || replay.Accepted != 1 || replay.BMPPeerSessions != 1 {
		t.Fatal("exact replay lost typed retention", replay, err)
	}
	changed := *fact
	changed.RawFrame = append([]byte(nil), raw...)
	changed.RawFrame[48] = 5
	changed, errValue := func() (entity.BMPPeerSession, error) {
		value, err := bgp.DecodePhysicalPeerSession(ctx, changed.RawFrame, bgp.PeerMessageBudget{MemoryBytes: 1 << 20, WorkUnits: 1 << 20})
		if err != nil {
			return entity.BMPPeerSession{}, err
		}
		return *value, nil
	}()
	if errValue != nil {
		t.Fatal(errValue)
	}
	claim.BMPPeerSession = &changed
	if _, err := repo.WriteEvidenceBatchReceipt(tenancy.WithTenant(ctx, tenancy.ID(a.ID)), listener, listenerSerials[a.ID], []entity.Observation{claim}); !errors.Is(err, entity.ErrConflictingEvidence) {
		t.Fatal("same UUID changed original session", err)
	}
	claim = claims[a.ID]
	claim.ID = uuid.NewString()
	claim.OriginSerial = serials[b.ID]
	receipt, err := repo.WriteEvidenceBatchReceipt(tenancy.WithTenant(ctx, tenancy.ID(a.ID)), listener, listenerSerials[a.ID], []entity.Observation{claim})
	if err != nil || receipt.Accepted != 0 || receipt.BMPPeerSessions != 0 || receipt.Unresolved != 1 {
		t.Fatal("foreign router serial crossed tenant boundary", receipt, err)
	}
	read(a.ID)
	read(b.ID)
}
