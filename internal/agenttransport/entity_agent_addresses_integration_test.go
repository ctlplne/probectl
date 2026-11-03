// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package agenttransport_test

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/ctlplne/probectl/internal/agent"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tags"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport"
)

// Real evidence client + listener + mTLS + PostgreSQL, not a release/four-store receipt.
func TestAgentAddressSnapshotRealMTLSClientKeepsTenantAndMetadataPresence(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	pool := setup(ctx, t)
	t.Cleanup(pool.Close)
	testsupport.LockPostgresPublicCatalog(t, pool)
	ts := startTestServer(ctx, t, pool)
	type lane struct {
		tenant, agent string
		client        *agent.EvidenceClient
	}
	var lanes []lane
	contextID, siteID, tagID := newUUID(t), newUUID(t), newUUID(t)
	for _, suffix := range []string{"a", "b"} {
		tenant, err := store.NewTenants(pool).Create(ctx, fmt.Sprintf("agent-address-wire-%s-%d", suffix, time.Now().UnixNano()), suffix)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if _, err := pool.Exec(context.Background(), `DELETE FROM tenants WHERE id=$1`, tenant.ID); err != nil {
				t.Error(err)
			}
		})
		agentID := newUUID(t)
		var cert, key []byte
		for _, uri := range []string{crypto.AgentSPIFFEID(tenant.ID, agentID), crypto.EntitySPIFFEID(tenant.ID, agentID)} {
			cert, key, err = ts.ca.IssueClientCert(agentID, uri, time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			block, _ := pem.Decode(cert)
			if block == nil {
				t.Fatal("QA certificate missing")
			}
			leaf, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				t.Fatal(err)
			}
			if err := store.NewAgentIdentities(pool).Record(ctx, tenant.ID, agentID, uri, leaf.SerialNumber.Text(16), leaf.NotAfter, ""); err != nil {
				t.Fatal(err)
			}
		}
		if err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenant.ID)), pool, func(ctx context.Context, sc tenancy.Scope) error {
			if _, err := (store.Agents{}).Register(ctx, sc, agentID, "wire-agent", "10.2.0.99", "fixture", crypto.AgentSPIFFEID(tenant.ID, agentID), nil); err != nil {
				return err
			}
			if _, err := sc.Q.Exec(ctx, `INSERT INTO entity_contexts(tenant_id,id,site_id,vrf_id,site_label,vrf_label) VALUES ($1,$2,$3,$4,'same-site','same-vrf')`, tenant.ID, contextID, siteID, newUUID(t)); err != nil {
				return err
			}
			if _, err := sc.Q.Exec(ctx, `INSERT INTO entities(tenant_id,context_id,id,kind,label) VALUES ($1,$2,$3,'site','operator-site')`, tenant.ID, contextID, siteID); err != nil {
				return err
			}
			if err := store.NewEntityRegistry(pool).AssignEntitySource(ctx, sc, entity.SourceKey{AgentID: agentID, Kind: entity.AgentSite, SourceRef: agentID}, contextID, siteID); err != nil {
				return err
			}
			if _, err := sc.Q.Exec(ctx, `INSERT INTO tenant_tag_definitions(tenant_id,id,key) VALUES ($1,$2,'network')`, tenant.ID, tagID); err != nil {
				return err
			}
			_, err := (store.TagRules{}).Create(ctx, sc, tags.Rule{Scope: tags.Scope{TenantID: tenant.ID, ContextID: contextID}, TagID: tagID, TargetKind: "agent", Match: "cidr", AddressSide: "agent", CIDR: "10.2.0.0/24", Value: tenant.ID})
			return err
		}); err != nil {
			t.Fatal(err)
		}
		dir := t.TempDir()
		client, err := agent.DialEntityEvidence(ts.addr, writeTemp(t, dir, "evidence.crt", cert), writeTemp(t, dir, "evidence.key", key), ts.caFile, "localhost")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = client.Close() })
		lanes = append(lanes, lane{tenant.ID, agentID, client})
	}
	submit := func(lane lane, addresses []netip.Addr) error {
		item := entity.Observation{ID: newUUID(t), Source: entity.SourceKey{AgentID: lane.agent, Kind: entity.AgentSite, SourceRef: lane.agent}, Alias: entity.AliasKey{Kind: entity.AgentSiteAlias, Value: "operator-site"}, SourceRef: "agent:label:site", ObservedAt: time.Now(), AgentAddresses: addresses}
		accepted, unresolved, err := lane.client.Submit(ctx, []entity.Observation{item})
		if err == nil && (accepted != 1 || unresolved != 0) {
			t.Fatalf("wire evidence lost its source %d/%d", accepted, unresolved)
		}
		return err
	}
	resolve := func(lane lane) (store.ResolvedTagSubject, error) {
		return store.NewTagSnapshots(pool).ResolveSubject(tenancy.WithTenant(ctx, tenancy.ID(lane.tenant)), tags.Scope{TenantID: lane.tenant, ContextID: contextID}, store.TagSubjectReference{Kind: "agent", ID: lane.agent}, 8<<20)
	}
	assert := func(lane lane, count int) {
		t.Helper()
		out, err := resolve(lane)
		if err != nil || len(out.Items) != count {
			t.Fatalf("wire agent facts: %+v %v", out, err)
		}
		if count > 0 && out.Items[0].Value != lane.tenant {
			t.Fatal("same IP crossed tenant tag values")
		}
	}
	for _, lane := range lanes {
		assert(lane, 0)
		if err := submit(lane, []netip.Addr{netip.MustParseAddr("10.2.0.7")}); err != nil {
			t.Fatal(err)
		}
		assert(lane, 1)
	}
	if err := submit(lanes[0], []netip.Addr{}); err != nil {
		t.Fatal(err)
	}
	assert(lanes[0], 0)
	assert(lanes[1], 1)
	if err := submit(lanes[0], []netip.Addr{netip.MustParseAddr("10.2.0.8")}); err != nil {
		t.Fatal(err)
	}
	assert(lanes[0], 1)
	if err := submit(lanes[0], nil); err != nil {
		t.Fatal(err)
	}
	assert(lanes[0], 0)
	assert(lanes[1], 1)
	if _, _, err := store.NewAgentIdentities(pool).RevokeAgent(ctx, lanes[0].tenant, lanes[0].agent, "operator-test"); err != nil {
		t.Fatal(err)
	}
	if err := submit(lanes[0], []netip.Addr{netip.MustParseAddr("10.2.0.9")}); status.Code(err) != codes.Unauthenticated && status.Code(err) != codes.PermissionDenied {
		t.Fatalf("revoked credential returned another outcome: %v", err)
	}
	if _, err := resolve(lanes[0]); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatal("revoked ordinary identity retained agent tag access")
	}
	assert(lanes[1], 1)
}
