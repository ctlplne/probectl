// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration || isolation

package store

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/tags"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport"
)

func TestAgentAddressRulesRequireCurrentIssuedSourceAndNeverReviveOlderSnapshots(t *testing.T) {
	ctx := t.Context()
	pool := setup(ctx, t)
	t.Cleanup(pool.Close)
	testsupport.LockPostgresPublicCatalog(t, pool)
	var tenants []string
	for _, suffix := range []string{"a", "b"} {
		row, err := NewTenants(pool).Create(ctx, fmt.Sprintf("agent-facts-%s-%d", suffix, time.Now().UnixNano()), suffix)
		if err != nil {
			t.Fatal(err)
		}
		tenants = append(tenants, row.ID)
	}
	t.Cleanup(func() {
		if _, err := pool.Exec(context.Background(), `DELETE FROM tenants WHERE id=ANY($1::uuid[])`, tenants); err != nil {
			t.Error(err)
		}
	})
	contextID, siteID, tagID := uuid.NewString(), uuid.NewString(), uuid.NewString()
	agents, serials, ordinary := map[string]string{}, map[string]string{}, map[string]string{}
	repo := NewEntityRegistry(pool)
	run := func(tenant string, fn func(context.Context, tenancy.Scope) error) {
		t.Helper()
		if err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenant)), pool, fn); err != nil {
			t.Fatal(err)
		}
	}
	for _, tenant := range tenants {
		agent := uuid.NewString()
		agents[tenant] = agent
		serials[tenant] = strings.ReplaceAll(uuid.NewString(), "-", "")
		ordinary[tenant] = strings.ReplaceAll(uuid.NewString(), "-", "")
		for _, credential := range []struct{ uri, serial string }{{crypto.EntitySPIFFEID(tenant, agent), serials[tenant]}, {crypto.AgentSPIFFEID(tenant, agent), ordinary[tenant]}} {
			if err := NewAgentIdentities(pool).Record(ctx, tenant, agent, credential.uri, credential.serial, time.Now().Add(time.Hour), ""); err != nil {
				t.Fatal(err)
			}
		}
		run(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			if _, err := (Agents{}).Register(ctx, sc, agent, "edge-agent", "10.2.0.99", "fixture", crypto.AgentSPIFFEID(tenant, agent), nil); err != nil {
				return err
			}
			if _, err := sc.Q.Exec(ctx, `INSERT INTO entity_contexts(tenant_id,id,site_id,vrf_id,site_label,vrf_label) VALUES ($1,$2,$3,$4,'same-site','same-vrf')`, tenant, contextID, siteID, uuid.NewString()); err != nil {
				return err
			}
			if _, err := sc.Q.Exec(ctx, `INSERT INTO entities(tenant_id,context_id,id,kind,label) VALUES ($1,$2,$3,'site','operator-site')`, tenant, contextID, siteID); err != nil {
				return err
			}
			if err := repo.AssignEntitySource(ctx, sc, entity.SourceKey{AgentID: agent, Kind: entity.AgentSite, SourceRef: agent}, contextID, siteID); err != nil {
				return err
			}
			if _, err := sc.Q.Exec(ctx, `INSERT INTO tenant_tag_definitions(tenant_id,id,key) VALUES ($1,$2,'network')`, tenant, tagID); err != nil {
				return err
			}
			for _, prefix := range []string{"10.2.0.0/24", "2001:db8:2::/48"} {
				if _, err := (TagRules{}).Create(ctx, sc, tags.Rule{Scope: tags.Scope{TenantID: tenant, ContextID: contextID}, TagID: tagID, TargetKind: "agent", Match: "cidr", AddressSide: "agent", CIDR: prefix, Value: tenant}); err != nil {
					return err
				}
			}
			return nil
		})
	}
	claim := func(tenant string, addresses []netip.Addr, at time.Time) entity.Observation {
		return entity.Observation{ID: uuid.NewString(), Source: entity.SourceKey{AgentID: agents[tenant], Kind: entity.AgentSite, SourceRef: agents[tenant]}, Alias: entity.AliasKey{Kind: entity.AgentSiteAlias, Value: "operator-site"}, SourceRef: "agent:label:site", ObservedAt: at, AgentAddresses: addresses}
	}
	write := func(tenant string, item entity.Observation) {
		t.Helper()
		accepted, unresolved, err := repo.WriteEvidenceBatch(tenancy.WithTenant(ctx, tenancy.ID(tenant)), agents[tenant], serials[tenant], []entity.Observation{item})
		if err != nil || accepted != 1 || unresolved != 0 {
			t.Fatalf("agent address evidence %d/%d: %v", accepted, unresolved, err)
		}
	}
	resolve := func(tenant, agent string) (ResolvedTagSubject, error) {
		return NewTagSnapshots(pool).ResolveSubject(tenancy.WithTenant(ctx, tenancy.ID(tenant)), tags.Scope{TenantID: tenant, ContextID: contextID}, TagSubjectReference{Kind: "agent", ID: agent}, 8<<20)
	}
	assert := func(tenant, want string) {
		t.Helper()
		out, err := resolve(tenant, agents[tenant])
		if err != nil {
			t.Fatal(err)
		}
		if want == "" && len(out.Items) != 0 || want != "" && (len(out.Items) != 1 || out.Items[0].Value != want) {
			t.Fatalf("agent CIDR facts: %+v", out.Items)
		}
	}
	a, b := tenants[0], tenants[1]
	for _, tenant := range tenants {
		assert(tenant, "")
		write(tenant, claim(tenant, []netip.Addr{netip.MustParseAddr("10.2.0.7"), netip.MustParseAddr("2001:db8:2::9")}, time.Now()))
		assert(tenant, tenant)
	}
	if _, err := resolve(a, agents[b]); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("foreign agent read reached facts: %v", err)
	}
	base := claim(a, []netip.Addr{netip.MustParseAddr("10.2.0.8")}, time.Now())
	write(a, base)
	write(a, base)
	changed := base
	changed.AgentAddresses = []netip.Addr{}
	if _, _, err := repo.WriteEvidenceBatch(tenancy.WithTenant(ctx, tenancy.ID(a)), agents[a], serials[a], []entity.Observation{changed}); !errors.Is(err, entity.ErrConflictingEvidence) {
		t.Fatal("same UUID changed complete metadata presence/value")
	}
	clearing := claim(a, []netip.Addr{}, time.Now())
	write(a, clearing)
	absentReplay := clearing
	absentReplay.AgentAddresses = nil
	if _, _, err := repo.WriteEvidenceBatch(tenancy.WithTenant(ctx, tenancy.ID(a)), agents[a], serials[a], []entity.Observation{absentReplay}); !errors.Is(err, entity.ErrConflictingEvidence) {
		t.Fatal("UUID replay erased empty-versus-absent snapshot presence")
	}
	assert(a, "")
	assert(b, b)
	// Let actual PostgreSQL time expire a valid interval. The latest clearing
	// epoch remains a fence; its older still-live address must never revive.
	run(a, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `UPDATE entity_evidence SET expires_at=clock_timestamp()+interval '100 milliseconds' WHERE tenant_id=$1 AND agent_id=$2 AND source_kind='agent_site' AND cardinality(agent_addresses)=0`, a, agents[a])
		return err
	})
	if _, err := pool.Exec(ctx, `SELECT pg_sleep(0.15)`); err != nil {
		t.Fatal(err)
	}
	assert(a, "")
	write(a, claim(a, []netip.Addr{netip.MustParseAddr("10.2.0.8")}, time.Now()))
	assert(a, a)
	run(a, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `UPDATE entity_source_contexts SET expires_at=clock_timestamp()+interval '100 milliseconds' WHERE tenant_id=$1 AND agent_id=$2 AND source_kind='agent_site'`, a, agents[a])
		return err
	})
	if _, err := pool.Exec(ctx, `SELECT pg_sleep(0.15)`); err != nil {
		t.Fatal(err)
	}
	assert(a, "")
	assert(b, b)
	run(a, func(ctx context.Context, sc tenancy.Scope) error {
		return repo.AssignEntitySource(ctx, sc, entity.SourceKey{AgentID: agents[a], Kind: entity.AgentSite, SourceRef: agents[a]}, contextID, siteID)
	})
	assert(a, "") // a fresh assignment cannot retroactively authorize old observations.
	write(a, claim(a, []netip.Addr{netip.MustParseAddr("10.2.0.8")}, time.Now()))
	assert(a, a)
	write(a, claim(a, nil, time.Now()))
	assert(a, "") // unavailable/legacy is not authority for the older set.
	at := time.Now()
	write(a, claim(a, []netip.Addr{netip.MustParseAddr("10.2.0.8")}, at))
	write(a, claim(a, []netip.Addr{netip.MustParseAddr("10.2.0.9")}, at))
	if _, err := resolve(a, agents[a]); !errors.Is(err, ErrTagSubjectFactsAmbiguous) {
		t.Fatal("contradictory equal-epoch snapshots silently chose an address set")
	}
	write(a, claim(a, []netip.Addr{netip.MustParseAddr("10.2.0.8")}, time.Now()))
	assert(a, a)
	// Expire and restore an ordinary credential: evidence credentials alone
	// cannot authorize an owned agent read. The other tenant stays unchanged.
	run(a, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `UPDATE agent_identities SET not_after=clock_timestamp()+interval '100 milliseconds' WHERE tenant_id=$1 AND agent_id=$2 AND serial=$3`, a, agents[a], ordinary[a])
		return err
	})
	if _, err := pool.Exec(ctx, `SELECT pg_sleep(0.15)`); err != nil {
		t.Fatal(err)
	}
	if _, err := resolve(a, agents[a]); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatal("expired ordinary identity retained agent tag access")
	}
	assert(b, b)
	if err := NewAgentIdentities(pool).Record(ctx, a, agents[a], crypto.AgentSPIFFEID(a, agents[a]), strings.ReplaceAll(uuid.NewString(), "-", ""), time.Now().Add(time.Hour), ordinary[a]); err != nil {
		t.Fatal(err)
	}
	assert(a, a)
	// A newer evidence credential supplies a nonmatching snapshot. After that
	// credential expires the earlier still-live credential must not resurrect
	// its older matching address set.
	oldSerial := serials[a]
	serials[a] = strings.ReplaceAll(uuid.NewString(), "-", "")
	if err := NewAgentIdentities(pool).Record(ctx, a, agents[a], crypto.EntitySPIFFEID(a, agents[a]), serials[a], time.Now().Add(time.Hour), oldSerial); err != nil {
		t.Fatal(err)
	}
	write(a, claim(a, []netip.Addr{netip.MustParseAddr("198.51.100.7")}, time.Now()))
	assert(a, "")
	run(a, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `UPDATE agent_identities SET not_after=clock_timestamp()+interval '100 milliseconds' WHERE tenant_id=$1 AND agent_id=$2 AND serial=$3`, a, agents[a], serials[a])
		return err
	})
	if _, err := pool.Exec(ctx, `SELECT pg_sleep(0.15)`); err != nil {
		t.Fatal(err)
	}
	assert(a, "")
	assert(b, b)
	oldSerial = serials[a]
	serials[a] = strings.ReplaceAll(uuid.NewString(), "-", "")
	if err := NewAgentIdentities(pool).Record(ctx, a, agents[a], crypto.EntitySPIFFEID(a, agents[a]), serials[a], time.Now().Add(time.Hour), oldSerial); err != nil {
		t.Fatal(err)
	}
	write(a, claim(a, []netip.Addr{netip.MustParseAddr("10.2.0.8")}, time.Now()))
	assert(a, a)
	run(a, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `UPDATE agent_identities SET revoked_at=clock_timestamp(),revoked_by='operator-test' WHERE tenant_id=$1 AND agent_id=$2 AND serial=$3`, a, agents[a], serials[a])
		return err
	})
	assert(a, "")
	assert(b, b)
	for _, value := range []string{"ARRAY['10.2.0.7/24'::inet]", "ARRAY['ff02::1'::inet]", "ARRAY[NULL::inet]", "ARRAY[['10.2.0.7'::inet],['10.2.0.8'::inet]]"} {
		err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(a)), pool, func(ctx context.Context, sc tenancy.Scope) error {
			_, err := sc.Q.Exec(ctx, `UPDATE entity_evidence SET agent_addresses=`+value+` WHERE tenant_id=$1 AND agent_id=$2 AND source_kind='agent_site'`, a, agents[a])
			return err
		})
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "23514" {
			t.Fatalf("pooled store admitted malformed address snapshot: %v", err)
		}
	}
}
