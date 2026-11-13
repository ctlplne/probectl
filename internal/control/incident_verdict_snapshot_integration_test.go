// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration || isolation

package control

import (
	"context"
	"reflect"
	"testing"
	"time"

	gouuid "github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/incident"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestIncidentVerdictSnapshotsKeepCurrentActorOriginalsAndTenant(t *testing.T) {
	f, _, graphs := seedDependencyGraphFixture(t)
	ids := map[string]string{}
	actors := map[string]*auth.Principal{}
	for _, tenant := range f.tenants {
		ids[tenant] = gouuid.NewString()
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			for _, permission := range []string{permIncidentRead, "entities.read", "metrics.read", "events.read", permTestRead} {
				if err := (store.Roles{}).AddPermission(ctx, sc, f.roles[tenant], permission); err != nil {
					return err
				}
			}
			if _, err := sc.Q.Exec(ctx, `INSERT INTO incidents(tenant_id,id,title,entity_context_id,entity_id,identity_lookup_attempted) VALUES($1,$2,'verdict source snapshot',$3,$4,true)`, tenant, ids[tenant], f.contextID, graphs[tenant].Nodes[0].EntityID); err != nil {
				return err
			}
			current, err := readCurrentUserAuthorityScope(ctx, sc, f.users[tenant])
			if err == nil {
				actors[tenant] = auth.ClonePrincipal(current.principal)
			}
			return err
		})
	}
	from, to := time.Now().UTC().Add(-time.Minute), time.Now().UTC()
	initial := map[string]incidentVerdictSnapshot{}
	for _, tenant := range f.tenants {
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
		before, err := f.server.loadIncidentVerdictSnapshot(ctx, actors[tenant], ids[tenant], from, to, 64<<20, nil)
		if err != nil || before.inputs == nil || before.inputs.TenantID != tenant || len(before.tests) != 1 || before.tests[0].TestID != graphs[tenant].Nodes[0].TestID || before.digest == "" {
			t.Fatal("complete owned snapshot was lost", err)
		}
		for _, source := range before.sources {
			if source.TenantID != tenant || source.ContextID != f.contextID {
				t.Fatal("sibling tenant supplied a source")
			}
		}
		after, err := f.server.loadIncidentVerdictSnapshot(ctx, actors[tenant], ids[tenant], from, to, 64<<20, &before)
		if err != nil || after.digest != before.digest {
			t.Fatal("unchanged original selectors failed publication", err)
		}
		got, err := f.server.computeIncidentVerdict(ctx, actors[tenant], ids[tenant], from, to, 128<<20)
		if err != nil || got.Domain != incident.FaultUnknown || len(got.Hypotheses) != 4 {
			t.Fatal("configuration-only coverage invented a domain", got, err)
		}
		initial[tenant] = before
	}
	a, b := f.tenants[0], f.tenants[1]
	ctxA, ctxB := tenancy.WithTenant(t.Context(), tenancy.ID(a)), tenancy.WithTenant(t.Context(), tenancy.ID(b))
	if got, err := f.server.computeIncidentVerdict(ctxA, actors[a], ids[b], from, to, 128<<20); err == nil || !reflect.DeepEqual(got, incident.FaultVerdict{}) {
		t.Fatal("foreign incident returned a verdict prefix", got, err)
	}
	beforeA := initial[a]
	if got, err := f.server.loadIncidentVerdictSnapshot(ctxB, actors[b], ids[b], from, to, 64<<20, &beforeA); err == nil || !reflect.DeepEqual(got, incidentVerdictSnapshot{}) {
		t.Fatal("foreign original selectors borrowed the sibling source population", err)
	}
	f.in(a, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `DELETE FROM role_permissions WHERE tenant_id=$1 AND role_id=$2 AND permission_key=$3`, a, f.roles[a], permTestRead)
		return err
	})
	if got, err := f.server.loadIncidentVerdictSnapshot(ctxA, actors[a], ids[a], from, to, 64<<20, &beforeA); err == nil || !reflect.DeepEqual(got, incidentVerdictSnapshot{}) {
		t.Fatal("captured actor permissions survived current withdrawal", err)
	}
	if got, err := f.server.computeIncidentVerdict(ctxB, actors[b], ids[b], from, to, 128<<20); err != nil || got.Domain != incident.FaultUnknown {
		t.Fatal("tenant A permission withdrawal affected tenant B", got, err)
	}
	t.Log("real-integration: paired app-role PG/RLS current actor, complete source selection and original-selector checks; source configuration is modeled, no served/native or four-domain lab qualification claimed")
}
