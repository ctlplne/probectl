// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package flow_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// Runs inside the existing real application-role/RLS/lifecycle root. Temporary
// edits to its owned fixture demonstrate that visibility never interprets the
// current query text or substitutes it for a frozen report's source capture.
func queryViewMetadataAccessProof(ctx context.Context, t *testing.T, pool *pgxpool.Pool, st *flow.PostgresQueryViewStore, red, blue string, saved flow.SavedQueryView) {
	t.Helper()
	redContext := tenancy.WithTenant(ctx, tenancy.ID(red))
	blueContext := tenancy.WithTenant(ctx, tenancy.ID(blue))
	if item, err := st.GetQueryViewAccess(redContext, red, "bob", saved.ID); err != nil || item.TenantID != red || item.OwnerID != "alice" || item.Visibility != "tenant" || item.Version != saved.Version {
		t.Fatal("current shared source metadata lost exact identity", err)
	}
	for _, lane := range []struct {
		ctx           context.Context
		tenant, owner string
	}{{ctx, red, "alice"}, {blueContext, red, "alice"}, {redContext, blue, "alice"}, {blueContext, blue, "alice"}} {
		if item, err := st.GetQueryViewAccess(lane.ctx, lane.tenant, lane.owner, saved.ID); !errors.Is(err, flow.ErrQueryViewNotFound) || item != (flow.QueryViewAccess{}) {
			t.Fatal("source visibility escaped a missing or mismatched tenant binding", err)
		}
	}
	encoded, err := json.Marshal(saved.Definition)
	if err != nil {
		t.Fatal(err)
	}
	write := func(ctx context.Context, tenant, statement string, args ...any) error {
		return tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenant)), pool, func(ctx context.Context, sc tenancy.Scope) error {
			_, err := sc.Q.Exec(ctx, statement, args...)
			return err
		})
	}
	var redChanged, blueCreated bool
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if redChanged {
			if err := write(cleanup, red, `UPDATE flow_query_views SET definition=$3::jsonb,visibility='tenant' WHERE tenant_id=$1::uuid AND id=$2::uuid`, red, saved.ID, string(encoded)); err != nil {
				t.Error("restore owned visibility fixture", err)
			}
		}
		if blueCreated {
			if err := write(cleanup, blue, `DELETE FROM flow_query_views WHERE tenant_id=$1::uuid AND id=$2::uuid`, blue, saved.ID); err != nil {
				t.Error("remove owned same-ID visibility fixture", err)
			}
		}
	}()
	if err := write(ctx, red, `UPDATE flow_query_views SET definition=jsonb_set(definition,'{plan,view}','"invalid"'::jsonb) WHERE tenant_id=$1::uuid AND id=$2::uuid`, red, saved.ID); err != nil {
		t.Fatal(err)
	}
	redChanged = true
	if _, err := st.GetQueryView(redContext, red, "bob", saved.ID); err == nil {
		t.Fatal("invalid current query fixture unexpectedly decoded")
	}
	if item, err := st.GetQueryViewAccess(redContext, red, "bob", saved.ID); err != nil || item.Version != saved.Version || item.OwnerID != "alice" {
		t.Fatal("source metadata must remain readable after definition change", err)
	}
	if err := write(ctx, blue, `INSERT INTO flow_query_views(tenant_id,id,owner_id,name,visibility,definition,version,created_at,updated_at) VALUES($1::uuid,$2::uuid,'blue-owner',$3,'tenant',$4::jsonb,9007199254740993,now(),now())`, blue, saved.ID, saved.Definition.Name, string(encoded)); err != nil {
		t.Fatal(err)
	}
	blueCreated = true
	if item, err := st.GetQueryViewAccess(blueContext, blue, "viewer", saved.ID); err != nil || item.TenantID != blue || item.OwnerID != "blue-owner" || item.Version != "9007199254740993" {
		t.Fatal("same source ID crossed its storage tenant or lost revision precision", err)
	}
	if item, err := st.GetQueryViewAccess(redContext, red, "bob", saved.ID); err != nil || item.OwnerID != "alice" || item.Version != saved.Version {
		t.Fatal("foreign same-ID source retargeted current metadata", err)
	}
	if err := write(ctx, red, `UPDATE flow_query_views SET visibility='private',definition=jsonb_set(definition,'{visibility}','"private"'::jsonb) WHERE tenant_id=$1::uuid AND id=$2::uuid`, red, saved.ID); err != nil {
		t.Fatal(err)
	}
	if item, err := st.GetQueryViewAccess(redContext, red, "bob", saved.ID); !errors.Is(err, flow.ErrQueryViewNotFound) || item != (flow.QueryViewAccess{}) {
		t.Fatal("revoked source sharing still discloses current metadata", err)
	}
	if item, err := st.GetQueryViewAccess(redContext, red, "alice", saved.ID); err != nil || item.Visibility != "private" {
		t.Fatal("current owner access depended on mutable query decoding", err)
	}
	canceled, cancel := context.WithCancel(redContext)
	cancel()
	if _, err := st.GetQueryViewAccess(canceled, red, "alice", saved.ID); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled current visibility read ran", err)
	}
}
