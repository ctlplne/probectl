// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration || isolation

package control

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/fairness"
	"github.com/ctlplne/probectl/internal/reporting"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestClientReportCapturesCompleteBackdatedMonthWithCurrentPairedAuthority(t *testing.T) {
	d := seedDependencyRoutingFixture(t)
	f := d.f
	f.server.WithFairness(fairness.NewGate(fairness.DefaultPolicy(), nil))
	at := time.Now().UTC()
	from, to, err := reporting.ClientReportMonth("", at)
	if err != nil {
		t.Fatal(err)
	}
	actors := map[string]*auth.Principal{}
	for lane, tenant := range f.tenants {
		for range lane + 1 {
			d.observe(t, tenant, 0, lane == 1)
		}
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			if err := (store.Roles{}).AddPermission(ctx, sc, f.roles[tenant], permTestRead); err != nil {
				return err
			}
			current, err := readCurrentUserAuthorityScope(ctx, sc, f.users[tenant])
			if err == nil {
				actors[tenant] = auth.ClonePrincipal(current.principal)
			}
			return err
		})
		backdateClientReportOriginals(t, d, tenant, from)
	}
	for lane, tenant := range f.tenants {
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
		capture, err := f.server.captureClientReportTests(ctx, actors[tenant], "", at, flowstore.DefaultExplorerBudget())
		if err != nil {
			t.Fatal("complete backdated-month capture failed", err)
		}
		capture.close()
		capture.close()
		if capture.TenantID != tenant || len(capture.Sources) != 2 || len(capture.Availability) != 2 || len(capture.Tables) != 2 || len(capture.InputsDigest) != 64 {
			t.Fatal("month capture lost source population or provenance")
		}
		foundRoot := false
		for _, row := range capture.Availability {
			if row.TenantID != tenant || !row.From.Equal(from) || !row.To.Equal(to) || row.Counts.Unknown != "0" || row.OriginalsDigest == "" {
				t.Fatal("renewed current source lost its original valid monthly receipts")
			}
			if row.Source.TestID == d.graphs[tenant].Nodes[0].TestID {
				foundRoot = true
				if lane == 0 && (row.OriginalCount != "2" || row.Counts.Failed != "2" || row.Counts.Successful != "0") || lane == 1 && (row.OriginalCount != "3" || row.Counts.Failed != "1" || row.Counts.Successful != "2") {
					t.Fatal("monthly counts differ from complete original queries", row.Counts)
				}
			}
		}
		if !foundRoot {
			t.Fatal("canonical root test disappeared")
		}
		for _, table := range capture.Tables {
			if table.TenantID != tenant {
				t.Fatal("another tenant entered a monthly table")
			}
		}
		foreign := tenancy.WithTenant(ctx, tenancy.ID(f.tenants[1-lane]))
		if result, err := f.server.captureClientReportTests(foreign, actors[tenant], "", at, flowstore.DefaultExplorerBudget()); !errors.Is(err, entity.ErrScopeMismatch) || result != nil {
			t.Fatal("capture adopted another request's tenant", err)
		}
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			called := false
			values, err := store.NewEntityRegistry(f.pool).ClientReportConfiguredTestsInScope(tenancy.WithTenant(ctx, tenancy.ID(f.tenants[1-lane])), sc, 1<<20, func(context.Context, entity.ContextRecord, store.IncidentImpactEntity, string) error {
				called = true
				return nil
			})
			if !errors.Is(err, entity.ErrScopeMismatch) || values != nil || called {
				t.Fatal("foreign selection borrowed the RLS transaction", err)
			}
			return nil
		})
	}
	a, b := f.tenants[0], f.tenants[1]
	f.in(a, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `DELETE FROM role_permissions WHERE tenant_id=$1 AND role_id=$2 AND permission_key=$3`, a, f.roles[a], permTestRead)
		return err
	})
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(a))
	result, err := f.server.captureClientReportTests(ctx, actors[a], "", at, flowstore.DefaultExplorerBudget())
	domain, ok := apierror.As(err)
	if !ok || domain.Kind != apierror.KindForbidden || result != nil {
		t.Fatal("stale actor retained withdrawn source permission or returned a partial capture", err)
	}
	ctx = tenancy.WithTenant(t.Context(), tenancy.ID(b))
	result, err = f.server.captureClientReportTests(ctx, actors[b], "", at, flowstore.DefaultExplorerBudget())
	if err != nil || result == nil || len(result.Availability) != 2 {
		t.Fatal("permission withdrawal crossed tenant storage/current-authority boundary", err)
	}
	result.close()
	t.Log("real-integration: complete backdated calendar-month capture through application-role PG/RLS, current actor/source/definition, expired original serials plus renewed current identities, distinct paired counts, tenant refusal and withdrawn current permission with sibling survival; historical clocks/outcomes modeled, full pack/publication/delivery and real senders remain owed")
}

func backdateClientReportOriginals(t *testing.T, d *dependencyRoutingFixture, tenant string, from time.Time) {
	t.Helper()
	f := d.f
	var originals []store.IncidentTestMeasurement
	err := tenancy.InTenantReadSnapshot(tenancy.WithTenant(t.Context(), tenancy.ID(tenant)), f.pool, func(ctx context.Context, sc tenancy.Scope) error {
		registry := store.NewEntityRegistry(f.pool)
		sources, err := registry.ClientReportConfiguredTestsInScope(ctx, sc, 16<<20, func(context.Context, entity.ContextRecord, store.IncidentImpactEntity, string) error { return nil })
		if err != nil {
			return err
		}
		originals, err = (store.Incidents{}).IncidentWindowTestMeasurementsInScope(ctx, sc, sources, time.Now().Add(-time.Hour), time.Now().Add(time.Hour), 16<<20)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
		for _, statement := range []string{
			`UPDATE entity_contexts SET created_at=$2 WHERE tenant_id=$1`,
			`UPDATE entities SET created_at=$2 WHERE tenant_id=$1`,
			`UPDATE tests SET updated_at=$2,created_at=$2 WHERE tenant_id=$1`,
			`UPDATE entity_test_contexts SET assigned_at=$2 WHERE tenant_id=$1`,
			`UPDATE entity_path_test_contexts SET assigned_at=$2 WHERE tenant_id=$1`,
			`UPDATE entity_source_contexts SET assigned_at=$2 WHERE tenant_id=$1`,
			`UPDATE entity_agent_contexts SET assigned_at=$2 WHERE tenant_id=$1`,
		} {
			if _, err := sc.Q.Exec(ctx, statement, tenant, from.Add(-24*time.Hour)); err != nil {
				return err
			}
		}
		if _, err := sc.Q.Exec(ctx, `UPDATE agent_identities SET issued_at=$3,not_after=$4 WHERE tenant_id=$1 AND agent_id=$2`, tenant, d.graphs[tenant].Nodes[0].AgentID, from.Add(-time.Hour), from.Add(24*time.Hour)); err != nil {
			return err
		}
		for index, value := range originals {
			if value.ICMP == nil {
				return errors.New("complete source query omitted original typed receipt")
			}
			measurement := *value.ICMP
			measurement.StartedAt, measurement.CompletedAt = from.Add(time.Hour+time.Duration(index)*time.Second), from.Add(time.Hour+time.Duration(index)*time.Second)
			body, err := json.Marshal(measurement)
			if err != nil {
				return err
			}
			if _, err := sc.Q.Exec(ctx, `UPDATE entity_evidence SET observed_at=$3,expires_at=$3::timestamptz+interval '1 hour',icmp_measurement=$4::jsonb WHERE tenant_id=$1 AND id=$2`, tenant, value.EvidenceID, measurement.CompletedAt, body); err != nil {
				return err
			}
		}
		return nil
	})
	if len(originals) == 0 {
		t.Fatal("historical fixture had no original measurements")
	}
	if err := store.NewAgentIdentities(f.pool).Record(t.Context(), tenant, d.graphs[tenant].Nodes[0].AgentID, crypto.EntitySPIFFEID(tenant, d.graphs[tenant].Nodes[0].AgentID), "face"+strings.ReplaceAll(tenant, "-", ""), time.Now().UTC().Add(time.Hour), ""); err != nil {
		t.Fatal(err)
	}
}
