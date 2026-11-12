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

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/sourceepoch"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestIncidentTestMeasurementsKeepOriginalClockCurrentAuthorityAndTenant(t *testing.T) {
	d := seedDependencyRoutingFixture(t)
	f := d.f
	for lane, tenant := range f.tenants {
		for i := range 3 {
			d.observe(t, tenant, 0, (i+lane)%2 == 1)
		}
	}
	read := func(tenant string, from, to time.Time, budget int64) ([]store.IncidentTestMeasurement, error) {
		t.Helper()
		var out []store.IncidentTestMeasurement
		err := tenancy.InTenantReadSnapshot(tenancy.WithTenant(t.Context(), tenancy.ID(tenant)), f.pool, func(ctx context.Context, sc tenancy.Scope) error {
			var generation int64
			if err := sc.Q.QueryRow(ctx, `SELECT COALESCE((SELECT generation FROM flow_snapshot_epochs WHERE tenant_id=$1),1)`, tenant).Scan(&generation); err != nil {
				return err
			}
			node := d.graphs[tenant].Nodes[0]
			input := &store.IncidentImpactInputs{TenantID: tenant, SourceGeneration: generation, Entities: []store.IncidentImpactEntity{{ContextID: f.contextID, EntityID: node.EntityID, IncidentRoot: true}}}
			sources, err := (store.Incidents{}).ConfiguredImpactTestsInScope(ctx, sc, input, 1<<20, func(_ context.Context, record entity.ContextRecord, member store.IncidentImpactEntity, id string) error {
				if record.TenantID != tenant || member.ContextID != f.contextID || member.EntityID != node.EntityID || id != "" && id != node.TestID {
					return entity.ErrScopeMismatch
				}
				return nil
			})
			if err != nil {
				return err
			}
			if len(sources) != 1 {
				return errors.New("owned configured-test source missing")
			}
			out, err = (store.Incidents{}).IncidentICMPMeasurementsInScope(ctx, sc, sources, from, to, budget)
			return err
		})
		return out, err
	}
	recheck := func(tenant string, reads []store.IncidentTestMeasurement) error {
		return tenancy.InTenantReadSnapshot(tenancy.WithTenant(t.Context(), tenancy.ID(tenant)), f.pool, func(ctx context.Context, sc tenancy.Scope) error {
			return (store.Incidents{}).RecheckIncidentTestMeasurementsInScope(ctx, sc, reads, 16<<20)
		})
	}
	from, to := time.Now().UTC().Add(-time.Minute), time.Now().UTC().Add(time.Minute)
	initial := map[string][]store.IncidentTestMeasurement{}
	for lane, tenant := range f.tenants {
		values, err := read(tenant, from, to, 16<<20)
		if err != nil || len(values) != 3 {
			t.Fatal("complete own retained measurements were lost", len(values), err)
		}
		down := 0
		for _, value := range values {
			if !value.Available || value.ICMP == nil || value.TenantID != tenant || value.TestID != d.graphs[tenant].Nodes[0].TestID || value.EvidenceID == "" || value.ObservationID == "" {
				t.Fatal("original source was not independently attested", value.Reason, value.TestID)
			}
			if value.ICMP.Replies == 0 {
				down++
			}
		}
		if down != 2-lane {
			t.Fatal("a sibling tenant supplied observed test outcomes", down)
		}
		if err := recheck(tenant, values); err != nil {
			t.Fatal("unchanged retained originals failed current publication", err)
		}
		initial[tenant] = values
		if values, err := read(tenant, from, to, 4096); !errors.Is(err, store.ErrIncidentImpactBudget) || values != nil {
			t.Fatal("whole-history memory refusal returned a prefix", values, err)
		}
	}
	if err := recheck(f.tenants[0], initial[f.tenants[1]]); !errors.Is(err, entity.ErrScopeMismatch) {
		t.Fatal("foreign original selectors borrowed the tenant snapshot", err)
	}
	a, b := f.tenants[0], f.tenants[1]
	original := initial[a][0]
	f.in(a, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `UPDATE entity_evidence SET icmp_measurement=jsonb_set(icmp_measurement,'{definition_hash}',to_jsonb($3::text)) WHERE tenant_id=$1 AND id=$2`, a, original.EvidenceID, strings.Repeat("0", 64))
		return err
	})
	if err := recheck(a, initial[a]); !errors.Is(err, entity.ErrConflictingEvidence) {
		t.Fatal("original document mutation survived final disclosure check", err)
	}
	restore, err := json.Marshal(original.ICMP)
	if err != nil {
		t.Fatal(err)
	}
	f.in(a, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `UPDATE entity_evidence SET icmp_measurement=$3::jsonb WHERE tenant_id=$1 AND id=$2`, a, original.EvidenceID, restore)
		return err
	})

	// Modeled history clock isolates the retention/rotation contract. This does
	// not claim a historical physical sender or a completed week-long lab run.
	old := time.Now().UTC().Truncate(time.Microsecond).Add(-2 * time.Hour)
	for _, tenant := range f.tenants {
		node := d.graphs[tenant].Nodes[0]
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
				if _, err := sc.Q.Exec(ctx, statement, tenant, old.Add(-time.Hour)); err != nil {
					return err
				}
			}
			_, err := sc.Q.Exec(ctx, `UPDATE agent_identities SET issued_at=$3,not_after=$4 WHERE tenant_id=$1 AND agent_id=$2`, tenant, node.AgentID, old.Add(-2*time.Hour), old.Add(time.Hour))
			return err
		})
		for i, value := range initial[tenant] {
			m := *value.ICMP
			m.StartedAt = old.Add(time.Duration(i) * time.Second)
			m.CompletedAt = m.StartedAt
			document, err := json.Marshal(m)
			if err != nil {
				t.Fatal(err)
			}
			f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
				_, err := sc.Q.Exec(ctx, `UPDATE entity_evidence SET observed_at=$3,expires_at=$3::timestamptz+interval '1 hour',icmp_measurement=$4::jsonb WHERE tenant_id=$1 AND id=$2`, tenant, value.EvidenceID, m.CompletedAt, document)
				return err
			})
		}
		// Current source authority uses a fresh certificate; the original expired
		// certificate must still have covered every original measurement instant.
		if err := store.NewAgentIdentities(f.pool).Record(t.Context(), tenant, node.AgentID, crypto.EntitySPIFFEID(tenant, node.AgentID), "f00d"+strings.ReplaceAll(tenant, "-", ""), time.Now().UTC().Add(time.Hour), ""); err != nil {
			t.Fatal(err)
		}
		values, err := read(tenant, old.Add(-time.Minute), old.Add(time.Minute), 16<<20)
		if err != nil || len(values) != 3 {
			t.Fatal("expired original certificates erased valid retained observations", len(values), err)
		}
		for _, value := range values {
			if !value.Available || value.ICMP == nil {
				t.Fatal("current renewed source could not cite its original valid measurement", value.Reason)
			}
		}
		initial[tenant] = values
	}
	f.in(a, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `UPDATE agent_identities SET revoked_at=clock_timestamp(),revoked_by='impact-regression' WHERE tenant_id=$1 AND agent_id=$2 AND serial=$3`, a, d.graphs[a].Nodes[0].AgentID, "f00d"+strings.ReplaceAll(a, "-", ""))
		return err
	})
	values, err := read(a, old.Add(-time.Minute), old.Add(time.Minute), 16<<20)
	if err != nil || len(values) != 3 {
		t.Fatal("source withdrawal hid unavailable-coverage accounting", len(values), err)
	}
	for _, value := range values {
		if value.Available || value.ICMP != nil {
			t.Fatal("revoked current sender revived historical test measurements")
		}
	}
	if values, err := read(b, old.Add(-time.Minute), old.Add(time.Minute), 16<<20); err != nil || len(values) != 3 || !values[0].Available {
		t.Fatal("sender revocation affected the sibling tenant", len(values), err)
	}
	f.in(a, func(ctx context.Context, sc tenancy.Scope) error {
		if err := tenancy.LockTenantAuditStream(ctx, sc.Q, a); err != nil {
			return err
		}
		return sourceepoch.InvalidateSourceGenerationInScope(ctx, sc)
	})
	if err := recheck(a, initial[a]); !errors.Is(err, sourceepoch.ErrInvalidating) {
		t.Fatal("active erasure reused an old original-measurement grant", err)
	}
	f.in(a, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `UPDATE flow_snapshot_epochs SET invalidating=false,observation_erasing=false,transition_token=NULL WHERE tenant_id=$1`, a)
		return err
	})
	if err := recheck(a, initial[a]); !errors.Is(err, sourceepoch.ErrInvalidating) {
		t.Fatal("completed erasure revived an earlier captured generation", err)
	}
	t.Log("real-integration: paired app-role PG/RLS original measurement/definition/current-source/rotation/withdrawal/erasure boundaries; observations and historical clocks are modeled, physical sender and full FX9 proof remain owed")
}
