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
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/change"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/evidence"
	"github.com/ctlplne/probectl/internal/fairness"
	"github.com/ctlplne/probectl/internal/reporting"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestClientReportCapturesCompleteBackdatedMonthWithCurrentPairedAuthority(t *testing.T) {
	d := seedDependencyRoutingFixture(t)
	f := d.f
	var diagnostics bytes.Buffer
	f.server.log = slog.New(slog.NewTextHandler(&diagnostics, nil))
	t.Cleanup(func() {
		if t.Failed() {
			for _, line := range strings.Split(diagnostics.String(), "\n") {
				if strings.Contains(line, "capacity forecast") {
					t.Log(line)
				}
			}
		}
	})
	f.server.WithFairness(fairness.NewGate(fairness.DefaultPolicy(), nil))
	memory := flowstore.NewMemory()
	f.server.WithFlowStore(memory)
	private, public, err := crypto.GenerateEd25519KeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	f.server.WithEvidenceSigningKey(private)
	at := time.Now().UTC()
	from, to, err := reporting.ClientReportMonth("", at)
	if err != nil {
		t.Fatal(err)
	}
	actors := map[string]*auth.Principal{}
	finalizers := map[string]incidentEvidenceFinalizer{}
	capacityFinalizers := map[string]incidentEvidenceFinalizer{}
	for lane, tenant := range f.tenants {
		for range lane + 1 {
			d.observe(t, tenant, 0, lane == 1)
		}
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			for _, permission := range []string{permTestRead, permChangeRead, permFlowRead} {
				if err := (store.Roles{}).AddPermission(ctx, sc, f.roles[tenant], permission); err != nil {
					return err
				}
			}
			if _, err := sc.Q.Exec(ctx, `UPDATE incidents SET started_at=$3,last_seen_at=$3 WHERE tenant_id=$1 AND id=$2`, tenant, d.cases[tenant], from.Add(2*time.Hour)); err != nil {
				return err
			}
			if _, err := (store.ChangeEvents{}).Create(ctx, sc, change.Event{Source: "generic", Kind: change.KindDeploy, Title: "month for " + tenant, OccurredAt: from.Add(time.Hour)}); err != nil {
				return err
			}
			if _, err := sc.Q.Exec(ctx, `INSERT INTO device_configs(tenant_id,device,version,content,content_hash,previous_hash,drifted,observed_at,archived_at)
 VALUES($1,'same-report-device',1,'redacted model previous',$3,'',false,$2::timestamptz-interval '1 day',$2),
 ($1,'same-report-device',2,'redacted model current',$4,$3,true,$2::timestamptz+interval '1 hour',$2)`, tenant, from, strings.Repeat("a", 64), strings.Repeat("b", 64)); err != nil {
				return err
			}
			current, err := readCurrentUserAuthorityScope(ctx, sc, f.users[tenant])
			if err == nil {
				actors[tenant] = auth.ClonePrincipal(current.principal)
			}
			return err
		})
		backdateClientReportOriginals(t, d, tenant, from)
		seedCapacityCounterPeriod(f, memory, tenant, from, to, true)
	}
	capacityTarget := reporting.ClientReportCapacityTarget{Target: reporting.ClientReportCapacityRef{Kind: "interface", ContextID: f.contextID, InterfaceID: f.interfaceID}, Direction: "max_directional_percentiles", CapacityBPS: "12000000", MaximumPollGap: "5m", PhysicalBounds: []reporting.ClientReportPhysicalBound{{ContextID: f.contextID, InterfaceID: f.interfaceID, MaxBPS: "50000000"}}, ForecastMonths: 1}
	for lane, tenant := range f.tenants {
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
		capture, err := f.server.captureClientReportSources(ctx, actors[tenant], "", at, flowstore.DefaultExplorerBudget(), capacityTarget)
		if err != nil {
			t.Fatal("complete backdated-month capture failed", err)
		}
		capture.close()
		capture.close()
		if capture.TenantID != tenant || len(capture.Sources) != 2 || len(capture.Availability) != 2 || len(capture.Tables) != 6 || len(capture.InputsDigest) != 64 {
			t.Fatal("month capture lost source population or provenance")
		}
		if capture.Events == nil || len(capture.Events.Incidents) != 1 || capture.Events.Incidents[0].ID != d.cases[tenant] || len(capture.Events.IncidentLineage[d.cases[tenant]]) != 64 || len(capture.Events.Changes) != 2 {
			t.Fatal("whole monthly incident, stored change or config-drift input was omitted")
		}
		for _, event := range capture.Events.Changes {
			if event.TenantID != tenant {
				t.Fatal("monthly event capture included another tenant")
			}
		}
		if len(capture.Verdicts) != 1 || capture.Verdicts[0].IncidentID != d.cases[tenant] || capture.Verdicts[0].publication == nil || capture.retainedBytes <= 0 {
			t.Fatal("monthly incident omitted its classified verdict, signed package or final authority check")
		}
		manifest, err := evidence.Verify(capture.Verdicts[0].SignedPackage)
		if err != nil || manifest.Incident.ID != d.cases[tenant] || manifest.Contract != evidence.ContractVersion || manifest.TenantScopeDigest != "sha256:"+hex.EncodeToString(crypto.Hash([]byte(tenant))) {
			t.Fatal("monthly incident package failed existing offline verification", err)
		}
		var signed evidence.Package
		if err := json.Unmarshal(capture.Verdicts[0].SignedPackage, &signed); err != nil || signed.Signing.PublicKey != string(public) {
			t.Fatal("monthly package changed the configured trusted signing identity", err)
		}
		finalizers[tenant] = capture.Verdicts[0].publication
		if len(capture.Capacity) != 1 || capture.Capacity[0].OriginalRows == "0" || len(capture.Capacity[0].OriginalsDigest) != 64 || len(capture.Capacity[0].Measurement.Forecasts) != 2 || capture.Capacity[0].publication == nil {
			t.Fatal("monthly capacity lost complete original counters, both directions or final validation")
		}
		for _, forecast := range capture.Capacity[0].Measurement.Forecasts {
			if !forecast.Trained || !forecast.CoverageComplete || !forecast.From.Equal(from) || !forecast.To.Equal(to) || !forecast.Until.Equal(to.AddDate(0, 1, 0)) {
				t.Fatal("monthly runout changed its full training period or configured horizon", forecast.Reason)
			}
		}
		capacityFinalizers[tenant] = capture.Capacity[0].publication
		if err := capture.Verdicts[0].publication(ctx); err != nil {
			t.Fatal("unchanged monthly source failed final disclosure check", err)
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
			if table.ID == "client-evidence" {
				rows := 0
				if err := table.WalkRows(ctx, func(row []string) error {
					decoded, err := base64.StdEncoding.DecodeString(row[8])
					if err != nil {
						return err
					}
					manifest, err := evidence.Verify(decoded)
					if err != nil {
						return err
					}
					if manifest.Incident.ID != d.cases[tenant] || row[2] != manifest.PackageID || row[3] != hex.EncodeToString(crypto.Hash(decoded)) {
						return errors.New("evidence index changed the complete signed envelope or scope")
					}
					rows++
					return nil
				}); err != nil || rows != 1 {
					t.Fatal("offline evidence index was omitted or changed", err)
				}
			}
		}
		foreign := tenancy.WithTenant(ctx, tenancy.ID(f.tenants[1-lane]))
		if result, err := f.server.captureClientReportSources(foreign, actors[tenant], "", at, flowstore.DefaultExplorerBudget()); !errors.Is(err, entity.ErrScopeMismatch) || result != nil {
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
		_, err := sc.Q.Exec(ctx, `DELETE FROM role_permissions WHERE tenant_id=$1 AND role_id=$2 AND permission_key=$3`, a, f.roles[a], permChangeRead)
		return err
	})
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(a))
	result, err := f.server.captureClientReportSources(ctx, actors[a], "", at, flowstore.DefaultExplorerBudget())
	domain, ok := apierror.As(err)
	if !ok || domain.Kind != apierror.KindForbidden || result != nil {
		t.Fatal("stale actor retained withdrawn change permission or returned a test-only prefix", err)
	}
	f.in(a, func(ctx context.Context, sc tenancy.Scope) error {
		return (store.Roles{}).AddPermission(ctx, sc, f.roles[a], permChangeRead)
	})
	f.in(a, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `DELETE FROM role_permissions WHERE tenant_id=$1 AND role_id=$2 AND permission_key=$3`, a, f.roles[a], permTestRead)
		return err
	})
	ctx = tenancy.WithTenant(t.Context(), tenancy.ID(a))
	result, err = f.server.captureClientReportSources(ctx, actors[a], "", at, flowstore.DefaultExplorerBudget())
	domain, ok = apierror.As(err)
	if !ok || domain.Kind != apierror.KindForbidden || result != nil {
		t.Fatal("stale actor retained withdrawn source permission or returned a partial capture", err)
	}
	if err := finalizers[a](ctx); err == nil {
		t.Fatal("signed monthly verdict retained withdrawn permission at final disclosure")
	}
	ctx = tenancy.WithTenant(t.Context(), tenancy.ID(b))
	if err := finalizers[b](ctx); err != nil {
		t.Fatal("another tenant's permission loss invalidated a retained signed verdict", err)
	}
	result, err = f.server.captureClientReportSources(ctx, actors[b], "", at, flowstore.DefaultExplorerBudget())
	if err != nil || result == nil || len(result.Availability) != 2 {
		t.Fatal("permission withdrawal crossed tenant storage/current-authority boundary", err)
	}
	result.close()
	f.in(a, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `DELETE FROM role_permissions WHERE tenant_id=$1 AND role_id=$2 AND permission_key=$3`, a, f.roles[a], permFlowRead)
		return err
	})
	if err := capacityFinalizers[a](tenancy.WithTenant(t.Context(), tenancy.ID(a))); err == nil {
		t.Fatal("retained capacity evidence bypassed withdrawn current flow permission")
	}
	if err := capacityFinalizers[b](ctx); err != nil {
		t.Fatal("capacity permission change invalidated another tenant", err)
	}
	t.Log("real-integration: complete backdated calendar-month capture through application-role PG/RLS, current actor/source/definition, expired original serials plus renewed current identities, distinct paired counts, whole incident/change/config inputs, tenant refusal and withdrawn current permission with sibling survival; historical clocks/outcomes modeled, full pack/publication/delivery and real senders remain owed")
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
