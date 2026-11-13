// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.
// Production use requires a valid commercial agreement; resale additionally
// requires an MSP entitlement and reseller agreement.

//go:build integration || isolation

package silo

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport"
	"github.com/ctlplne/probectl/migrations"
)

func TestProbeOutcomesKeepSiloTypedChecksAndTenantOnProvisionAndCatchup(t *testing.T) {
	pool := itPool(t)
	t.Cleanup(pool.Close)
	testsupport.LockPostgresPublicCatalog(t, pool)
	ctx := t.Context()
	tenants := []string{
		mkTenant(t, pool, fmt.Sprintf("outcome-a-%d", time.Now().UnixNano()), "siloed", ""),
		mkTenant(t, pool, fmt.Sprintf("outcome-b-%d", time.Now().UnixNano()), "siloed", ""),
	}
	prov := NewProvisioner(pool, CHPlanes{}, nil, 0, slog.New(slog.NewTextHandler(io.Discard, nil)))
	t.Cleanup(func() {
		for _, tenant := range tenants {
			if err := prov.Teardown(context.Background(), tenant, "", tenancy.IsolationSiloed); err != nil {
				t.Error(err)
			}
		}
		if _, err := pool.Exec(context.Background(), `DELETE FROM tenants WHERE id=ANY($1::uuid[])`, tenants); err != nil {
			t.Error(err)
		}
	})
	contextID, entityID, legacyID, evidenceID, testID := uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString()
	end := time.Now().UTC().Truncate(time.Microsecond)
	body, err := json.Marshal(entity.ProbeOutcome{Version: 1, DefinitionHash: strings.Repeat("a", 64), CanaryType: "http", StartedAt: end.Add(-time.Second), CompletedAt: end, Success: true})
	if err != nil {
		t.Fatal(err)
	}
	httpBody, err := json.Marshal(entity.ProbeOutcome{Version: 2, DefinitionHash: strings.Repeat("a", 64), CanaryType: "http", StartedAt: end.Add(-time.Second), CompletedAt: end, HTTPResponse: &entity.ProbeHTTPResponse{StatusCode: 503, TLSVerified: true, SameOrigin: true}})
	if err != nil {
		t.Fatal(err)
	}
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, query, args...); err != nil {
			t.Fatal(err)
		}
	}
	for lane, tenant := range tenants {
		if err := prov.Provision(ctx, tenant, "", tenancy.IsolationSiloed); err != nil {
			t.Fatal(err)
		}
		schema := quoteIdent(SchemaName(tenant))
		selectedBody := body
		if lane == 0 {
			selectedBody = httpBody
		}
		exec(`INSERT INTO `+schema+`.entity_contexts(tenant_id,id,site_id,vrf_id,site_label,vrf_label) VALUES($1,$2,$2,$2,'neutral-site','neutral-vrf')`, tenant, contextID)
		exec(`INSERT INTO `+schema+`.entities(tenant_id,context_id,id,kind,label) VALUES($1,$2,$3,'device','neutral-device')`, tenant, contextID, entityID)
		exec(`INSERT INTO `+schema+`.entity_evidence(tenant_id,context_id,id,observation_id,entity_id,alias_kind,alias_value,source,source_ref,agent_id,source_kind,configured_ref,observed_at,sender_serial)
 VALUES($1,$2,$3,$3,$4,'address','192.0.2.7','lifecycle-component','icmp:configured-test','neutral-agent','path_agent',$5,$6,'abc')`, tenant, contextID, legacyID, entityID, testID, end)
		if lane == 0 {
			// An existing silo retains its old rows and enum until additive
			// catch-up installs the new column and complete typed boundary.
			exec(`ALTER TABLE ` + schema + `.entity_evidence DROP COLUMN probe_outcome CASCADE`)
			exec(`ALTER TABLE ` + schema + `.entity_evidence DROP CONSTRAINT entity_evidence_alias_kind_v2_check`)
			exec(`ALTER TABLE ` + schema + `.entity_evidence ADD CONSTRAINT entity_evidence_alias_kind_check CHECK(alias_kind='address') NOT VALID`)
			for range 2 {
				if err := prov.CatchUpSchema(ctx, tenant); err != nil {
					t.Fatal("outcome catch-up", err)
				}
			}
		}
		exec(`INSERT INTO `+schema+`.entity_evidence(tenant_id,context_id,id,observation_id,entity_id,alias_kind,alias_value,source,source_ref,agent_id,source_kind,configured_ref,observed_at,sender_serial,probe_outcome)
 VALUES($1,$2,$3,$3,$4,'configured_test_id',$5,'lifecycle-component','probe:configured-test','neutral-agent','path_agent',$5,$6,'abc',$7::jsonb)`, tenant, contextID, evidenceID, entityID, testID, end, selectedBody)
		var legacyTime time.Time
		if err := pool.QueryRow(ctx, `SELECT observed_at FROM `+schema+`.entity_evidence WHERE tenant_id=$1 AND id=$2 AND probe_outcome IS NULL`, tenant, legacyID).Scan(&legacyTime); err != nil || !legacyTime.Equal(end) {
			t.Fatal("outcome catch-up changed legacy evidence", legacyTime, err)
		}
		mutations := []string{
			`probe_outcome=probe_outcome-'success'`,
			`probe_outcome=jsonb_set(probe_outcome,'{canary_type}','"icmp"'::jsonb)`,
			`probe_outcome=jsonb_set(probe_outcome,'{definition_hash}','"bad"'::jsonb)`,
			`probe_outcome=NULL`,
			`source_kind='device_target'`,
			`source_ref='icmp:configured-test'`,
			`alias_kind='address'`,
			`alias_value='different-test'`,
			`observed_at=observed_at+interval '1 second'`,
		}
		if lane == 0 {
			mutations = append(mutations,
				`probe_outcome=probe_outcome-'http_response'`,
				`probe_outcome=jsonb_set(probe_outcome,'{version}','1'::jsonb)`,
				`probe_outcome=jsonb_set(probe_outcome,'{http_response,status_code}','1000'::jsonb)`,
				`probe_outcome=jsonb_set(probe_outcome,'{http_response,tls_verified}','"true"'::jsonb)`,
				`probe_outcome=jsonb_set(probe_outcome,'{http_response,claimed_host}','"untrusted"'::jsonb)`)
		}
		for _, mutation := range mutations {
			_, err := pool.Exec(ctx, `UPDATE `+schema+`.entity_evidence SET `+mutation+` WHERE tenant_id=$1 AND id=$2`, tenant, evidenceID)
			var constraint *pgconn.PgError
			if !errors.As(err, &constraint) || constraint.Code != "23514" {
				t.Fatal("silo lost typed outcome rejection", mutation, err)
			}
		}
		for _, caller := range tenants {
			tx, err := pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = tx.Exec(ctx, `SET LOCAL ROLE probectl_app`); err == nil {
				_, err = tx.Exec(ctx, `SELECT set_config('probectl.tenant_id',$1,true)`, caller)
			}
			var count int
			if err == nil {
				err = tx.QueryRow(ctx, `SELECT count(*) FROM `+schema+`.entity_evidence`).Scan(&count)
			}
			var changed int64
			if err == nil && caller != tenant {
				tag, writeErr := tx.Exec(ctx, `DELETE FROM `+schema+`.entity_evidence WHERE id=$1`, evidenceID)
				err, changed = writeErr, tag.RowsAffected()
			}
			_ = tx.Rollback(ctx)
			want := 0
			if caller == tenant {
				want = 2
			}
			if err != nil || count != want || changed != 0 {
				t.Fatal("qualified silo outcome access bypassed tenant RLS", count, want, changed, err)
			}
		}
	}
	migration, err := migrations.FS.ReadFile("0201_configured_probe_outcomes.sql")
	if err != nil {
		t.Fatal(err)
	}
	httpMigration, err := migrations.FS.ReadFile("0204_http_primary_response_outcomes.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, string(migration)+"\n"+string(httpMigration)); err != nil {
		t.Fatal("outcome migration replay with accepted pooled/silo rows", err)
	}
	t.Log("real-integration: paired managed-silo fresh/catch-up/replay typed constraints and qualified app-role RLS; direct rows prove storage, not sender attestation")
}
