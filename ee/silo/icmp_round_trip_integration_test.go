// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.
// Production use requires a valid commercial agreement; resale additionally
// requires an MSP entitlement and reseller agreement.

//go:build integration || isolation

package silo

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport"
	"github.com/ctlplne/probectl/migrations"
)

func TestICMPRoundTripsKeepSiloTypedChecksOriginalClockAndTenantOnCatchup(t *testing.T) {
	pool := itPool(t)
	t.Cleanup(pool.Close)
	testsupport.LockPostgresPublicCatalog(t, pool)
	ctx := t.Context()
	tenants := []string{mkTenant(t, pool, "rtt-a-"+uuid.NewString(), "siloed", ""), mkTenant(t, pool, "rtt-b-"+uuid.NewString(), "siloed", "")}
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
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, query, args...); err != nil {
			t.Fatal(err)
		}
	}
	contextID, entityID, testID := uuid.NewString(), uuid.NewString(), uuid.NewString()
	end := time.Now().UTC().Truncate(time.Microsecond)
	digest := crypto.Hash([]byte("modeled silo ICMP definition and network quote"))
	legacy := entity.ICMPMeasurement{Version: 1, DefinitionHash: hex.EncodeToString(digest[:]), StartedAt: end.Add(-time.Second), CompletedAt: end, Requested: 2, Attempted: 2, Transmitted: 2, Replies: 1, ReadComplete: true, Responders: []string{"192.0.2.7"}}
	for lane, tenant := range tenants {
		if err := prov.Provision(ctx, tenant, "", tenancy.IsolationSiloed); err != nil {
			t.Fatal(err)
		}
		schema := quoteIdent(SchemaName(tenant))
		exec(`INSERT INTO `+schema+`.entity_contexts(tenant_id,id,site_id,vrf_id,site_label,vrf_label) VALUES($1,$2,$2,$2,'neutral-site','neutral-vrf')`, tenant, contextID)
		exec(`INSERT INTO `+schema+`.entities(tenant_id,context_id,id,kind,label) VALUES($1,$2,$3,'device','neutral-device')`, tenant, contextID, entityID)
		ids := []string{}
		insert := func(m *entity.ICMPMeasurement) string {
			t.Helper()
			id := uuid.NewString()
			var body []byte
			indexed := end
			if m != nil {
				var err error
				body, err = json.Marshal(m)
				if err != nil {
					t.Fatal(err)
				}
				indexed = m.CompletedAt.Truncate(time.Microsecond)
			}
			exec(`INSERT INTO `+schema+`.entity_evidence(tenant_id,context_id,id,observation_id,entity_id,alias_kind,alias_value,source,source_ref,agent_id,source_kind,configured_ref,observed_at,sender_serial,icmp_measurement)
 VALUES($1,$2,$3,$3,$4,'address','192.0.2.7','path_agent','icmp:configured-test','neutral-agent','path_agent',$5,$6,'abc',$7::jsonb)`, tenant, contextID, id, entityID, testID, indexed, body)
			ids = append(ids, id)
			return id
		}
		insert(nil)
		insert(&legacy)
		if lane == 0 {
			// Preserve existing originals while repairing the old index check.
			exec(`ALTER TABLE ` + schema + `.entity_evidence DROP CONSTRAINT entity_evidence_icmp_measurement_check`)
			exec(`ALTER TABLE ` + schema + `.entity_evidence ADD CONSTRAINT entity_evidence_icmp_measurement_check CHECK(icmp_measurement IS NULL OR observed_at=(icmp_measurement->>'completed_at')::timestamptz) NOT VALID`)
			for range 2 {
				if err := prov.CatchUpSchema(ctx, tenant); err != nil {
					t.Fatal(err)
				}
			}
		}
		v2 := legacy
		v2.Version = 2
		v2.NetworkErrors = []entity.ICMPNetworkError{{Sequence: 1, Responder: "192.0.2.1", Type: 3, Code: 1, ReceivedAt: end, PacketDigest: hex.EncodeToString(digest[:])}}
		insert(&v2)
		v3 := v2
		v3.Version = 3
		v3.CompletedAt = end.Add(789 * time.Nanosecond)
		v3.NetworkErrors = append([]entity.ICMPNetworkError(nil), v2.NetworkErrors...)
		v3.NetworkErrors[0].ReceivedAt = v3.CompletedAt.Add(-time.Nanosecond)
		v3.RoundTrips = &entity.ICMPRoundTrips{Nanos: []uint64{9007199254740993}, ExecutionNanos: 9007199254741000}
		originalID := insert(&v3)
		for _, mutation := range []string{
			`icmp_measurement=jsonb_set(icmp_measurement,'{round_trips,nanos}','[]')`,
			`icmp_measurement=icmp_measurement-'round_trips'`,
			`source_ref='probe:configured-test'`,
			`observed_at=observed_at+interval '1 microsecond'`,
		} {
			_, err := pool.Exec(ctx, `UPDATE `+schema+`.entity_evidence SET `+mutation+` WHERE tenant_id=$1 AND id=$2`, tenant, originalID)
			var check *pgconn.PgError
			if !errors.As(err, &check) || check.Code != "23514" {
				t.Fatal("silo accepted malformed or substituted original RTT evidence", err)
			}
		}
		var raw []byte
		var indexed time.Time
		if err := pool.QueryRow(ctx, `SELECT observed_at,icmp_measurement FROM `+schema+`.entity_evidence WHERE tenant_id=$1 AND id=$2`, tenant, originalID).Scan(&indexed, &raw); err != nil {
			t.Fatal(err)
		}
		var restored entity.ICMPMeasurement
		if json.Unmarshal(raw, &restored) != nil || !indexed.Equal(end) || !restored.CompletedAt.Equal(v3.CompletedAt) || restored.RoundTrips == nil || restored.RoundTrips.Nanos[0] != v3.RoundTrips.Nanos[0] {
			t.Fatal("silo replaced an original clock or exact RTT")
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
				err = tx.QueryRow(ctx, `SELECT count(*) FROM `+schema+`.entity_evidence WHERE id=ANY($1::uuid[])`, ids).Scan(&count)
			}
			_ = tx.Rollback(ctx)
			want := 0
			if caller == tenant {
				want = len(ids)
			}
			if err != nil || count != want {
				t.Fatal("qualified original RTT storage crossed tenant RLS", count, want, err)
			}
		}
	}
	migration, err := migrations.FS.ReadFile("0217_icmp_original_round_trips.sql")
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		exec(string(migration))
	}
	t.Logf("real-integration: legacy and precise original RTT storage in %d isolated tenant schemas; source bodies modeled", len(tenants))
}
