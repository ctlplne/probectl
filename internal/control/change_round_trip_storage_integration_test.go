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
	"testing"
	"time"

	gouuid "github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func verifyChangeRoundTripStorage(t *testing.T, f *roleExplanationAPIFixture, tenant, observation string, original *entity.ICMPMeasurement) {
	t.Helper()
	body, err := json.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}
	f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
		var stored []byte
		var indexed time.Time
		if err := sc.Q.QueryRow(ctx, `SELECT observed_at,icmp_measurement FROM entity_evidence WHERE tenant_id=$1 AND observation_id=$2`, tenant, observation).Scan(&indexed, &stored); err != nil {
			return err
		}
		var restored entity.ICMPMeasurement
		if json.Unmarshal(stored, &restored) != nil || !restored.CompletedAt.Equal(original.CompletedAt) || restored.RoundTrips == nil || !indexed.Equal(original.CompletedAt.Truncate(time.Microsecond)) {
			t.Fatal("SQL storage rounded an original source clock or replaced its indexed microsecond")
		}
		for _, mutation := range []string{
			`jsonb_set($4::jsonb,'{round_trips,nanos}','[]')`,
			`jsonb_set($4::jsonb,'{round_trips,nanos,0}','-1')`,
			`jsonb_set($4::jsonb,'{round_trips,execution_nanos}','-1')`,
			`jsonb_set($4::jsonb,'{round_trips,execution_nanos}','9223372036854775808')`,
			`jsonb_set($4::jsonb,'{round_trips}','null')`,
			`jsonb_set($4::jsonb,'{round_trips}','{"nanos":[],"execution_nanos":0,"unknown":true}')`,
			`$4::jsonb||'{"unknown":true}'`,
			`jsonb_set($4::jsonb,'{started_at}',to_jsonb($5::text))`,
		} {
			if _, err := sc.Q.Exec(ctx, `SAVEPOINT invalid_original_round_trip`); err != nil {
				return err
			}
			query := `INSERT INTO entity_evidence(tenant_id,context_id,id,observation_id,entity_id,alias_kind,alias_value,source,source_ref,agent_id,source_kind,configured_ref,observed_at,expires_at,sender_serial,icmp_measurement)
 SELECT tenant_id,context_id,$3::uuid,$3::uuid,entity_id,alias_kind,alias_value,source,source_ref,agent_id,source_kind,configured_ref,observed_at,expires_at,sender_serial,` + mutation + `
 FROM entity_evidence WHERE tenant_id=$1 AND observation_id=$2`
			args := []any{tenant, observation, gouuid.NewString(), body}
			if mutation == `jsonb_set($4::jsonb,'{started_at}',to_jsonb($5::text))` {
				args = append(args, original.CompletedAt.Add(time.Nanosecond).Format(time.RFC3339Nano))
			}
			_, rejected := sc.Q.Exec(ctx, query, args...)
			if _, err := sc.Q.Exec(ctx, `ROLLBACK TO SAVEPOINT invalid_original_round_trip`); err != nil {
				return err
			}
			if _, err := sc.Q.Exec(ctx, `RELEASE SAVEPOINT invalid_original_round_trip`); err != nil {
				return err
			}
			var check *pgconn.PgError
			if !errors.As(rejected, &check) || check.Code != "23514" || check.ConstraintName != "entity_evidence_icmp_measurement_check" {
				t.Fatal("SQL accepted malformed original RTTs or refused them at another boundary", rejected)
			}
		}
		return nil
	})
}
