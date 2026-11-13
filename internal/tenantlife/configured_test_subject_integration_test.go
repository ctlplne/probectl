// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package tenantlife

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport"
)

// Direct retained-row fixtures exercise real lifecycle SQL and FORCE RLS.
// They do not attest a sender or simulate a successful probe.
func TestConfiguredTestReferencesSurviveSubjectErasureWithoutHidingPersonalText(t *testing.T) {
	pool := itPool(t)
	t.Cleanup(pool.Close)
	testsupport.LockPostgresPublicCatalog(t, pool)
	ctx := t.Context()
	stamp := fmt.Sprint(time.Now().UnixNano())
	tenants := []string{mkTenant(t, pool, "test-reference-a-"+stamp), mkTenant(t, pool, "test-reference-b-"+stamp)}
	t.Cleanup(func() {
		if _, err := pool.Exec(context.Background(), `DELETE FROM tenants WHERE id=ANY($1::uuid[])`, tenants); err != nil {
			t.Error(err)
		}
	})
	person, contextID, entityID := uuid.NewString(), uuid.NewString(), uuid.NewString()
	ids := []string{uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString()}
	end := time.Now().UTC().Truncate(time.Microsecond)
	icmp, err := json.Marshal(entity.ICMPMeasurement{Version: 1, DefinitionHash: strings.Repeat("a", 64), StartedAt: end.Add(-time.Second), CompletedAt: end, Requested: 1, Attempted: 1, Transmitted: 1, Replies: 1, ReadComplete: true, Responders: []string{"192.0.2.7"}})
	if err != nil {
		t.Fatal(err)
	}
	outcome, err := json.Marshal(entity.ProbeOutcome{Version: 1, DefinitionHash: strings.Repeat("b", 64), CanaryType: "http", StartedAt: end.Add(-time.Second), CompletedAt: end, Success: true})
	if err != nil {
		t.Fatal(err)
	}
	in := func(tenant string, fn func(context.Context, tenancy.Scope) error) {
		t.Helper()
		if err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenant)), pool, fn); err != nil {
			t.Fatal(err)
		}
	}
	for _, tenant := range tenants {
		in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			if _, err := sc.Q.Exec(ctx, `INSERT INTO entity_contexts(tenant_id,id,site_id,vrf_id,site_label,vrf_label) VALUES($1,$2,$2,$2,'neutral-site','neutral-vrf')`, tenant, contextID); err != nil {
				return err
			}
			if _, err := sc.Q.Exec(ctx, `INSERT INTO entities(tenant_id,context_id,id,kind,label) VALUES($1,$2,$3,'device','neutral-device')`, tenant, contextID, entityID); err != nil {
				return err
			}
			for i, id := range ids {
				kind, alias, value, sourceRef, configured := "path_agent", "address", "192.0.2.7", "icmp:configured-test", person
				var measurement, generic, description any
				switch i {
				case 0:
					measurement = icmp
				case 1:
					alias, value, sourceRef, generic = "configured_test_id", person, "probe:configured-test", outcome
				case 2:
					kind, sourceRef, configured = "device_target", "snmp:configured-target", "neutral-target"
					description = "contact " + person
				case 3:
					sourceRef, configured = "path:configured-test", "operator "+person
				}
				if _, err := sc.Q.Exec(ctx, `INSERT INTO entity_evidence
 (tenant_id,context_id,id,observation_id,entity_id,alias_kind,alias_value,source,source_ref,agent_id,source_kind,configured_ref,sender_serial,observed_at,icmp_measurement,probe_outcome,snmp_system_description)
 VALUES($1,$2,$3,$3,$4,$5,$6,'lifecycle-component',$7,'neutral-agent',$8,$9,'abc',$10,$11::jsonb,$12::jsonb,$13)`, tenant, contextID, id, entityID, alias, value, sourceRef, kind, configured, end, measurement, generic, description); err != nil {
					return err
				}
			}
			return nil
		})
	}
	sink := func(ctx context.Context, actor, action, target string, data map[string]any) error {
		_, err := audit.ProviderAppend(ctx, pool, actor, action, target, data)
		return err
	}
	engine := New(pool, nil, nil, nil, sink, "fixture backups expire", nil)
	var bundle bytes.Buffer
	if _, err := engine.ExportSubject(ctx, tenants[0], person, &bundle, false); err != nil {
		t.Fatal(err)
	}
	selected := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSpace(readTarGz(t, bundle.Bytes())["postgres/entity_evidence.jsonl"]), "\n") {
		if line == "" {
			continue
		}
		var row struct{ ID, TenantID string }
		var fields map[string]any
		if err := json.Unmarshal([]byte(line), &fields); err != nil {
			t.Fatal(err)
		}
		row.ID, _ = fields["id"].(string)
		row.TenantID, _ = fields["tenant_id"].(string)
		if row.TenantID != tenants[0] || (row.ID != ids[2] && row.ID != ids[3]) || selected[row.ID] {
			t.Error("subject export selected a structural test reference or sibling row", row)
		}
		selected[row.ID] = true
	}
	if len(selected) != 2 {
		t.Error("subject export did not select exactly the personal metadata", selected)
	}
	report, err := engine.EraseSubject(ctx, tenants[0], person, "privacy-admin", "typed reference lifecycle")
	if err != nil || !report.Complete {
		t.Fatal("subject erasure incomplete", report, err)
	}
	plane := subjectPlanesByName(report.Planes)["postgres:entity_evidence"]
	if plane.Status != SubjectStatusDeleted || plane.Deleted != 2 || plane.Remaining != 0 {
		t.Fatal("subject erasure confused structural references and personal metadata", plane)
	}
	for lane, tenant := range tenants {
		in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			for i, id := range ids {
				var exists bool
				if err := sc.Q.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM entity_evidence WHERE tenant_id=$1 AND id=$2)`, tenant, id).Scan(&exists); err != nil {
					return err
				}
				if exists != (lane == 1 || i < 2) {
					return fmt.Errorf("subject erasure changed unrelated retained evidence: lane=%d kind=%d", lane, i)
				}
			}
			var foreign int
			if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM entity_evidence WHERE tenant_id=$1`, tenants[1-lane]).Scan(&foreign); err != nil {
				return err
			}
			if foreign != 0 {
				return fmt.Errorf("subject lifecycle bypassed FORCE RLS")
			}
			return nil
		})
	}
}
