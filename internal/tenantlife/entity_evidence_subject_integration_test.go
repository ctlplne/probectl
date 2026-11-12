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
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/store/flowsnapshot"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport"
)

// Seed valid retained evidence directly: this tests lifecycle/storage, not sender
// attestation. Identical row IDs and subjects exist in both FORCE-RLS tenants.
func TestEntityEvidenceSubjectMetadataExportErasureAndIsolation(t *testing.T) {
	pool := itPool(t)
	t.Cleanup(pool.Close)
	testsupport.LockPostgresPublicCatalog(t, pool)
	ctx := t.Context()
	stamp := fmt.Sprint(time.Now().UnixNano())
	tenants := []string{mkTenant(t, pool, "evidence-subject-a-"+stamp), mkTenant(t, pool, "evidence-subject-b-"+stamp)}
	t.Cleanup(func() {
		if _, err := pool.Exec(context.Background(), `DELETE FROM tenants WHERE id=ANY($1::uuid[])`, tenants); err != nil {
			t.Error(err)
		}
	})
	const person = "observed-person@example.test"
	type sample struct{ id, field, value string }
	samples := []sample{
		{uuid.NewString(), "snmp_system_name", person},
		{uuid.NewString(), "snmp_system_description", "device administered by " + person},
		{uuid.NewString(), "agent_addresses", "192.0.2.7"},
		{uuid.NewString(), "agent_addresses", "192.0.2.70"},
		{uuid.NewString(), "agent_addresses", "2001:db8::7"},
		{uuid.NewString(), "agent_addresses", "2001:db8::70"},
		{uuid.NewString(), "snmp_system_name", "unrelated-router"},
		{uuid.NewString(), "snmp_interface_prefixes", "192.0.2.7/32"},
		{uuid.NewString(), "snmp_interface_prefixes", "192.0.2.70/32"},
		{uuid.NewString(), "snmp_interface_prefixes", "2001:db8::7/128"},
		{uuid.NewString(), "snmp_interface_prefixes", "2001:db8::70/128"},
		{uuid.NewString(), "snmp_interface_prefixes", "192.0.2.0/24"},
		{uuid.NewString(), "icmp", "192.0.2.7"},
		{uuid.NewString(), "icmp", "192.0.2.70"},
		{uuid.NewString(), "icmp", "2001:db8::7"},
		{uuid.NewString(), "icmp", "2001:db8::70"},
	}
	contextID, entityID := uuid.NewString(), uuid.NewString()
	generations := make(map[string]int64)
	for _, tenant := range tenants {
		err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenant)), pool, func(ctx context.Context, sc tenancy.Scope) error {
			if _, err := sc.Q.Exec(ctx, `INSERT INTO entity_contexts(tenant_id,id,site_id,vrf_id,site_label,vrf_label) VALUES($1,$2,$2,$2,'neutral-site','neutral-vrf')`, tenant, contextID); err != nil {
				return err
			}
			if _, err := sc.Q.Exec(ctx, `INSERT INTO entities(tenant_id,context_id,id,kind,label) VALUES($1,$2,$3,'device','neutral-router')`, tenant, contextID, entityID); err != nil {
				return err
			}
			for _, row := range samples {
				var name, description, addresses, prefixes, icmp, observed any
				aliasValue := "neutral-alias"
				kind, alias, sourceRef, configured := "device_target", "address", "snmp:configured-target", "neutral-target"
				switch row.field {
				case "snmp_system_name":
					name = row.value
				case "snmp_system_description":
					description = row.value
				case "agent_addresses":
					addresses = []netip.Addr{netip.MustParseAddr(row.value)}
					kind, alias, sourceRef, configured = "agent_site", "agent_site_id", "agent:label:site", "neutral-agent"
				case "snmp_interface_prefixes":
					prefixes = fmt.Sprintf(`[{"if_index":1,"prefix":%q,"on_link":true}]`, row.value)
				case "icmp":
					kind, alias, sourceRef, configured = "path_agent", "address", "icmp:configured-test", contextID
					aliasValue = "192.0.2.200"
					if strings.Contains(row.value, ":") {
						aliasValue = "2001:db8::200"
					}
					end := time.Now().UTC().Truncate(time.Microsecond)
					observed = end
					body, err := json.Marshal(entity.ICMPMeasurement{Version: 1, DefinitionHash: strings.Repeat("a", 64), StartedAt: end.Add(-time.Second), CompletedAt: end, Requested: 3, Attempted: 3, Transmitted: 3, Replies: 1, ReadComplete: true, Responders: []string{row.value}})
					if err != nil {
						return err
					}
					icmp = body
				}
				_, err := sc.Q.Exec(ctx, `INSERT INTO entity_evidence
 (tenant_id,context_id,id,observation_id,entity_id,alias_kind,alias_value,source,source_ref,agent_id,source_kind,configured_ref,sender_serial,observed_at,snmp_system_name,snmp_system_description,agent_addresses,snmp_interface_prefixes,icmp_measurement)
 VALUES($1,$2,$3,$3,$4,$5,$15,'lifecycle-component',$6,'neutral-agent',$7,$8,'abc',COALESCE($14::timestamptz,statement_timestamp()),$9,$10,$11::inet[],$12::jsonb,$13::jsonb)`, tenant, contextID, row.id, entityID, alias, sourceRef, kind, configured, name, description, addresses, prefixes, icmp, observed, aliasValue)
				if err != nil {
					return err
				}
			}
			var err error
			generations[tenant], err = flowsnapshot.SourceGenerationInScope(ctx, sc)
			return err
		})
		if err != nil {
			t.Fatal("clean evidence lifecycle fixture", err)
		}
	}
	sink := func(ctx context.Context, actor, action, target string, data map[string]any) error {
		_, err := audit.ProviderAppend(ctx, pool, actor, action, target, data)
		return err
	}
	engine := New(pool, nil, nil, nil, sink, "fixture backups expire", nil)
	deleted := map[string]bool{}
	for _, query := range []struct {
		subject string
		indexes []int
	}{
		{person, []int{0, 1}},
		{"192.0.2.7", []int{2, 7, 12}},
		{"2001:0db8:0:0:0:0:0:7", []int{4, 9, 14}},
	} {
		want := map[string]bool{}
		for _, index := range query.indexes {
			want[samples[index].id] = true
		}
		var bundle bytes.Buffer
		if _, err := engine.ExportSubject(ctx, tenants[0], query.subject, &bundle, false); err != nil {
			t.Fatal("export evidence subject", err)
		}
		files := readTarGz(t, bundle.Bytes())
		var got = map[string]bool{}
		for _, line := range strings.Split(strings.TrimSpace(files["postgres/entity_evidence.jsonl"]), "\n") {
			if line == "" {
				continue
			}
			var row struct {
				ICMP     *entity.ICMPMeasurement `json:"icmp_measurement"`
				ID       string                  `json:"id"`
				Tenant   string                  `json:"tenant_id"`
				Prefixes []struct {
					IfIndex uint32 `json:"if_index"`
					Prefix  string `json:"prefix"`
					OnLink  bool   `json:"on_link"`
				} `json:"snmp_interface_prefixes"`
			}
			if err := json.Unmarshal([]byte(line), &row); err != nil {
				t.Fatal(err)
			}
			if row.Tenant != tenants[0] || !want[row.ID] || got[row.ID] {
				t.Fatal("entity evidence export selected unrelated rows")
			}
			for _, expected := range samples {
				if expected.id == row.ID && expected.field == "icmp" && (row.ICMP == nil || len(row.ICMP.Responders) != 1 || row.ICMP.Responders[0] != expected.value || row.ICMP.Requested != 3 || row.ICMP.Replies != 1) {
					t.Fatal("ICMP evidence portability omitted or changed original metadata")
				}
				if expected.id == row.ID && expected.field == "snmp_interface_prefixes" {
					if len(row.Prefixes) != 1 || row.Prefixes[0].IfIndex != 1 || row.Prefixes[0].Prefix != expected.value || !row.Prefixes[0].OnLink {
						t.Fatal("prefix evidence portability omitted or changed original metadata")
					}
				}
			}
			got[row.ID] = true
		}
		if len(got) != len(want) {
			t.Fatal("entity evidence export omitted retained subject metadata")
		}
		report, err := engine.EraseSubject(ctx, tenants[0], query.subject, "privacy-admin", "metadata lifecycle")
		if err != nil || !report.Complete {
			t.Fatalf("evidence erasure incomplete: %v %+v", err, report)
		}
		plane := subjectPlanesByName(report.Planes)["postgres:entity_evidence"]
		if plane.Status != SubjectStatusDeleted || plane.Deleted != int64(len(want)) || plane.Remaining != 0 {
			t.Fatal("entity evidence erasure retained subject metadata", plane)
		}
		for id := range want {
			deleted[id] = true
		}
		for lane, tenant := range tenants {
			err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenant)), pool, func(ctx context.Context, sc tenancy.Scope) error {
				var foreign int
				if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM entity_evidence WHERE tenant_id=$1`, tenants[1-lane]).Scan(&foreign); err != nil {
					return err
				}
				if foreign != 0 {
					t.Fatal("entity evidence foreign FORCE-RLS read succeeded")
				}
				rows, err := sc.Q.Query(ctx, `SELECT id::text FROM entity_evidence WHERE tenant_id=$1`, tenant)
				if err != nil {
					return err
				}
				var count int
				for rows.Next() {
					var id string
					if err := rows.Scan(&id); err != nil {
						rows.Close()
						return err
					}
					if lane == 0 && deleted[id] {
						t.Fatal("erased evidence still physically stored")
					}
					count++
				}
				rows.Close()
				if err := rows.Err(); err != nil {
					return err
				}
				wantCount := len(samples)
				if lane == 0 {
					wantCount -= len(deleted)
				}
				if count != wantCount {
					t.Fatalf("unrelated or sibling evidence changed: got=%d want=%d", count, wantCount)
				}
				if err := audit.LockTenantStream(ctx, sc.Q, tenant); err != nil {
					return err
				}
				generationErr := flowsnapshot.MatchSourceGenerationInScope(ctx, sc, generations[tenant])
				if (lane == 0) == (generationErr == nil) {
					t.Fatal("evidence subject generation isolation changed", lane, generationErr)
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
		}
	}
}
