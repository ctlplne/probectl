// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration || isolation

package store

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"google.golang.org/protobuf/proto"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/entity"
	agentv1 "github.com/ctlplne/probectl/internal/gen/probectl/agent/v1"
	"github.com/ctlplne/probectl/internal/testsupport"
	"github.com/ctlplne/probectl/migrations"
)

// Physical-copy repair and actual JSONB expansion; this schema double does
// not establish source identity. The paired registry test proves FORCE RLS.
func TestSNMPPrefixStorageKeepsCompleteWirePopulationAndRepairsManagedCopies(t *testing.T) {
	ctx := t.Context()
	pool := setup(ctx, t)
	t.Cleanup(pool.Close)
	testsupport.LockPostgresPublicCatalog(t, pool)
	id, err := crypto.UUIDv4()
	if err != nil {
		t.Fatal(err)
	}
	schema := pgx.Identifier{"t_" + strings.ReplaceAll(id, "-", "")}.Sanitize()
	if _, err := pool.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := pool.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE"); err != nil {
			t.Error(err)
		}
	})
	table := schema + ".entity_evidence"
	if _, err := pool.Exec(ctx, "CREATE TABLE "+table+"(source_kind text,alias_kind text,source_ref text)"); err != nil {
		t.Fatal(err)
	}
	repair, err := migrations.FS.ReadFile("0174_snmp_interface_prefix_snapshot.sql")
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if _, err := pool.Exec(ctx, string(repair)); err != nil {
			t.Fatal("complete prefix expansion is not idempotent for existing managed tables", err)
		}
	}
	var rows []entity.SNMPInterfacePrefix
	snapshot := &agentv1.SnmpInterfacePrefixSnapshot{}
	for index := uint32(1); index <= 20000; index++ {
		row := entity.SNMPInterfacePrefix{IfIndex: index, Prefix: netip.MustParsePrefix("2001:db8::/32"), OnLink: true}
		rows = append(rows, row)
		snapshot.Prefixes = append(snapshot.Prefixes, &agentv1.SnmpInterfacePrefix{IfIndex: index, Prefix: row.Prefix.String(), OnLink: row.OnLink})
	}
	request := &agentv1.SubmitEntityEvidenceRequest{Observations: []*agentv1.EntityEvidenceObservation{{
		ObservationId: id, SourceKind: "device_target", ConfiguredRef: "192.0.2.1", AliasKind: "address",
		AliasValue: "192.0.2.1", SourceRef: "snmp:configured-target", SnmpInterfacePrefixes: snapshot}}}
	if proto.Size(request) >= 1<<20 {
		t.Fatal("complete storage corpus does not fit its actual request envelope")
	}
	body, err := json.Marshal(rows)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, "INSERT INTO "+table+" VALUES('device_target','address','snmp:configured-target',$1::jsonb)", body); err != nil {
		t.Fatal("whole in-wire prefix population refused expanded JSONB storage", err)
	}
	var count, bytes int
	var valid bool
	if err := pool.QueryRow(ctx, "SELECT jsonb_array_length(snmp_interface_prefixes),octet_length(snmp_interface_prefixes::text),public.probectl_snmp_prefix_snapshot_valid(snmp_interface_prefixes) FROM "+table).Scan(&count, &bytes, &valid); err != nil {
		t.Fatal(err)
	}
	if count != len(rows) || bytes <= 1<<20 || bytes >= 8<<20 || !valid {
		t.Fatal("complete expanded prefix population lost rows or wire/storage accounting", count, bytes, valid)
	}
	for _, bad := range []string{`[]`, `null`, `{}`, `[{"if_index":0,"prefix":"192.0.2.0/24","on_link":true}]`,
		`[{"if_index":2147483648,"prefix":"192.0.2.0/24","on_link":true}]`,
		`[{"if_index":1,"prefix":"192.0.2.1/24","on_link":true}]`,
		`[{"if_index":1,"prefix":"::ffff:192.0.2.0/120","on_link":true}]`,
		`[{"if_index":1,"prefix":"192.0.2.0/24","on_link":"true"}]`,
		`[{"if_index":1,"prefix":"192.0.2.0/24","on_link":true,"extra":1}]`,
		`[{"if_index":1,"prefix":"192.0.2.0/24","on_link":true},{"if_index":1,"prefix":"192.0.2.0/24","on_link":false}]`} {
		_, err := pool.Exec(ctx, "INSERT INTO "+table+" VALUES('device_target','address','snmp:configured-target',$1::jsonb)", bad)
		var refusal *pgconn.PgError
		if !errors.As(err, &refusal) || refusal.Code != "23514" {
			t.Fatal("physical-copy CHECK accepted incomplete or malformed prefix metadata", err)
		}
	}
	for _, source := range []string{"('flow_exporter','address','snmp:configured-target')", "('device_target','snmp_interface_id','snmp:configured-target')", "('device_target','address','snmp:ifIndex:1')"} {
		_, err := pool.Exec(ctx, "INSERT INTO "+table+"(source_kind,alias_kind,source_ref,snmp_interface_prefixes) SELECT x.*,$1::jsonb FROM (VALUES "+source+") AS x", body)
		var refusal *pgconn.PgError
		if !errors.As(err, &refusal) || refusal.Code != "23514" {
			t.Fatal("physical-copy CHECK allowed prefix metadata on a different source family", err)
		}
	}
}
