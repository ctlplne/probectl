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
	"io"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport"
)

// Actual PostgreSQL regex semantics, FORCE-RLS, export and destructive parent
// erasure. Inputs are retained source configuration, not a claimed SNMP proof.
func TestNetworkSubjectPostgresKeepsNeighboursAndTenantIsolation(t *testing.T) {
	pool := itPool(t)
	t.Cleanup(pool.Close)
	testsupport.LockPostgresPublicCatalog(t, pool)
	ctx := t.Context()
	stamp := fmt.Sprint(time.Now().UnixNano())
	tenants := []string{mkTenant(t, pool, "net-subject-a-"+stamp), mkTenant(t, pool, "net-subject-b-"+stamp)}
	t.Cleanup(func() {
		if _, err := pool.Exec(context.Background(), `DELETE FROM tenants WHERE id=ANY($1::uuid[])`, tenants); err != nil {
			t.Error(err)
		}
	})
	area, device := uuid.NewString(), uuid.NewString()
	const sender = "neutral-network-agent"
	all := map[string]bool{}
	for _, tc := range networkSubjectCases() {
		for _, value := range append(append([]string{}, tc.match...), tc.keep...) {
			all[value] = true
		}
	}
	for _, tenant := range tenants {
		err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenant)), pool, func(ctx context.Context, sc tenancy.Scope) error {
			if _, err := sc.Q.Exec(ctx, `INSERT INTO entity_contexts(tenant_id,id,site_id,vrf_id,site_label,vrf_label) VALUES($1,$2,$2,$2,'neutral-site','neutral-vrf')`, tenant, area); err != nil {
				return err
			}
			if _, err := sc.Q.Exec(ctx, `INSERT INTO entities(tenant_id,context_id,id,kind,label) VALUES($1,$2,$3,'device','neutral-device')`, tenant, area, device); err != nil {
				return err
			}
			if _, err := sc.Q.Exec(ctx, `INSERT INTO entity_agent_contexts(tenant_id,agent_id,context_id) VALUES($1,$2,$3)`, tenant, sender, area); err != nil {
				return err
			}
			for value := range all {
				if _, err := sc.Q.Exec(ctx, `INSERT INTO entity_source_contexts(tenant_id,agent_id,source_kind,source_ref,context_id,anchor_entity_id) VALUES($1,$2,'device_target',$3,$4,$5)`, tenant, sender, value, area, device); err != nil {
					return err
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	engine := New(pool, nil, nil, nil, nil, "fixture backups expire", nil)
	wanted := map[string]bool{}
	for value := range all {
		wanted[value] = true
	}
	for _, tc := range networkSubjectCases() {
		pattern, ok := literalSubjectPattern(tc.subject)
		if !ok {
			t.Fatal("missing subject pattern")
		}
		// Prove against the database engine rather than assuming Go and
		// PostgreSQL implement identical regular-expression details.
		for _, group := range []struct {
			values []string
			match  bool
		}{{tc.match, true}, {tc.keep, false}} {
			for _, value := range group.values {
				var got bool
				if err := pool.QueryRow(ctx, `SELECT $1::text ~ $2::text`, value, pattern).Scan(&got); err != nil || got != group.match {
					t.Fatal("PostgreSQL network matcher", tc.subject, value, got, group.match, err)
				}
				// Exact identity fields must also preserve zones and equivalent
				// address forms. Case-folding a zone can delete another source.
				policy := subjectTablePolicy{exact: []string{"source_ref"}}
				args := subjectTableMatchArgs(tenants[0], newSubjectAliasSet(tc.subject), policy)
				query := fmt.Sprintf(`SELECT subject_row.tenant_id=$1 AND %s FROM (SELECT $1::text tenant_id,$%d::text source_ref) subject_row`, subjectTableMatchPredicate(policy), len(args)+1)
				address, parseErr := netip.ParseAddr(value)
				expected := parseErr == nil && address.Unmap() == netip.MustParseAddr(tc.subject).Unmap()
				if err := pool.QueryRow(ctx, query, append(args, value)...).Scan(&got); err != nil || got != expected {
					t.Fatal("exact network identity conflated zones or lost an address", tc.subject, value, got, expected, err)
				}
			}
		}
		if tc.subject == "10.0.0.1" {
			var selectedNeighbour bool
			if err := pool.QueryRow(ctx, `SELECT '10.0.0.10' ILIKE $1 ESCAPE '!'`, literalILikeContainsPattern(tc.subject)).Scan(&selectedNeighbour); err != nil || !selectedNeighbour {
				t.Fatal("original destructive-substring reproduction missing", err)
			}
		}
		var output bytes.Buffer
		if _, err := engine.ExportSubject(ctx, tenants[0], tc.subject, &output, false); err != nil {
			t.Fatal("network portability export", tc.subject, err)
		}
		files := readTarGz(t, output.Bytes())
		decoder := json.NewDecoder(strings.NewReader(files["postgres/entity_source_contexts.jsonl"]))
		seen := map[string]bool{}
		for {
			var row struct {
				Tenant string `json:"tenant_id"`
				Source string `json:"source_ref"`
			}
			err := decoder.Decode(&row)
			if err == io.EOF {
				break
			}
			if err != nil || row.Tenant != tenants[0] || seen[row.Source] {
				t.Fatal("network export tenant/row identity", err)
			}
			seen[row.Source] = true
		}
		if len(seen) != len(tc.match) {
			t.Fatal("network export lost complete matches or selected neighbours", tc.subject, len(seen), len(tc.match))
		}
		for _, value := range tc.match {
			if !seen[value] {
				t.Fatal("export omitted exact address representation", value)
			}
		}
		if _, _, err := engine.eraseSubjectPostgres(ctx, tenants[0], tc.subject, "privacy-admin", "network subject regression"); err != nil {
			t.Fatal(err)
		}
		for _, value := range tc.match {
			delete(wanted, value)
		}
		for lane, tenant := range tenants {
			err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenant)), pool, func(ctx context.Context, sc tenancy.Scope) error {
				var foreign int
				if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM entity_source_contexts WHERE tenant_id=$1`, tenants[1-lane]).Scan(&foreign); err != nil {
					return err
				}
				if foreign != 0 {
					t.Fatal("network lifecycle bypassed FORCE-RLS")
				}
				rows, err := sc.Q.Query(ctx, `SELECT source_ref FROM entity_source_contexts WHERE tenant_id=$1`, tenant)
				if err != nil {
					return err
				}
				defer rows.Close()
				kept := map[string]bool{}
				for rows.Next() {
					var value string
					if err := rows.Scan(&value); err != nil {
						return err
					}
					kept[value] = true
				}
				if err := rows.Err(); err != nil {
					return err
				}
				expected := wanted
				if lane == 1 {
					expected = all
				}
				if len(kept) != len(expected) {
					t.Fatal("erasure changed a neighbour or sibling tenant", tc.subject, lane, len(kept), len(expected))
				}
				for value := range expected {
					if !kept[value] {
						t.Fatal("unrelated source removed", lane, value)
					}
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
		}
	}
}
