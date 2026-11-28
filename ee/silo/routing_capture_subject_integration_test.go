// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.
// Production use requires a valid commercial agreement; resale additionally
// requires an MSP entitlement and reseller agreement.

//go:build integration

package silo

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/tenantlife"
	"github.com/ctlplne/probectl/internal/testsupport"
)

// Exercise the shipped subject workflow through two physically separate
// managed PostgreSQL schemas with tenant scope and app-role rights. Capture
// payloads are modeled, and intentionally cross the 128-digest scan page.
func TestSiloRoutingCaptureSubjectErasureSpansDigestPages(t *testing.T) {
	pool := itPool(t)
	t.Cleanup(pool.Close)
	testsupport.LockPostgresPublicCatalog(t, pool)
	ctx := t.Context()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	stamp := time.Now().UnixNano()
	ids := [2]string{
		mkTenant(t, pool, fmt.Sprintf("capture-subject-silo-a-%d", stamp), "siloed", ""),
		mkTenant(t, pool, fmt.Sprintf("capture-subject-silo-b-%d", stamp), "siloed", ""),
	}
	prov := NewProvisioner(pool, CHPlanes{}, nil, 0, log)
	t.Cleanup(func() {
		for _, id := range ids {
			if err := prov.Teardown(context.Background(), id, "", tenancy.IsolationSiloed); err != nil {
				t.Error(err)
			}
		}
		if _, err := pool.Exec(context.Background(), `DELETE FROM tenants WHERE id=ANY($1::uuid[])`, ids[:]); err != nil {
			t.Error(err)
		}
	})
	for _, id := range ids {
		if err := prov.Provision(ctx, id, "", tenancy.IsolationSiloed); err != nil {
			t.Fatal(err)
		}
	}
	tenancy.SetRouter(NewRouter(pool, nil, time.Second))
	t.Cleanup(func() { tenancy.SetRouter(nil) })
	sink := func(ctx context.Context, actor, action, target string, data map[string]any) error {
		_, err := audit.ProviderAppend(ctx, pool, actor, action, target, data)
		return err
	}
	lifecycle := tenantlife.New(pool, nil, nil, nil, sink, "test backup policy", log)

	const subject = `alice\"@example.test`
	const matches = 130
	const decoy = "unclassified-field"
	for _, id := range ids {
		err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(id)), pool, func(ctx context.Context, sc tenancy.Scope) error {
			var schema, role string
			if err := sc.Q.QueryRow(ctx, `SELECT current_schema(), current_user`).Scan(&schema, &role); err != nil {
				return err
			}
			if schema != SchemaName(id) || role != tenancy.AppRole {
				return fmt.Errorf("expected isolated app-role schema, got %s as %s", schema, role)
			}
			clocks, err := json.Marshal(map[string]string{"tenant_id": id, "kind": "routing_clocks"})
			if err != nil {
				return err
			}
			clockDigest := crypto.Hash(clocks)
			if _, err := sc.Q.Exec(ctx, `INSERT INTO bgp_flow_capture_objects(tenant_id,digest,kind,payload) VALUES($1,$2,'routing_clocks',$3)`, id, clockDigest, string(clocks)); err != nil {
				return err
			}
			for i := range matches + 1 {
				owner := map[string]string{"AgentID": subject}
				if i == matches {
					owner = map[string]string{"AgentID": "other", "Note": subject, "Marker": decoy}
				}
				facts, err := json.Marshal(map[string]any{"tenant_id": id, "kind": "routing_facts", "data": map[string]any{"Owner": owner, "CaptureIndex": i}})
				if err != nil {
					return err
				}
				digest := crypto.Hash(facts)
				key := crypto.Hash([]byte(fmt.Sprintf("fixture-flow-%d", i)))
				if _, err := sc.Q.Exec(ctx, `INSERT INTO bgp_flow_capture_objects(tenant_id,digest,kind,payload) VALUES($1,$2,'routing_facts',$3)`, id, digest, string(facts)); err != nil {
					return err
				}
				if _, err := sc.Q.Exec(ctx, `INSERT INTO bgp_flow_capture_receipts(tenant_id,flow_key,captured_at_unix_nanos,outcome) VALUES($1,$2,$3,'captured')`, id, key, stamp); err != nil {
					return err
				}
				if _, err := sc.Q.Exec(ctx, `INSERT INTO bgp_flow_capture_payloads(tenant_id,flow_key,facts_digest,clocks_digest) VALUES($1,$2,$3,$4)`, id, key, digest, clockDigest); err != nil {
					return err
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}

	assertExport := func(lane int, want int) {
		t.Helper()
		var archive bytes.Buffer
		manifest, err := lifecycle.ExportSubject(ctx, ids[lane], subject, &archive, false)
		if err != nil || manifest.TenantID != ids[lane] {
			t.Fatalf("export routing captures for lane %d: %v", lane, err)
		}
		body := strings.TrimSpace(readTenantlifeBundle(t, archive.Bytes())["postgres/bgp_flow_capture_objects.jsonl"])
		var count int
		if body != "" {
			count = strings.Count(body, "\n") + 1
		}
		if count != want || strings.Contains(body, ids[1-lane]) || strings.Contains(body, decoy) {
			t.Fatalf("lane %d exported %d owned captures, want %d with no decoy or sibling", lane, count, want)
		}
	}
	assertExport(0, matches)
	erased, err := lifecycle.EraseSubject(ctx, ids[0], subject, "privacy-admin", "managed capture lifecycle proof")
	if err != nil || !erased.Complete {
		t.Fatalf("managed routing subject erasure incomplete: %v", err)
	}
	const planeName = "postgres:bgp_flow_capture_objects"
	var receipt tenantlife.SubjectPlaneResult
	for _, plane := range erased.Planes {
		if plane.Plane == planeName {
			receipt = plane
		}
	}
	if receipt.Deleted != matches || receipt.Remaining != 0 {
		t.Fatalf("managed routing subject erasure receipt: %+v", receipt)
	}
	assertExport(0, 0)
	assertExport(1, matches)

	for lane, id := range ids {
		err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(id)), pool, func(ctx context.Context, sc tenancy.Scope) error {
			var objects, links, receipts int
			if err := sc.Q.QueryRow(ctx, `SELECT (SELECT count(*) FROM bgp_flow_capture_objects),
 (SELECT count(*) FROM bgp_flow_capture_payloads), (SELECT count(*) FROM bgp_flow_capture_receipts)`).Scan(&objects, &links, &receipts); err != nil {
				return err
			}
			if receipts != matches+1 || objects != 2+lane*matches || links != 1+lane*matches {
				t.Errorf("lane %d retained %d objects, %d payload links and %d first receipts", lane, objects, links, receipts)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}
