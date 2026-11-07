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
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport"
)

// Actual app-role Postgres, lifecycle export/erasure and storage cascades;
// capture documents/source identities are modeled, not physical telemetry.
func TestRoutingCaptureSubjectDecodedErasureKeepsFirstReceiptAndSibling(t *testing.T) {
	admin := itPool(t)
	t.Cleanup(admin.Close)
	testsupport.LockPostgresPublicCatalog(t, admin)
	pool := flowQueryRuntime(t, admin)
	tenants := []string{mkTenant(t, admin, "capture-subject-a-"+flowQueryUUID(t)), mkTenant(t, admin, "capture-subject-b-"+flowQueryUUID(t))}
	t.Cleanup(func() {
		if _, err := admin.Exec(context.Background(), `DELETE FROM tenants WHERE id=ANY($1::uuid[])`, tenants); err != nil {
			t.Error(err)
		}
	})
	const subject = `alice"@example.test`
	key := crypto.Hash([]byte("modeled verified flow"))
	for _, tenant := range tenants {
		err := tenancy.InTenant(tenancy.WithTenant(t.Context(), tenancy.ID(tenant)), pool, func(ctx context.Context, sc tenancy.Scope) error {
			facts, err := json.Marshal(map[string]any{"tenant_id": tenant, "kind": "routing_facts", "data": map[string]any{"Owner": map[string]string{"AgentID": subject}}})
			if err != nil {
				return err
			}
			clocks, err := json.Marshal(map[string]any{"tenant_id": tenant, "kind": "routing_clocks"})
			if err != nil {
				return err
			}
			for kind, body := range map[string][]byte{"routing_facts": facts, "routing_clocks": clocks} {
				if _, err := sc.Q.Exec(ctx, `INSERT INTO bgp_flow_capture_objects(tenant_id,digest,kind,payload) VALUES($1,$2,$3,$4)`, tenant, crypto.Hash(body), kind, string(body)); err != nil {
					return err
				}
			}
			if _, err := sc.Q.Exec(ctx, `INSERT INTO bgp_flow_capture_receipts(tenant_id,flow_key,captured_at_unix_nanos,outcome) VALUES($1,$2,$3,'captured')`, tenant, key, time.Now().UnixNano()); err != nil {
				return err
			}
			_, err = sc.Q.Exec(ctx, `INSERT INTO bgp_flow_capture_payloads(tenant_id,flow_key,facts_digest,clocks_digest) VALUES($1,$2,$3,$4)`, tenant, key, crypto.Hash(facts), crypto.Hash(clocks))
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	engine := New(pool, nil, nil, nil, nil, "owned capture backups", testLog())
	var archive bytes.Buffer
	if _, err := engine.ExportSubject(t.Context(), tenants[0], subject, &archive, false); err != nil {
		t.Fatal(err)
	}
	files := readTarGz(t, archive.Bytes())
	body := strings.TrimSpace(files["postgres/bgp_flow_capture_objects.jsonl"])
	if body == "" || strings.Contains(body, tenants[1]) || strings.Count(body, "\n") != 0 {
		t.Fatal("decoded routing capture subject export lost its own content or crossed tenant", body)
	}
	if _, _, err := engine.eraseSubjectPostgres(t.Context(), tenants[0], subject, "privacy-admin", "owned capture lifecycle proof"); err != nil {
		t.Fatal(err)
	}
	for lane, tenant := range tenants {
		err := tenancy.InTenant(tenancy.WithTenant(t.Context(), tenancy.ID(tenant)), pool, func(ctx context.Context, sc tenancy.Scope) error {
			var objects, links, receipts int
			if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM bgp_flow_capture_objects`).Scan(&objects); err != nil {
				return err
			}
			if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM bgp_flow_capture_payloads`).Scan(&links); err != nil {
				return err
			}
			if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM bgp_flow_capture_receipts`).Scan(&receipts); err != nil {
				return err
			}
			if receipts != 1 || lane == 0 && (objects != 1 || links != 0) || lane == 1 && (objects != 2 || links != 1) {
				t.Fatal("decoded capture erasure lost tombstones or changed its sibling", lane, objects, links, receipts)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}
