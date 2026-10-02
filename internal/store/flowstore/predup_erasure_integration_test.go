// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package flowstore

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/testsupport"
)

// TestFlowPreDedupErasure is the TEN-03 regression against a real ClickHouse.
// The v2 dedup migration RENAMEs the v1 flows table to probectl_flows_pre_dedup
// and retains it with every tenant's pre-dedup rows. Erasure (DeleteTenant /
// DeleteSubject) deleted only the live flows+rollup tables, so a tenant's data
// survived in the retained copy while the deletion attestation reported
// verified_zero. After the fix both paths also erase the pre-dedup copy.
//
// Runs in the integration job (PROBECTL_FLOWSTORE_URL points at the test
// ClickHouse); SkipOrFatal fails the build when PROBECTL_TEST_REQUIRE_SERVICES=1
// but CH is unavailable, so it can never pass by silently skipping in CI.
func TestFlowPreDedupErasure(t *testing.T) {
	url := os.Getenv("PROBECTL_FLOWSTORE_URL")
	if url == "" {
		testsupport.SkipOrFatal(t, "PROBECTL_FLOWSTORE_URL not set — TEN-03 pre-dedup erasure gate runs in CI")
	}
	c, err := NewClickHouse(url, 0)
	if err != nil {
		t.Fatalf("clickhouse: %v", err)
	}
	ctx := context.Background()
	pre := sharedFlowsTable + "_pre_dedup"

	countPre := func(t *testing.T, tenant string) int64 {
		t.Helper()
		rows, err := c.query(ctx, "",
			"SELECT count() AS n FROM "+pre+" WHERE tenant_id={tenant:String}", chParams{"tenant": tenant})
		if err != nil {
			t.Fatalf("count pre-dedup: %v", err)
		}
		if len(rows) == 0 {
			return 0
		}
		return int64(chToUint64(rows[0]["n"]))
	}
	// seed inserts a residual pre-dedup flow row for the tenant, exactly as a
	// dedup-migration upgrade leaves behind (identity field agent_id carries the
	// subject so DeleteSubject can target it). Only the columns we assert on are
	// set; the rest take ClickHouse defaults.
	seed := func(t *testing.T, tenant, subject string) {
		t.Helper()
		if err := c.exec(ctx, "",
			"INSERT INTO "+pre+" (tenant_id, agent_id) VALUES ({tenant:String}, {subject:String})",
			chParams{"tenant": tenant, "subject": subject}, nil); err != nil {
			t.Fatalf("seed pre-dedup: %v", err)
		}
	}

	t.Run("DeleteTenant", func(t *testing.T) {
		tenant := fmt.Sprintf("itest-ten03-dt-%d", time.Now().UnixNano())
		seed(t, tenant, "subj-a")
		if n := countPre(t, tenant); n != 1 {
			t.Fatalf("seed precondition: pre-dedup rows=%d, want 1", n)
		}
		if _, err := c.DeleteTenant(ctx, tenant); err != nil {
			t.Fatalf("DeleteTenant: %v", err)
		}
		if n := countPre(t, tenant); n != 0 {
			t.Errorf("TEN-03: %d pre-dedup flow row(s) survived DeleteTenant — verified_zero would be a false attestation", n)
		}
	})

	t.Run("DeleteSubject", func(t *testing.T) {
		tenant := fmt.Sprintf("itest-ten03-ds-%d", time.Now().UnixNano())
		subject := "subj-erase-me"
		seed(t, tenant, subject)
		if n := countPre(t, tenant); n != 1 {
			t.Fatalf("seed precondition: pre-dedup rows=%d, want 1", n)
		}
		if _, _, err := c.DeleteSubject(ctx, tenant, subject); err != nil {
			t.Fatalf("DeleteSubject: %v", err)
		}
		if n := countPre(t, tenant); n != 0 {
			t.Errorf("TEN-03: %d pre-dedup flow row(s) mentioning the subject survived DeleteSubject", n)
		}
	})
}
