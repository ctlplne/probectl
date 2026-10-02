// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package otelstore

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/testsupport"
)

// TestOtelPreDedupErasure is the TEN-03 regression against a real ClickHouse.
// The v2 OTLP dedup migration RENAMEs the v1 spans and logs tables to
// probectl_otel_{spans,logs}_pre_dedup and retains them. Erasure (EraseTenant /
// EraseSubject) deleted only the live tables, so a tenant's data survived in
// the retained copies while the attestation reported verified_zero. After the
// fix both paths also erase the pre-dedup copies.
//
// Runs in the integration job (PROBECTL_OTELSTORE_URL points at the test
// ClickHouse); SkipOrFatal fails the build when PROBECTL_TEST_REQUIRE_SERVICES=1
// but CH is unavailable, so it can never pass by silently skipping in CI.
func TestOtelPreDedupErasure(t *testing.T) {
	url := os.Getenv("PROBECTL_OTELSTORE_URL")
	if url == "" {
		testsupport.SkipOrFatal(t, "PROBECTL_OTELSTORE_URL not set — TEN-03 pre-dedup erasure gate runs in CI")
	}
	c, err := NewClickHouseWithClient(url, 0, nil)
	if err != nil {
		t.Fatalf("clickhouse: %v", err)
	}
	ctx := context.Background()

	countPre := func(t *testing.T, table, tenant string) int {
		t.Helper()
		rows, err := c.query(ctx, "", "",
			"SELECT count() AS n FROM "+table+"_pre_dedup"+" WHERE tenant_id={tenant:String}", chParams{"tenant": tenant})
		if err != nil {
			t.Fatalf("count pre-dedup %s: %v", table, err)
		}
		if len(rows) == 0 {
			return 0
		}
		return int(i64(rows[0]["n"]))
	}
	// seed inserts a residual pre-dedup span and log row for the tenant, exactly
	// as a dedup-migration upgrade leaves behind (service carries the subject so
	// EraseSubject can target it). Only the asserted columns are set.
	seed := func(t *testing.T, tenant, subject string) {
		t.Helper()
		for _, table := range []string{spansTable, logsTable} {
			if err := c.execAt(ctx, "",
				"INSERT INTO "+table+"_pre_dedup"+" (tenant_id, service) VALUES ({tenant:String}, {subject:String})",
				chParams{"tenant": tenant, "subject": subject}, nil); err != nil {
				t.Fatalf("seed pre-dedup %s: %v", table, err)
			}
		}
	}

	t.Run("EraseTenant", func(t *testing.T) {
		tenant := fmt.Sprintf("itest-ten03-et-%d", time.Now().UnixNano())
		seed(t, tenant, "svc-a")
		for _, table := range []string{spansTable, logsTable} {
			if n := countPre(t, table, tenant); n != 1 {
				t.Fatalf("seed precondition: %s pre-dedup rows=%d, want 1", table, n)
			}
		}
		if _, _, err := c.EraseTenant(ctx, tenant); err != nil {
			t.Fatalf("EraseTenant: %v", err)
		}
		for _, table := range []string{spansTable, logsTable} {
			if n := countPre(t, table, tenant); n != 0 {
				t.Errorf("TEN-03: %d %s pre-dedup row(s) survived EraseTenant — verified_zero would be a false attestation", n, table)
			}
		}
	})

	t.Run("EraseSubject", func(t *testing.T) {
		tenant := fmt.Sprintf("itest-ten03-es-%d", time.Now().UnixNano())
		subject := "svc-erase-me"
		seed(t, tenant, subject)
		for _, table := range []string{spansTable, logsTable} {
			if n := countPre(t, table, tenant); n != 1 {
				t.Fatalf("seed precondition: %s pre-dedup rows=%d, want 1", table, n)
			}
		}
		if _, _, err := c.EraseSubject(ctx, tenant, subject); err != nil {
			t.Fatalf("EraseSubject: %v", err)
		}
		for _, table := range []string{spansTable, logsTable} {
			if n := countPre(t, table, tenant); n != 0 {
				t.Errorf("TEN-03: %d %s pre-dedup row(s) mentioning the subject survived EraseSubject", n, table)
			}
		}
	})
}
