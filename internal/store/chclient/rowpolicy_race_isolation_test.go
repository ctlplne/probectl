// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build isolation

package chclient_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/store/chclient"
	"github.com/ctlplne/probectl/internal/testsupport"
	"github.com/ctlplne/probectl/internal/testsupport/chtest"
)

// TestReaderRowPolicyReapplyNeverOpensTheTable (DPR-325) re-applies the
// reader row policy in a loop, as every replica's boot does, while concurrent
// reader queries count a table that holds only tenant Y's rows under tenant
// X's setting. Every one of them must count zero. With the former
// CREATE ROW POLICY OR REPLACE (remove-then-insert) some reads started while
// the table had no policy and counted Y's rows.
func TestReaderRowPolicyReapplyNeverOpensTheTable(t *testing.T) {
	raw := os.Getenv("PROBECTL_FLOWSTORE_URL")
	if raw == "" {
		testsupport.SkipOrFatal(t, "PROBECTL_FLOWSTORE_URL not set — the row-policy concurrency proof needs a real ClickHouse")
	}
	duration := 8 * time.Second
	if s, err := strconv.Atoi(os.Getenv("PROBECTL_TEST_POLICY_RACE_SECONDS")); err == nil && s > 0 {
		duration = time.Duration(s) * time.Second
	}
	db := fmt.Sprintf("probectl_t_policyrace_%d", time.Now().UnixNano())
	table := db + ".probectl_flows"
	exec := func(stmt string) {
		t.Helper()
		if _, err := chtest.Exec(raw, stmt); err != nil {
			t.Fatalf("%s: %v", stmt, err)
		}
	}
	exec("CREATE DATABASE " + db)
	t.Cleanup(func() {
		_, _ = chtest.Exec(raw, "DROP ROW POLICY IF EXISTS probectl_reader_scope ON "+table)
		_, _ = chtest.Exec(raw, "DROP DATABASE IF EXISTS "+db)
	})
	exec("CREATE TABLE " + table + " (tenant_id String, v UInt8) ENGINE = MergeTree ORDER BY tenant_id")
	exec("INSERT INTO " + table + " VALUES ('tenant-y', 1), ('tenant-y', 2)")

	reader, readerClient := chtest.ProvisionReader(t, raw, "policyrace_reader")
	apply := func() error {
		for _, stmt := range chclient.ReaderRowPolicyStatements("probectl_reader_scope", table, "SQL_probectl_tenant", reader) {
			if _, err := chtest.Exec(raw, stmt); err != nil {
				return err
			}
		}
		return nil
	}
	if err := apply(); err != nil {
		t.Fatal(err)
	}
	exec("GRANT SELECT ON " + table + " TO " + reader)

	base := chclient.StripUserinfo(raw)
	count := func(tenant string) (string, error) {
		q := url.Values{"query": {"SELECT count() FROM " + table}, "SQL_probectl_tenant": {tenant}}
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, base+"/?"+q.Encode(), nil)
		if err != nil {
			return "", err
		}
		resp, err := readerClient.Do(req)
		if err != nil {
			return "", err
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		if resp.StatusCode != http.StatusOK {
			return "", fmt.Errorf("status %d: %s", resp.StatusCode, body)
		}
		return strings.TrimSpace(string(body)), nil
	}
	if got, err := count("tenant-y"); err != nil || got != "2" {
		t.Fatalf("the owner's own setting counted %q (err %v), want 2: the policy must admit its tenant", got, err)
	}

	var stop atomic.Bool
	var reads, leaks, errs atomic.Int64
	var firstLeak atomic.Value
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for !stop.Load() {
				got, err := count("tenant-x")
				reads.Add(1)
				switch {
				case err != nil:
					errs.Add(1)
				case got != "0":
					leaks.Add(1)
					firstLeak.CompareAndSwap(nil, got)
				}
			}
		}()
	}
	reapplies := 0
	for start := time.Now(); time.Since(start) < duration; reapplies++ {
		if err := apply(); err != nil {
			stop.Store(true)
			wg.Wait()
			t.Fatalf("re-apply %d: %v", reapplies, err)
		}
	}
	stop.Store(true)
	wg.Wait()
	t.Logf("re-applied the reader policy %d times; %d concurrent foreign-tenant reads, %d errors, %d unfiltered", reapplies, reads.Load(), errs.Load(), leaks.Load())
	if reads.Load() < 500 || reapplies < 100 {
		t.Fatalf("non-vacuity: only %d reads against %d re-applies; the race was not exercised", reads.Load(), reapplies)
	}
	if errs.Load() != 0 {
		t.Fatalf("%d concurrent reader queries failed while the policy was re-applied", errs.Load())
	}
	if n := leaks.Load(); n != 0 {
		t.Fatalf("CROSS-TENANT READ: %d of %d reader queries under tenant X's setting counted tenant Y's rows (first: %v) while the policy was re-applied", n, reads.Load(), firstLeak.Load())
	}
}

// TestReaderRowPolicyConvergesADriftedPolicyInPlace (DPR-325): dropping OR
// REPLACE must not lose convergence. A policy left permissive and bound to a
// previous reader is rewritten to the setting-scoped expression and moved to
// the current reader.
func TestReaderRowPolicyConvergesADriftedPolicyInPlace(t *testing.T) {
	raw := os.Getenv("PROBECTL_FLOWSTORE_URL")
	if raw == "" {
		testsupport.SkipOrFatal(t, "PROBECTL_FLOWSTORE_URL not set — the row-policy convergence proof needs a real ClickHouse")
	}
	db := fmt.Sprintf("probectl_t_policydrift_%d", time.Now().UnixNano())
	table := db + ".probectl_flows"
	for _, stmt := range []string{
		"CREATE DATABASE " + db,
		"CREATE TABLE " + table + " (tenant_id String) ENGINE = MergeTree ORDER BY tenant_id",
	} {
		if _, err := chtest.Exec(raw, stmt); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_, _ = chtest.Exec(raw, "DROP ROW POLICY IF EXISTS probectl_reader_scope ON "+table)
		_, _ = chtest.Exec(raw, "DROP DATABASE IF EXISTS "+db)
	})
	old, _ := chtest.ProvisionReader(t, raw, "policydrift_old")
	current, _ := chtest.ProvisionReader(t, raw, "policydrift_new")
	if _, err := chtest.Exec(raw, "CREATE ROW POLICY probectl_reader_scope ON "+table+" FOR SELECT USING 1 TO "+old); err != nil {
		t.Fatal(err)
	}
	for _, stmt := range chclient.ReaderRowPolicyStatements("probectl_reader_scope", table, "SQL_probectl_tenant", current) {
		if _, err := chtest.Exec(raw, stmt); err != nil {
			t.Fatalf("%s: %v", stmt, err)
		}
	}
	got, err := chtest.Exec(raw, "SELECT select_filter, arrayStringConcat(apply_to_list, ',') FROM system.row_policies WHERE database = '"+db+"' AND short_name = 'probectl_reader_scope' FORMAT TSVRaw")
	if err != nil {
		t.Fatal(err)
	}
	fields := strings.Split(strings.TrimSpace(got), "\t")
	if len(fields) != 2 || !strings.Contains(fields[0], "getSetting('SQL_probectl_tenant')") || fields[1] != current {
		t.Fatalf("the drifted policy was not converged in place: %q (want the setting-scoped filter bound only to %s)", got, current)
	}
}

// TestReaderProofRefusesBroadGrants (DPR-328, real ClickHouse): the boot proof
// passes the documented grants (the pooled database plus individual
// per-tenant tables) and refuses a reader that also holds SELECT on every
// database or on a whole per-tenant database, though every existing table
// still carries its policy: such a reader would read any table created later,
// and system tables, unfiltered.
func TestReaderProofRefusesBroadGrants(t *testing.T) {
	raw := os.Getenv("PROBECTL_FLOWSTORE_URL")
	if raw == "" {
		testsupport.SkipOrFatal(t, "PROBECTL_FLOWSTORE_URL not set — the reader grant proof needs a real ClickHouse")
	}
	db := fmt.Sprintf("probectl_t_grants_%d", time.Now().UnixNano())
	for _, stmt := range []string{
		"CREATE DATABASE " + db,
		"CREATE TABLE " + db + ".probectl_flows (tenant_id String) ENGINE = MergeTree ORDER BY tenant_id",
		"INSERT INTO " + db + ".probectl_flows VALUES ('tenant-y')",
	} {
		if _, err := chtest.Exec(raw, stmt); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_, _ = chtest.Exec(raw, "DROP ROW POLICY IF EXISTS probectl_reader_scope ON "+db+".probectl_flows")
		_, _ = chtest.Exec(raw, "DROP DATABASE IF EXISTS "+db)
	})
	reader, readerClient := chtest.ProvisionReader(t, raw, "grants_reader")
	scope := chclient.SiloScope{
		Plane: "test", Control: chclient.NewWithClient(nil), ControlBase: raw,
		Reader: chclient.NewReader(readerClient, raw), ReaderUser: reader, TenantSetting: "SQL_probectl_tenant",
	}
	ctx := context.Background()
	if err := scope.Ensure(ctx, "", db); err != nil {
		t.Fatal(err)
	}
	if err := scope.Verify(ctx, "", db); err != nil {
		t.Fatalf("the documented grants must pass the proof: %v", err)
	}
	for _, broad := range []string{"GRANT SELECT ON " + db + ".* TO " + reader, "GRANT SELECT ON *.* TO " + reader} {
		if _, err := chtest.Exec(raw, broad); err != nil {
			t.Fatal(err)
		}
		err := scope.Verify(ctx, "", db)
		if err == nil || !errors.Is(err, chclient.ErrReaderUnsafe) {
			t.Fatalf("after %q the proof returned %v, want a definitive refusal", broad, err)
		}
	}
}
