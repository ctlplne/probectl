// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package endpointstore

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/store/chclient"
	"github.com/ctlplne/probectl/internal/testsupport"
)

// TestEndpointRetentionCountsSeeRowsUnderReaderRowPolicy is the GAP-04 regression
// against a real ClickHouse. When the control-plane connects as a reader covered
// by the setting-scoped row policy (tenant_id = getSetting(SQL_probectl_tenant)),
// PruneTenantBefore/DeleteTenant verify-count SELECTs omitted the per-request
// tenant setting, so the policy hid every row and the counts read 0 even when
// rows existed — a false "pruned nothing"/"verified zero". With the setting
// attached (mirroring Latest/ExportTenant), the counts see the tenant's rows.
//
// The pruned count carries the clean RED→GREEN signal: three rows older than the
// cutoff must be reported pruned (RED: 0 under the policy). DeleteTenant is also
// exercised under the policy; note a heavyweight ALTER DELETE ignores the
// FOR-SELECT policy, so a successful delete always leaves zero rows and its
// verify count agrees either way — the count-scoping fix is the same one line.
func TestEndpointRetentionCountsSeeRowsUnderReaderRowPolicy(t *testing.T) {
	rawURL := os.Getenv("PROBECTL_TEST_CLICKHOUSE_URL")
	if rawURL == "" {
		testsupport.SkipOrFatal(t, "PROBECTL_TEST_CLICKHOUSE_URL not set — GAP-04 row-policy count gate runs in CI")
	}
	base, err := url.Parse(rawURL)
	if err != nil || base.User == nil {
		t.Fatalf("PROBECTL_TEST_CLICKHOUSE_URL must carry userinfo: %v", err)
	}

	// Writer store (service creds): runs migrations, seeds, provisions the reader
	// and policy, and verifies the physical table (not under the policy).
	writer, err := NewClickHouseWithClient(rawURL, 0, nil)
	if err != nil {
		t.Fatalf("writer clickhouse: %v", err)
	}
	ctx := context.Background()
	stamp := time.Now().UnixNano()
	reader := fmt.Sprintf("epgap_reader_%d", stamp)
	readerPw := "readerpw"
	tenant := fmt.Sprintf("itest-gap04-%d", stamp)

	for _, ddl := range []string{
		fmt.Sprintf("CREATE USER IF NOT EXISTS %s IDENTIFIED BY '%s' SETTINGS %s = ''", reader, readerPw, tenantSetting),
		fmt.Sprintf("GRANT SELECT, INSERT, ALTER, CREATE TABLE ON *.* TO %s", reader),
	} {
		if err := writer.execAt(ctx, "", ddl, nil, nil); err != nil {
			if strings.Contains(err.Error(), "etting") {
				testsupport.SkipOrFatal(t, "custom settings prefix not configured on this server: %v", err)
			}
			t.Fatalf("provision reader: %v (%s)", err, ddl)
		}
	}
	t.Cleanup(func() {
		_, _ = writer.DeleteTenant(ctx, tenant)
		_ = writer.execAt(ctx, "", "DROP ROW POLICY IF EXISTS probectl_endpoint_reader_scope ON "+eventsTable, nil, nil)
		_ = writer.execAt(ctx, "", "DROP USER IF EXISTS "+reader, nil, nil)
	})

	// Reader store: scoped exactly as production — reader creds + tenant scoping on.
	readerURL := fmt.Sprintf("%s://%s:%s@%s", base.Scheme, reader, readerPw, base.Host)
	rs, err := NewClickHouseWithClient(readerURL, 0, nil)
	if err != nil {
		t.Fatalf("reader clickhouse: %v", err)
	}
	rs = rs.WithTenantScoping(true)
	if err := writer.EnsureReaderRowPolicy(ctx, reader); err != nil {
		if strings.Contains(err.Error(), "etting") {
			testsupport.SkipOrFatal(t, "custom settings prefix not configured: %v", err)
		}
		t.Fatalf("EnsureReaderRowPolicy: %v", err)
	}

	old := time.Now().UTC().Add(-48 * time.Hour)
	fresh := time.Now().UTC()
	events := []Event{
		{TenantID: tenant, AgentID: "a1", Type: "endpoint.session", SignalKey: "old1", Target: "old1", ObservedAt: old},
		{TenantID: tenant, AgentID: "a1", Type: "endpoint.session", SignalKey: "old2", Target: "old2", ObservedAt: old},
		{TenantID: tenant, AgentID: "a1", Type: "endpoint.session", SignalKey: "old3", Target: "old3", ObservedAt: old},
		{TenantID: tenant, AgentID: "a1", Type: "endpoint.session", SignalKey: "new1", Target: "new1", ObservedAt: fresh},
		{TenantID: tenant, AgentID: "a1", Type: "endpoint.session", SignalKey: "new2", Target: "new2", ObservedAt: fresh},
	}
	if err := writer.Insert(ctx, events); err != nil {
		t.Fatalf("seed events: %v", err)
	}

	// Confirm (via the writer, which is not under the policy) all 5 landed.
	if got := rawTenantCount(ctx, t, writer, tenant); got != 5 {
		t.Fatalf("seed precondition: tenant rows=%d, want 5", got)
	}

	// GAP-04: PruneTenantBefore's pruned count is a policy-scoped SELECT. With the
	// setting attached it reports the three rows older than the cutoff; the bug
	// hid them behind the policy and reported 0.
	cutoff := time.Now().UTC().Add(-1 * time.Hour)
	pruned, err := rs.PruneTenantBefore(ctx, tenant, cutoff)
	if err != nil {
		t.Fatalf("PruneTenantBefore: %v", err)
	}
	if pruned != 3 {
		t.Fatalf("PruneTenantBefore pruned count = %d, want 3 (reader row policy hid the rows and reported 0)", pruned)
	}
	// The two fresh rows are deliberately left; the physical table proves it.
	if got := rawTenantCount(ctx, t, writer, tenant); got != 2 {
		t.Fatalf("rows left after prune = %d, want 2", got)
	}

	// DeleteTenant under the same policy: its post-delete verify count must not be
	// policy-blinded. A heavyweight ALTER DELETE ignores the FOR-SELECT policy, so
	// after a successful delete zero rows remain and remaining is 0 either way;
	// this asserts the scoped count still reports the true (empty) state.
	remaining, err := rs.DeleteTenant(ctx, tenant)
	if err != nil {
		t.Fatalf("DeleteTenant: %v", err)
	}
	if remaining != 0 {
		t.Fatalf("DeleteTenant remaining = %d, want 0", remaining)
	}
	if got := rawTenantCount(ctx, t, writer, tenant); got != 0 {
		t.Fatalf("rows after DeleteTenant = %d, want 0", got)
	}
}

// rawTenantCount counts a tenant's rows as the service user (not under the reader
// row policy), so the test can verify the physical table independently of the
// policy-scoped reads under test.
func rawTenantCount(ctx context.Context, t *testing.T, c *ClickHouse, tenantID string) int64 {
	t.Helper()
	rows, err := c.queryAt(ctx, "",
		"SELECT count() AS n FROM "+eventsTable+" WHERE tenant_id={tenant:String} FORMAT JSONEachRow",
		boundParams(map[string]string{"tenant": tenantID}))
	if err != nil {
		t.Fatalf("raw tenant count: %v", err)
	}
	return int64(chclient.Count(rows))
}
