// SPDX-License-Identifier: LicenseRef-probectl-TBD

//go:build isolation

package ebpfstore

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

// RED-001: the eBPF ClickHouse reader path must be database-scoped too. The
// query below intentionally has no WHERE tenant_id predicate; only the reader
// row policy and SQL_probectl_tenant setting can keep tenant B hidden.
func TestEBPFSettingScopedReaderCannotCrossTenant(t *testing.T) {
	rawURL := os.Getenv("PROBECTL_EBPFSTORE_URL")
	if rawURL == "" {
		t.Skip("PROBECTL_EBPFSTORE_URL not set — ClickHouse isolation gate runs in CI")
	}
	c, err := NewClickHouse(rawURL, 0)
	if err != nil {
		t.Fatalf("clickhouse: %v", err)
	}
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	ta := fmt.Sprintf("ebpfreda%d", now.UnixNano())
	tb := fmt.Sprintf("ebpfredb%d", now.UnixNano())
	reader := fmt.Sprintf("ebpfredr%d", now.UnixNano())
	readerPw := "readerpw"
	defer func() {
		_, _ = c.DeleteTenant(ctx, ta)
		_, _ = c.DeleteTenant(ctx, tb)
		_ = c.exec(ctx, "DROP USER IF EXISTS "+reader, nil)
	}()

	if err := c.Insert(ctx, []Edge{
		{TenantID: ta, AgentID: "n1", WindowStart: now, SrcWorkload: "web", DstWorkload: "db", DstPort: 5432, L7Protocol: "tcp", Bytes: 1000, Packets: 10, Connections: 2},
		{TenantID: ta, AgentID: "n1", WindowStart: now, SrcWorkload: "web", DstWorkload: "cache", DstPort: 6379, L7Protocol: "tcp", Bytes: 500, Packets: 5, Connections: 1},
		{TenantID: tb, AgentID: "n9", WindowStart: now, SrcWorkload: "x", DstWorkload: "y", DstPort: 443, L7Protocol: "tls", Bytes: 9999, Packets: 99, Connections: 9},
	}); err != nil {
		t.Fatalf("insert: %v", err)
	}

	for _, ddl := range []string{
		fmt.Sprintf("CREATE USER IF NOT EXISTS %s IDENTIFIED BY '%s'", reader, readerPw),
		fmt.Sprintf("GRANT SELECT ON *.* TO %s", reader),
	} {
		if err := c.exec(ctx, ddl, nil); err != nil {
			t.Fatalf("provision reader user: %v (%s)", err, ddl)
		}
	}
	if err := c.EnsureReaderRowPolicy(ctx, reader); err != nil {
		if strings.Contains(err.Error(), "etting") {
			t.Skipf("custom settings prefix not configured on this server: %v", err)
		}
		t.Fatalf("EnsureReaderRowPolicy: %v", err)
	}

	n, errText := ebpfCountAs(t, reader, readerPw, ta)
	if errText != "" {
		if strings.Contains(errText, "etting") {
			t.Skipf("custom settings prefix not configured: %s", errText)
		}
		t.Fatalf("reader read failed: %s", errText)
	}
	if n != 2 {
		t.Fatalf("reader saw %d eBPF edge rows via a predicate-free query, want exactly tenant A's 2 (CROSS-TENANT LEAK if >2)", n)
	}
}

func ebpfCountAs(t *testing.T, user, pass, tenant string) (int, string) {
	t.Helper()
	base, err := url.Parse(os.Getenv("PROBECTL_EBPFSTORE_URL"))
	if err != nil {
		t.Fatalf("parse ebpfstore url: %v", err)
	}
	q := url.Values{"query": {"SELECT count() AS n FROM " + sharedEdgesTable + " FORMAT TabSeparated"}}
	if tenant != "" {
		q.Set(tenantSettingName, tenant)
	}
	u := url.URL{
		Scheme:   base.Scheme,
		User:     url.UserPassword(user, pass),
		Host:     base.Host,
		Path:     base.Path,
		RawQuery: q.Encode(),
	}
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, u.String(), nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("reader request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return -1, string(body)
	}
	var n int
	_, _ = fmt.Sscanf(strings.TrimSpace(string(body)), "%d", &n)
	return n, ""
}
