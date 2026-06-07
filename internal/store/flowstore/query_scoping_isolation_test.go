//go:build isolation

package flowstore

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

// TENANT-102 / TENANT-105 (Sprint 5/6): prove the DB-level row policy — not the
// application WHERE clause — constrains a reader. We connect as a NON-service
// ClickHouse user and issue a PREDICATE-FREE read; the row policy must still
// return only that reader's tenant rows. This is the "split read/write users so
// the query path cannot read cross-tenant even if the app is compromised"
// guarantee, demonstrated against real ClickHouse.

// chReadCountAs issues a raw, predicate-free count over the flows table as
// (user, pass) — bypassing the app-layer WHERE so the DB policy is what scopes
// the result. Returns the count and any CH error text.
func chReadCountAs(t *testing.T, user, pass string) (int, string) {
	t.Helper()
	base, err := url.Parse(os.Getenv("PROBECTL_FLOWSTORE_URL"))
	if err != nil {
		t.Fatalf("parse flowstore url: %v", err)
	}
	u := fmt.Sprintf("%s://%s:%s@%s/?query=%s", base.Scheme, user, pass, base.Host,
		url.QueryEscape("SELECT count() AS n FROM "+sharedFlowsTable+" FORMAT TabSeparated"))
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, u, nil)
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

// serviceUser pulls the connecting (write/service) user out of the env URL so
// EnsureRowPolicies exempts the right account.
func serviceUser(t *testing.T) string {
	t.Helper()
	base, err := url.Parse(os.Getenv("PROBECTL_FLOWSTORE_URL"))
	if err != nil || base.User == nil {
		t.Fatalf("flowstore url has no userinfo: %v", err)
	}
	return base.User.Username()
}

func TestClickHouseReaderCannotCrossTenant(t *testing.T) {
	c := chFlow(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	// CH-safe, lowercase-alnum tenant ids (== the per-tenant CH user name, so
	// the currentUser() row policy matches without identifier quoting).
	ta := fmt.Sprintf("isoqa%d", now.UnixNano())
	tb := fmt.Sprintf("isoqb%d", now.UnixNano())
	readerPw := "readerpw"

	if err := c.Insert(ctx, []Row{
		flowRow(ta, "198.51.100.1", now), flowRow(ta, "198.51.100.2", now),
		flowRow(tb, "192.0.2.77", now),
	}); err != nil {
		t.Fatalf("insert: %v", err)
	}
	if err := c.EnsureRowPolicies(ctx, serviceUser(t)); err != nil {
		t.Fatalf("EnsureRowPolicies: %v", err)
	}

	// A reader user named exactly tenant A; granted SELECT but NOT the service
	// account (so it falls under tenant_id = currentUser(), not the exemption).
	for _, ddl := range []string{
		fmt.Sprintf("CREATE USER IF NOT EXISTS %s IDENTIFIED BY '%s'", ta, readerPw),
		fmt.Sprintf("GRANT SELECT ON *.* TO %s", ta),
	} {
		if err := c.exec(ctx, "", ddl, nil, nil); err != nil {
			t.Fatalf("provision reader user: %v (%s)", err, ddl)
		}
	}
	defer func() { _ = c.exec(ctx, "", "DROP USER IF EXISTS "+ta, nil, nil) }()

	// Predicate-free read as tenant A's user: the row policy must hide B.
	n, errText := chReadCountAs(t, ta, readerPw)
	if errText != "" {
		t.Fatalf("reader read failed: %s", errText)
	}
	if n != 2 {
		t.Fatalf("reader saw %d rows via a predicate-free query, want exactly tenant A's 2 (CROSS-TENANT LEAK if >2)", n)
	}

	// Cleanup rows so repeat CI runs stay clean.
	_, _ = c.DeleteTenant(ctx, ta)
	_, _ = c.DeleteTenant(ctx, tb)
}

// The Sprint 5 setting-scoped reader policy (getSetting('SQL_probectl_tenant'))
// is exercised where the server allows the custom-settings prefix; otherwise it
// skips (the prefix is operator config, documented in tenant-isolation.md, and
// the mechanism is unit-covered in scoping_test.go).
func TestClickHouseSettingScopedReaderPolicy(t *testing.T) {
	c := chFlow(t)
	ctx := context.Background()
	reader := fmt.Sprintf("isordr%d", time.Now().UnixNano())
	readerPw := "readerpw"

	for _, ddl := range []string{
		fmt.Sprintf("CREATE USER IF NOT EXISTS %s IDENTIFIED BY '%s'", reader, readerPw),
		fmt.Sprintf("GRANT SELECT ON *.* TO %s", reader),
	} {
		if err := c.exec(ctx, "", ddl, nil, nil); err != nil {
			t.Fatalf("provision reader: %v", err)
		}
	}
	defer func() { _ = c.exec(ctx, "", "DROP USER IF EXISTS "+reader, nil, nil) }()

	if err := c.EnsureReaderRowPolicy(ctx, reader); err != nil {
		// CH rejects getSetting() of an undeclared custom setting at policy
		// creation when custom_settings_prefixes is unset — that is operator
		// config, not a code defect.
		if strings.Contains(err.Error(), "etting") {
			t.Skipf("custom settings prefix not configured on this server: %v", err)
		}
		t.Fatalf("EnsureReaderRowPolicy: %v", err)
	}
	// The policy applied; a read without the setting must return nothing for
	// the reader (fail closed — unset setting matches no rows).
	n, errText := chReadCountAs(t, reader, readerPw)
	if errText != "" && strings.Contains(errText, "etting") {
		t.Skipf("custom settings prefix not configured: %s", errText)
	}
	if errText == "" && n != 0 {
		t.Fatalf("setting-scoped reader with NO setting saw %d rows, want 0 (fail closed)", n)
	}
}
