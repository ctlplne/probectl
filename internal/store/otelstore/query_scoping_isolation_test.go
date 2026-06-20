// SPDX-License-Identifier: LicenseRef-probectl-TBD

//go:build isolation

package otelstore

import (
	"bytes"
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

// TENANT-003 / TENANT-004: prove the DB-level row policy — not the application
// WHERE clause — constrains a reader on the PII-heaviest plane. We connect as a
// NON-service ClickHouse user and issue a PREDICATE-FREE read of the spans +
// logs tables; the currentUser() row policy must still return only that
// reader's tenant rows. This is the "split read/write users so the query path
// cannot read cross-tenant even if the app is compromised" guarantee that
// flowstore already had and otelstore now matches.

func otelCH(t *testing.T) *ClickHouse {
	t.Helper()
	u := os.Getenv("PROBECTL_OTELSTORE_URL")
	if u == "" {
		t.Skip("PROBECTL_OTELSTORE_URL not set — otel isolation gate runs in CI")
	}
	c, err := NewClickHouse(u, 0)
	if err != nil {
		t.Fatalf("clickhouse: %v", err)
	}
	return c
}

func otelServiceUser(t *testing.T) string {
	t.Helper()
	base, err := url.Parse(os.Getenv("PROBECTL_OTELSTORE_URL"))
	if err != nil || base.User == nil {
		t.Fatalf("otelstore url has no userinfo: %v", err)
	}
	return base.User.Username()
}

// otelCountAs issues a raw predicate-free count over a table as (user,pass),
// bypassing the app-layer WHERE so the DB policy is what scopes the result.
func otelCountAs(t *testing.T, table, user, pass string) (int, string) {
	t.Helper()
	base, err := url.Parse(os.Getenv("PROBECTL_OTELSTORE_URL"))
	if err != nil {
		t.Fatalf("parse otelstore url: %v", err)
	}
	u := fmt.Sprintf("%s://%s:%s@%s/?query=%s", base.Scheme, user, pass, base.Host,
		url.QueryEscape("SELECT count() AS n FROM "+table+" FORMAT TabSeparated"))
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

func TestOtelReaderCannotCrossTenant(t *testing.T) {
	c := otelCH(t)
	ctx := context.Background()
	now := time.Now().UTC()
	ta := fmt.Sprintf("isootela%d", now.UnixNano())
	tb := fmt.Sprintf("isootelb%d", now.UnixNano())
	readerPw := "readerpw"

	if err := c.WriteSpans(ctx, []Span{
		{TenantID: ta, TraceID: "aa", SpanID: "01", Service: "checkout", Start: now},
		{TenantID: ta, TraceID: "bb", SpanID: "02", Service: "cart", Start: now},
		{TenantID: tb, TraceID: "cc", SpanID: "03", Service: "checkout", Start: now},
	}); err != nil {
		t.Fatalf("write spans: %v", err)
	}
	if err := c.EnsureRowPolicies(ctx, otelServiceUser(t)); err != nil {
		t.Fatalf("EnsureRowPolicies: %v", err)
	}

	for _, ddl := range []string{
		fmt.Sprintf("CREATE USER IF NOT EXISTS %s IDENTIFIED BY '%s'", ta, readerPw),
		fmt.Sprintf("GRANT SELECT ON *.* TO %s", ta),
	} {
		if err := c.exec(ctx, ddl, nil, nil); err != nil {
			t.Fatalf("provision reader user: %v (%s)", err, ddl)
		}
	}
	defer func() { _ = c.exec(ctx, "DROP USER IF EXISTS "+ta, nil, nil) }()

	n, errText := otelCountAs(t, spansTable, ta, readerPw)
	if errText != "" {
		t.Fatalf("reader read failed: %s", errText)
	}
	if n != 2 {
		t.Fatalf("reader saw %d span rows via a predicate-free query, want exactly tenant A's 2 (CROSS-TENANT LEAK if >2)", n)
	}

	_, _, _ = c.EraseTenant(ctx, ta)
	_, _, _ = c.EraseTenant(ctx, tb)
}

func TestOtelSubjectExportEraseIsTenantScoped(t *testing.T) {
	c := otelCH(t)
	ctx := context.Background()
	now := time.Now().UTC()
	subject := fmt.Sprintf("alice-%d@example.com", now.UnixNano())
	ta := fmt.Sprintf("isootelsubja%d", now.UnixNano())
	tb := fmt.Sprintf("isootelsubjb%d", now.UnixNano())
	defer func() {
		_, _, _ = c.EraseTenant(ctx, ta)
		_, _, _ = c.EraseTenant(ctx, tb)
	}()

	if err := c.WriteSpans(ctx, []Span{
		{TenantID: ta, TraceID: "ta-subject", SpanID: "01", Service: "checkout", Name: "login " + subject, Start: now},
		{TenantID: ta, TraceID: "ta-bob", SpanID: "02", Service: "checkout", Name: "login bob@example.com", Start: now},
		{TenantID: tb, TraceID: "tb-subject", SpanID: "03", Service: "checkout", Name: "login " + subject, Start: now},
	}); err != nil {
		t.Fatalf("write spans: %v", err)
	}
	if err := c.WriteLogs(ctx, []LogRecord{
		{TenantID: ta, TS: now, Service: "checkout", Body: "subject " + subject, TraceID: "ta-subject", SpanID: "01"},
		{TenantID: ta, TS: now, Service: "checkout", Body: "subject bob@example.com", TraceID: "ta-bob", SpanID: "02"},
		{TenantID: tb, TS: now, Service: "checkout", Body: "subject " + subject, TraceID: "tb-subject", SpanID: "03"},
	}); err != nil {
		t.Fatalf("write logs: %v", err)
	}

	var spans, logs bytes.Buffer
	sn, ln, err := c.ExportSubject(ctx, ta, subject, &spans, &logs)
	if err != nil {
		t.Fatalf("export subject: %v", err)
	}
	if sn != 1 || ln != 1 {
		t.Fatalf("subject export counts = spans %d logs %d, want 1/1", sn, ln)
	}
	if strings.Contains(spans.String(), tb) || strings.Contains(logs.String(), tb) {
		t.Fatalf("subject export leaked another tenant:\nspans=%s\nlogs=%s", spans.String(), logs.String())
	}

	deleted, remaining, err := c.EraseSubject(ctx, ta, subject)
	if err != nil {
		t.Fatalf("erase subject: %v", err)
	}
	if deleted != 2 || remaining != 0 {
		t.Fatalf("subject erase counts = deleted %d remaining %d, want 2/0", deleted, remaining)
	}
	gotSpans, err := c.QuerySpans(ctx, ta, SpanQuery{})
	if err != nil {
		t.Fatalf("query tenant A spans: %v", err)
	}
	gotLogs, err := c.QueryLogs(ctx, ta, LogQuery{})
	if err != nil {
		t.Fatalf("query tenant A logs: %v", err)
	}
	if len(gotSpans) != 1 || len(gotLogs) != 1 {
		t.Fatalf("tenant A should retain only non-subject rows: spans=%v logs=%v", gotSpans, gotLogs)
	}
	gotSpans, err = c.QuerySpans(ctx, tb, SpanQuery{})
	if err != nil {
		t.Fatalf("query tenant B spans: %v", err)
	}
	gotLogs, err = c.QueryLogs(ctx, tb, LogQuery{})
	if err != nil {
		t.Fatalf("query tenant B logs: %v", err)
	}
	if len(gotSpans) != 1 || len(gotLogs) != 1 {
		t.Fatalf("tenant B matching subject must be untouched: spans=%v logs=%v", gotSpans, gotLogs)
	}
}

// The setting-scoped reader policy (getSetting('SQL_probectl_tenant')) must
// FAIL CLOSED: a read with NO setting returns nothing.
func TestOtelSettingScopedReaderPolicy(t *testing.T) {
	c := otelCH(t)
	ctx := context.Background()
	reader := fmt.Sprintf("isootelr%d", time.Now().UnixNano())
	readerPw := "readerpw"

	for _, ddl := range []string{
		fmt.Sprintf("CREATE USER IF NOT EXISTS %s IDENTIFIED BY '%s'", reader, readerPw),
		fmt.Sprintf("GRANT SELECT ON *.* TO %s", reader),
	} {
		if err := c.exec(ctx, ddl, nil, nil); err != nil {
			t.Fatalf("provision reader: %v", err)
		}
	}
	defer func() { _ = c.exec(ctx, "DROP USER IF EXISTS "+reader, nil, nil) }()

	if err := c.EnsureReaderRowPolicy(ctx, reader); err != nil {
		if strings.Contains(err.Error(), "etting") {
			t.Skipf("custom settings prefix not configured on this server: %v", err)
		}
		t.Fatalf("EnsureReaderRowPolicy: %v", err)
	}
	n, errText := otelCountAs(t, spansTable, reader, readerPw)
	if errText != "" && strings.Contains(errText, "etting") {
		t.Skipf("custom settings prefix not configured: %s", errText)
	}
	if errText == "" && n != 0 {
		t.Fatalf("setting-scoped reader with NO setting saw %d rows, want 0 (fail closed)", n)
	}
}
