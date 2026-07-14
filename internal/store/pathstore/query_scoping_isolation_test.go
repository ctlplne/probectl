// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//go:build isolation

package pathstore

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

	"github.com/imfeelingtheagi/probectl/internal/path"
)

// RED-001: the configured ClickHouse reader user must be constrained by the
// setting-scoped row policy, not by app-layer WHERE clauses. This test connects
// as that reader, sends a predicate-free SELECT, and relies on
// SQL_probectl_tenant to keep tenant B invisible.
func TestPathSettingScopedReaderCannotCrossTenant(t *testing.T) {
	rawURL := os.Getenv("PROBECTL_PATHSTORE_URL")
	if rawURL == "" {
		t.Skip("PROBECTL_PATHSTORE_URL not set — ClickHouse isolation gate runs in CI")
	}
	c, err := NewClickHouse(rawURL)
	if err != nil {
		t.Fatalf("clickhouse: %v", err)
	}
	ctx := context.Background()
	now := time.Now().UTC()
	ta := fmt.Sprintf("pathreda%d", now.UnixNano())
	tb := fmt.Sprintf("pathredb%d", now.UnixNano())
	readerA := fmt.Sprintf("pathredra%d", now.UnixNano())
	readerB := fmt.Sprintf("pathredrb%d", now.UnixNano())
	readerPw := "readerpw"
	target := fmt.Sprintf("red-target-%d.example", now.UnixNano())
	defer func() {
		_, _, _ = c.DeleteTenant(ctx, ta)
		_, _, _ = c.DeleteTenant(ctx, tb)
		_ = c.exec(ctx, "DROP USER IF EXISTS "+readerA, nil, nil)
		_ = c.exec(ctx, "DROP USER IF EXISTS "+readerB, nil, nil)
	}()

	mk := func(ip string) *path.Path {
		return &path.Path{
			Target: target, TargetIP: ip, Mode: "icmp", MaxHops: 8, TraceCount: 1, DestinationReached: true,
			Hops: []path.Hop{{TTL: 1, Nodes: []path.HopNode{{IP: ip, Sent: 1, Received: 1, RTTAvgMs: 1.5}}}},
		}
	}
	for _, item := range []struct {
		tenant string
		ip     string
	}{
		{tenant: ta, ip: "198.51.100.10"},
		{tenant: ta, ip: "198.51.100.11"},
		{tenant: tb, ip: "192.0.2.99"},
	} {
		if err := c.Save(ctx, item.tenant, mk(item.ip)); err != nil {
			t.Fatalf("save %s: %v", item.tenant, err)
		}
	}

	for _, reader := range []string{readerA, readerB} {
		for _, ddl := range []string{
			fmt.Sprintf("CREATE USER IF NOT EXISTS %s IDENTIFIED BY '%s'", reader, readerPw),
			fmt.Sprintf("GRANT SELECT ON *.* TO %s", reader),
		} {
			if err := c.exec(ctx, ddl, nil, nil); err != nil {
				t.Fatalf("provision reader user: %v (%s)", err, ddl)
			}
		}
	}
	// Install for A, then rotate the fixed policy to B. IF NOT EXISTS would
	// retain A's TO binding and leave B unfiltered; OR REPLACE must converge it.
	if err := c.EnsureReaderRowPolicy(ctx, readerA); err != nil {
		t.Fatalf("install reader A policy: %v", err)
	}
	if err := c.EnsureReaderRowPolicy(ctx, readerB); err != nil {
		if strings.Contains(err.Error(), "etting") {
			t.Skipf("custom settings prefix not configured on this server: %v", err)
		}
		t.Fatalf("EnsureReaderRowPolicy: %v", err)
	}

	n, errText := pathCountAs(t, readerB, readerPw, ta)
	if errText != "" {
		if strings.Contains(errText, "etting") {
			t.Skipf("custom settings prefix not configured: %s", errText)
		}
		t.Fatalf("reader read failed: %s", errText)
	}
	if n != 2 {
		t.Fatalf("reader saw %d path hop rows via a predicate-free query, want exactly tenant A's 2 (CROSS-TENANT LEAK if >2)", n)
	}
}

func pathCountAs(t *testing.T, user, pass, tenant string) (int, string) {
	t.Helper()
	base, err := url.Parse(os.Getenv("PROBECTL_PATHSTORE_URL"))
	if err != nil {
		t.Fatalf("parse pathstore url: %v", err)
	}
	q := url.Values{"query": {"SELECT count() AS n FROM " + hopsTable + " FORMAT TabSeparated"}}
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
