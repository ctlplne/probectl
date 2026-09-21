// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package control

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/testsupport"
)

// The real-stack receipt for tenant isolation (F50) and the storage-layer
// enforcement claim (CLM-STORAGE-LAYER-TENANCY) — docs/guardrails.md G7-1, the
// one whose failure is catastrophic.
//
// What was bound before gave both tenants IDENTICAL row counts and values. That
// shape cannot fail the way it needs to: if tenant A's rows were served to tenant
// B, every assertion still passes, because the two answers are indistinguishable.
// A receipt for an isolation guarantee has to be able to tell substitution from
// correctness, and that one could not.
//
// This one spans both stores a tenant's data actually lives in — Postgres for
// state and ClickHouse for events — and gives each tenant a DIFFERENT number of
// differently-valued rows, so substitution changes the count and the bytes. It
// then asks the question from both sides: A must see only A, and B must see only
// B. One-directional isolation tests miss a fence that leaks in the other
// direction, which is the direction nobody thinks to check.
//
// The query path is the public API (GET /v1/flows/top) and then the real CLI
// (`probectl flow top`) against a live server, not the store, so the fence is
// exercised where a request enters rather than where the developer hopes it holds.
func TestTwoTenantMultiStoreIsolationSurvivesSubstitution(t *testing.T) {
	flowURL := os.Getenv("PROBECTL_FLOWSTORE_URL")
	if flowURL == "" {
		testsupport.SkipOrFatal(t, "PROBECTL_FLOWSTORE_URL not set — the multi-store isolation receipt needs a real ClickHouse")
	}
	ch, err := flowstore.NewClickHouse(flowURL, 0)
	if err != nil {
		t.Fatalf("clickhouse: %v", err)
	}

	// Real Postgres for tenant state; the server gets the real ClickHouse store.
	srv, db := setupAPIServerWithLatest(t, nil)
	h := srv.WithFlowStore(ch).Handler()
	ctx := context.Background()

	tenantA := freshTenant(t, db, "isoA")
	tenantB := freshTenant(t, db, "isoB")

	// Deliberately asymmetric: different talker counts AND different byte
	// volumes, so a substituted answer is arithmetically wrong, not just
	// mislabelled.
	now := time.Now().UTC()
	seedTenantFlows(ctx, t, ch, tenantA, now, []flowSeed{
		{src: "10.10.0.1", bytes: 1_000},
		{src: "10.10.0.2", bytes: 2_000},
	})
	seedTenantFlows(ctx, t, ch, tenantB, now, []flowSeed{
		{src: "10.20.0.1", bytes: 7_000},
		{src: "10.20.0.2", bytes: 8_000},
		{src: "10.20.0.3", bytes: 9_000},
	})

	// ── the public API, from both sides ────────────────────────────────────
	topA := flowTop(t, h, tenantA)
	topB := flowTop(t, h, tenantB)
	if len(topA) != 2 {
		t.Fatalf("tenant A sees %d talkers, want 2 — the seed did not land, so every assertion below would be vacuous", len(topA))
	}
	if len(topB) != 3 {
		t.Fatalf("tenant B sees %d talkers, want 3", len(topB))
	}
	assertOnlyOwnFlows(t, "tenant A", topA, "10.10.", "10.20.", 3_000)
	assertOnlyOwnFlows(t, "tenant B", topB, "10.20.", "10.10.", 24_000)

	// The analytics themselves, not only the fence: top-talker means RANKED, so
	// the heaviest source has to come first and carry its own byte total. An
	// isolation assertion alone would pass on a correctly-scoped but wrongly
	// aggregated answer.
	if key, _ := topB[0]["key"].(string); key != "10.20.0.3" {
		t.Errorf("top talker for tenant B = %q, want 10.20.0.3 (the heaviest at 9000 bytes)", key)
	}
	var prev float64 = 1 << 62
	for _, item := range topB {
		bytes, ok := item["bytes"].(float64)
		if !ok {
			t.Fatalf("talker has no numeric bytes: %+v", item)
		}
		if bytes > prev {
			t.Errorf("top talkers are not ranked descending: %v after %v", bytes, prev)
		}
		prev = bytes
	}

	// ── the real CLI, from both sides ──────────────────────────────────────
	live := httptest.NewServer(h)
	defer live.Close()
	outA, codeA := runCLI(t, live.URL, tenantA, "flow", "top")
	if codeA != 0 {
		t.Fatalf("`probectl flow top` for tenant A exited %d: %s", codeA, outA)
	}
	if !strings.Contains(outA, "10.10.") {
		t.Errorf("CLI shows tenant A none of its own talkers: %s", outA)
	}
	if strings.Contains(outA, "10.20.") {
		t.Errorf("CLI leaks tenant B's talkers to tenant A: %s", outA)
	}
	outB, codeB := runCLI(t, live.URL, tenantB, "flow", "top")
	if codeB != 0 {
		t.Fatalf("`probectl flow top` for tenant B exited %d: %s", codeB, outB)
	}
	if strings.Contains(outB, "10.10.") {
		t.Errorf("CLI leaks tenant A's talkers to tenant B: %s", outB)
	}

	// ── a tenant with no data must get nothing, not someone else's ─────────
	// The empty case is where a missing fence shows up most often: a query with
	// no rows of its own is the one most likely to fall back to an unscoped scan.
	tenantC := freshTenant(t, db, "isoC")
	if got := flowTop(t, h, tenantC); len(got) != 0 {
		t.Errorf("a tenant that ingested nothing sees %d talkers: %+v", len(got), got)
	}
}

type flowSeed struct {
	src   string
	bytes uint64
}

func seedTenantFlows(ctx context.Context, t *testing.T, ch *flowstore.ClickHouse, tenant string, now time.Time, seeds []flowSeed) {
	t.Helper()
	rows := make([]flowstore.Row, 0, len(seeds))
	for i, s := range seeds {
		rows = append(rows, flowstore.Row{
			TenantID: tenant, AgentID: "agent-" + tenant[:8], Exporter: "exporter-1", Protocol: "netflow5",
			TS: now.Add(-time.Duration(i+1) * time.Minute), StartTS: now.Add(-time.Duration(i+2) * time.Minute),
			SrcAddr: s.src, DstAddr: "10.99.0.1", SrcPort: uint16(40000 + i), DstPort: 443,
			Transport: "tcp", Bytes: s.bytes, Packets: 10, BytesScaled: s.bytes, PacketsScaled: 10,
			InIf: 1, OutIf: 2,
		})
	}
	if err := ch.Insert(ctx, rows); err != nil {
		t.Fatalf("seed %d flows for %s: %v", len(rows), tenant, err)
	}
}

func flowTop(t *testing.T, h http.Handler, tenant string) []map[string]any {
	t.Helper()
	rec := apiReq(t, h, http.MethodGet, "/v1/flows/top?by=src&window=1h&limit=50", tenant, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /v1/flows/top as %s: %d %s", tenant, rec.Code, rec.Body)
	}
	var body struct {
		Items []map[string]any `json:"items"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode flow top: %v", err)
	}
	return body.Items
}

// assertOnlyOwnFlows checks identity AND arithmetic: every talker belongs to this
// tenant, none belongs to the other, and the total bytes are this tenant's total.
// The byte sum is what makes a substituted answer fail even if the addresses were
// somehow rewritten.
func assertOnlyOwnFlows(t *testing.T, who string, items []map[string]any, ownPrefix, otherPrefix string, wantBytes uint64) {
	t.Helper()
	var total uint64
	for _, item := range items {
		blob := fmt.Sprint(item)
		if !strings.Contains(blob, ownPrefix) {
			t.Errorf("%s: talker does not belong to it (want prefix %s): %s", who, ownPrefix, blob)
		}
		if strings.Contains(blob, otherPrefix) {
			t.Errorf("%s: talker belongs to the OTHER tenant (%s) — cross-tenant leakage: %s", who, otherPrefix, blob)
		}
		if b, ok := item["bytes"].(float64); ok {
			total += uint64(b)
		}
	}
	if total != wantBytes {
		t.Errorf("%s: total bytes = %d, want %d — the answer is not this tenant's data", who, total, wantBytes)
	}
}
