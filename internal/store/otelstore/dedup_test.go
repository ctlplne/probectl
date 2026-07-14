// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package otelstore

import (
	"testing"
	"time"
)

// CORRECT-004: OTLP spans + logs were plain MergeTrees with no dedup, so an
// at-least-once redelivered span/log batch became a PERMANENT duplicate. The
// fix makes both tables ReplacingMergeTrees (spans keyed on (trace_id, span_id),
// logs on a deterministic dedup_id) and reads them with FINAL.
//
// This is the always-on gate: it asserts (a) the shipped schema is the dedup
// ReplacingMergeTree shape and (b) a redelivered log gets the SAME dedup_id
// while a genuinely-different log gets a different one. The live "redelivered
// span/log dedupes once" assertion against real ClickHouse is
// TestOtelDedupRealRoundTrip (build tag `integration`).
func TestDedupSchemaAndKey(t *testing.T) {
	// Schema shape: v2 migration must produce ReplacingMergeTrees read with FINAL.
	migs := chMigrations()
	if len(migs) < 2 {
		t.Fatalf("expected a v2 dedup migration, got %d migrations", len(migs))
	}
	joined := ""
	for _, s := range migs[1].Statements {
		joined += s + "\n"
	}
	if !contains(joined, "ReplacingMergeTree") {
		t.Errorf("v2 migration does not rebuild into ReplacingMergeTree:\n%s", joined)
	}
	spansSQL := createSpansDedupDDL(spansTable)
	if !contains(spansSQL, "ReplacingMergeTree") || !contains(spansSQL, "span_id)") {
		t.Errorf("spans dedup DDL missing ReplacingMergeTree / (trace_id, span_id) key:\n%s", spansSQL)
	}
	logsSQL := createLogsDedupDDL(logsTable)
	if !contains(logsSQL, "ReplacingMergeTree") || !contains(logsSQL, "dedup_id)") {
		t.Errorf("logs dedup DDL missing ReplacingMergeTree / dedup_id key:\n%s", logsSQL)
	}

	// dedup_id determinism: a redelivered identical log hashes identically;
	// a genuine difference yields a different id.
	base := time.Date(2026, 6, 13, 10, 0, 0, 0, time.UTC)
	a := LogRecord{
		TenantID: "t1", TS: base, SeverityNum: 9, SeverityText: "info",
		Service: "checkout", Body: "info", TraceID: "aa", SpanID: "01",
		Attrs: map[string]string{"request_id": "req-a", "http.route": "/checkout"},
	}
	a2 := a // identical redelivery
	if logDedupID(a) != logDedupID(a2) {
		t.Error("identical redelivered log produced a different dedup_id (would not collapse)")
	}
	a3 := a
	a3.Attrs = map[string]string{"http.route": "/checkout", "request_id": "req-a"}
	if logDedupID(a) != logDedupID(a3) {
		t.Error("same log attrs in different map order produced a different dedup_id")
	}
	b := a
	b.Body = "different"
	if logDedupID(a) == logDedupID(b) {
		t.Error("two distinct log lines collapsed to the same dedup_id (would lose a real log)")
	}
	c := a
	c.Attrs = map[string]string{"request_id": "req-b", "http.route": "/checkout"}
	if logDedupID(a) == logDedupID(c) {
		t.Error("two logs that differ only by attrs collapsed to the same dedup_id (would lose a real log)")
	}
}

func TestLogAttrsAffectDedupID(t *testing.T) {
	base := time.Date(2026, 6, 13, 10, 0, 0, 0, time.UTC)
	a := LogRecord{
		TenantID: "t1", TS: base, SeverityNum: 9, SeverityText: "info",
		Service: "checkout", Body: "paid", TraceID: "aa", SpanID: "01",
		Attrs: map[string]string{"request_id": "req-a", "http.route": "/checkout"},
	}
	orderedDifferently := a
	orderedDifferently.Attrs = map[string]string{"http.route": "/checkout", "request_id": "req-a"}
	if logDedupID(a) != logDedupID(orderedDifferently) {
		t.Fatal("same log attrs in different map order must keep the same dedup_id")
	}

	changedAttr := a
	changedAttr.Attrs = map[string]string{"request_id": "req-b", "http.route": "/checkout"}
	if logDedupID(a) == logDedupID(changedAttr) {
		t.Fatal("changing only log attrs must produce a different dedup_id")
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
