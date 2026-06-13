// SPDX-License-Identifier: LicenseRef-probectl-TBD

package ai

import (
	"context"
	"testing"
)

func TestCorrelateFansOutAndRespectsRBAC(t *testing.T) {
	metrics := newRecordingSource(map[string][]Row{"t": {{"metric": "rtt"}}})
	events := newRecordingSource(map[string][]Row{"t": {{"event": "loss"}}})
	topo := newRecordingSource(map[string][]Row{"t": {{"node": "service:checkout"}}})

	// The caller may read metrics + topology, NOT events / entities.
	e := NewEngine(WithMetrics(metrics), WithEvents(events), WithTopology(topo))
	p := principal("t", PermMetricsRead, PermTopologyRead)

	res, err := e.Correlate(context.Background(), p, map[string]string{"service": "checkout"}, TimeRange{})
	if err != nil {
		t.Fatal(err)
	}

	got := map[Domain]bool{}
	for _, d := range res.Domains {
		got[d] = true
	}
	if !got[DomainMetrics] || !got[DomainTopology] || got[DomainEvents] {
		t.Errorf("provenance = %v, want metrics + topology only (events RBAC-skipped)", res.Domains)
	}
	if len(events.seen()) != 0 {
		t.Error("events source was queried despite the caller lacking events.read")
	}
	for _, row := range res.Rows {
		if row["_domain"] == nil {
			t.Errorf("row missing _domain provenance: %v", row)
		}
	}
}

// AIRCA-002: Correlate output must carry only allow-listed keys (+ the _domain
// marker) — mirroring TestAnalyzeStripsRawEvidenceFields for the correlation
// path. A raw source row with a secret/PII column must not egress.
func TestCorrelateStripsNonAllowListedRowFields(t *testing.T) {
	metrics := newRecordingSource(map[string][]Row{"t": {{
		"metric":          "rtt",      // allow-listed
		"value":           42,         // allow-listed
		"raw_query":       "SELECT *", // NOT allow-listed — must be stripped
		"customer_secret": "hunter2",  // NOT allow-listed — must be stripped
	}}})
	e := NewEngine(WithMetrics(metrics))
	p := principal("t", PermMetricsRead)

	res, err := e.Correlate(context.Background(), p, map[string]string{"service": "checkout"}, TimeRange{})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Rows) != 1 {
		t.Fatalf("rows = %d, want 1", len(res.Rows))
	}
	row := res.Rows[0]
	if row["_domain"] != string(DomainMetrics) {
		t.Errorf("_domain = %v, want metrics", row["_domain"])
	}
	if row["metric"] != "rtt" || row["value"] != 42 {
		t.Errorf("allow-listed keys dropped: %v", row)
	}
	for _, banned := range []string{"raw_query", "customer_secret"} {
		if _, present := row[banned]; present {
			t.Errorf("non-allow-listed key %q leaked through Correlate: %v", banned, row)
		}
	}
}
