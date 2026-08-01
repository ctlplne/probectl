// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package ai

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/ctlplne/probectl/internal/auth"
)

// blockingModel parks every Synthesize until released — for saturating the
// analyzer's concurrency cap deterministically.
type blockingModel struct {
	entered chan struct{} // signaled when a synthesis starts
	release chan struct{} // closed to let syntheses finish
}

func (m *blockingModel) Name() string { return "blocking-test" }
func (m *blockingModel) Synthesize(ctx context.Context, _ SynthesisInput) (Synthesis, error) {
	m.entered <- struct{}{}
	select {
	case <-m.release:
	case <-ctx.Done():
		return Synthesis{}, ctx.Err()
	}
	return Synthesis{RootCause: "done", Confidence: ConfidenceLow, InsufficientEvidence: true}, nil
}

// U-048: with the cap saturated, the next Analyze fails fast with ErrBusy —
// the burst cannot stack up behind a slow model even with no fairness gate.
func TestAnalyzeConcurrencyCapFailsFast(t *testing.T) {
	m := &blockingModel{entered: make(chan struct{}, 1), release: make(chan struct{})}
	a := NewAnalyzer(NewEngine(), WithModel(m), WithMaxConcurrent(1))
	p := &auth.Principal{TenantID: "t1", Permissions: map[string]bool{"metrics.read": true}}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if _, err := a.Analyze(context.Background(), p, Question{Text: "why is x down"}); err != nil {
			t.Errorf("in-flight analyze failed: %v", err)
		}
	}()
	<-m.entered // the single slot is now held inside Synthesize

	if _, err := a.Analyze(context.Background(), p, Question{Text: "second"}); !errors.Is(err, ErrBusy) {
		t.Fatalf("saturated analyzer returned %v, want ErrBusy", err)
	}

	close(m.release) // let the first finish; the slot frees up
	wg.Wait()
	if _, err := a.Analyze(context.Background(), p, Question{Text: "third"}); err != nil {
		t.Fatalf("after release, analyze should be admitted: %v", err)
	}
}

// The default analyzer has a cap without any option (U-048 acceptance: a
// default exists, not only an opt-in).
func TestAnalyzerHasDefaultConcurrencyCap(t *testing.T) {
	a := NewAnalyzer(NewEngine())
	if a.sem == nil || cap(a.sem) != DefaultMaxConcurrent {
		t.Fatalf("default analyzer sem cap = %v, want %d", cap(a.sem), DefaultMaxConcurrent)
	}
}

// U-092: only allow-listed keys survive into the serialized evidence fields;
// raw row extras (a future source's internal columns) are stripped, and an
// unknown domain falls back to the universal list (fail closed).
func TestSanitizeEvidenceFields(t *testing.T) {
	evs := []Evidence{
		{Domain: DomainEntities, Fields: Row{
			"id": "i1", "kind": "incident", "severity": "high", "title": "t",
			"raw_payload": "SECRET-ROW-DATA", "db_ctid": "(0,1)",
		}},
		{Domain: Domain("future-plane"), Fields: Row{
			"title": "ok", "internal_ptr": "0xdead",
		}},
		{Domain: DomainTopology, Fields: nil}, // nil Fields stays nil
	}
	sanitizeEvidenceFields(evs)

	f0 := evs[0].Fields
	if _, leaked := f0["raw_payload"]; leaked {
		t.Fatal("raw_payload leaked through the allow-list")
	}
	if _, leaked := f0["db_ctid"]; leaked {
		t.Fatal("db_ctid leaked through the allow-list")
	}
	for _, k := range []string{"id", "kind", "severity", "title"} {
		if _, ok := f0[k]; !ok {
			t.Fatalf("allow-listed key %q was dropped", k)
		}
	}
	f1 := evs[1].Fields
	if _, leaked := f1["internal_ptr"]; leaked {
		t.Fatal("unknown domain must fall back to the universal allow-list")
	}
	if _, ok := f1["title"]; !ok {
		t.Fatal("universal key dropped for unknown domain")
	}
	if evs[2].Fields != nil {
		t.Fatal("nil Fields must stay nil")
	}
}

// End-to-end: an Analyze answer never carries non-allow-listed evidence fields.
func TestAnalyzeStripsRawEvidenceFields(t *testing.T) {
	src := stubEntities{rows: []Row{{
		"id": "inc-1", "kind": "incident", "plane": "incident", "title": "checkout down",
		"secret_internal": "do-not-expose",
	}}}
	eng := NewEngine(WithEntities(src))
	a := NewAnalyzer(eng)
	p := &auth.Principal{TenantID: "t1", Permissions: map[string]bool{
		"entities.read": true, "metrics.read": true, "events.read": true, "topology.read": true,
	}}
	ans, err := a.Analyze(context.Background(), p, Question{Text: "why is checkout down", Subject: map[string]string{"target": "checkout"}})
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	if len(ans.Evidence) == 0 {
		t.Fatal("expected evidence")
	}
	for _, e := range ans.Evidence {
		if _, leaked := e.Fields["secret_internal"]; leaked {
			t.Fatalf("evidence %s leaked a non-allow-listed field", e.ID)
		}
	}
}

type stubEntities struct{ rows []Row }

func (s stubEntities) QueryEntities(_ context.Context, _ string, _ map[string]string, limit int) ([]Row, error) {
	if limit < len(s.rows) {
		return s.rows[:limit], nil
	}
	return s.rows, nil
}
