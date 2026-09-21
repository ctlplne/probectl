// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package support

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/version"
)

// TestBundleHasNoSecrets is the named support-bundle test (the safety core,
// guardrail 6): the bundle carries the right diagnostics AND no secret value
// ever appears anywhere in its bytes.
func TestBundleHasNoSecrets(t *testing.T) {
	const (
		envelopeKey = "c2VjcmV0LWtleS1tYXRlcmlhbC1iYXNlNjQtMzJieXRlcw==" // a fake key
		bearerToken = "tok_live_DEADBEEFCAFEBABE12345678"
		dbPassword  = "sup3rs3cr3tDBpass"
	)
	src := Sources{
		Version: version.Info{Version: "v9.9.9", Commit: "abc1234"},
		// The config snapshot is the allowlist: a redacted DSN (no password)
		// and a boolean for the envelope key — never the material.
		ConfigRedacted: map[string]any{
			"database_url":            "postgres://probectl:xxxxx@db:5432/probectl",
			"envelope_key_configured": true,
		},
		Health:           Health{Status: StatusOK},
		SelfMetrics:      map[string]float64{"goroutines": 12},
		Topology:         TopologySummary{Tenants: 3, Agents: 9, Region: "us-east"},
		DeviceCollection: DeviceCollectionSummary{ContractVersion: "probectl.device-collection-outcomes/v1", Receipts: []DeviceCollectionReceipt{}},
		FlowQuality:      FlowQualitySummary{ContractVersion: "probectl.flow-ingest-quality/v1", Receipts: []FlowQualityReceipt{}},
		Runtime:          CollectRuntime(time.Now().Add(-time.Hour)),
		// Defense in depth: even if a secret slipped into a field, it is
		// scrubbed from the assembled bytes.
		RedactValues: []string{envelopeKey, bearerToken, dbPassword},
	}

	var buf bytes.Buffer
	man, err := Generate(&buf, src)
	if err != nil {
		t.Fatal(err)
	}

	files, err := ReadBundle(&buf)
	if err != nil {
		t.Fatal(err)
	}
	// The expected diagnostics files are present.
	for _, want := range []string{"manifest.json", "version.json", "config-redacted.json", "health.json", "self-metrics.json", "topology-summary.json", "device-collection.json", "flow-ingest-quality.json", "runtime.json"} {
		if _, ok := files[want]; !ok {
			t.Fatalf("bundle missing %s (have %v)", want, keys(files))
		}
	}
	if man.Version != "v9.9.9" || man.FormatVersion != 1 {
		t.Fatalf("manifest: %+v", man)
	}

	// NO secret value appears anywhere in the bundle.
	all := bytes.Buffer{}
	for _, b := range files {
		all.Write(b)
	}
	blob := all.String()
	for _, secret := range []string{envelopeKey, bearerToken, dbPassword} {
		if strings.Contains(blob, secret) {
			t.Fatalf("SECRET LEAKED into the bundle: %q", secret)
		}
	}
	// The redacted DSN survives without its password.
	var cfg map[string]any
	if err := json.Unmarshal(files["config-redacted.json"], &cfg); err != nil {
		t.Fatal(err)
	}
	if dsn, _ := cfg["database_url"].(string); !strings.Contains(dsn, "xxxxx") || strings.Contains(dsn, dbPassword) {
		t.Fatalf("redacted DSN: %q", dsn)
	}
}

// TestScrubberSkipsTrivial: the scrubber ignores short values (so it never
// mangles legitimate content by matching "" or "ok").
func TestScrubberSkipsTrivial(t *testing.T) {
	scrub := scrubber([]string{"", "ok", "longenoughsecret"})
	in := []byte(`{"status":"ok","note":"longenoughsecret here"}`)
	out := string(scrub(in))
	if strings.Contains(out, "longenoughsecret") {
		t.Fatalf("long secret not scrubbed: %s", out)
	}
	if !strings.Contains(out, `"status":"ok"`) {
		t.Fatalf("trivial value wrongly scrubbed: %s", out)
	}
}

// TestDeepHealthAggregates: RunChecks reports each component and aggregates to
// the worst status; ordering is stable.
func TestDeepHealthAggregates(t *testing.T) {
	const secret = "postgres://operator:do-not-leak@private-db/probectl"
	checks := map[string]CheckFunc{
		"database": PingCheck("database", func(context.Context) error { return nil }),
		"bus": func(context.Context) Check {
			return Check{
				Status: StatusDegraded,
				Detail: "lagging",
				Finding: NewReadinessFinding(
					"INVALID ID",
					strings.Repeat("summary ", 30),
					strings.Repeat("evidence ", 100),
					LocalAction{Label: "Open cloud console", Href: "https://example.invalid", Kind: ActionNavigate},
				),
			}
		},
		"secrets": PingCheck("secrets", func(context.Context) error { return errors.New(secret) }),
	}
	observedAt := time.Unix(1700000000, 0).UTC()
	h := RunChecks(context.Background(), checks, func() time.Time { return observedAt })
	if h.Status != StatusDown { // the worst (secrets is down) wins
		t.Fatalf("aggregate must be the worst component: %s", h.Status)
	}
	if len(h.Checks) != 3 || h.Checks[0].Name != "bus" || h.Checks[1].Name != "database" || h.Checks[2].Name != "secrets" {
		t.Fatalf("checks must be name-sorted: %+v", h.Checks)
	}
	if h.Checks[1].Finding != nil {
		t.Fatalf("healthy checks must not fabricate operator work: %+v", h.Checks[1])
	}
	for _, c := range []Check{h.Checks[0], h.Checks[2]} {
		if c.Finding == nil || c.Finding.Component != c.Name || c.Finding.Scope != "deployment" || !c.Finding.ObservedAt.Equal(observedAt) {
			t.Fatalf("unhealthy check lacks normalized finding: %+v", c)
		}
	}
	if h.Checks[0].Finding.ID != "readiness.bus" ||
		h.Checks[0].Finding.NextAction.Href != "/admin#support-bundle" ||
		len([]rune(h.Checks[0].Finding.Summary)) > 160 ||
		len([]rune(h.Checks[0].Finding.Evidence)) > 512 {
		t.Fatalf("unsafe or unbounded finding was not normalized: %+v", h.Checks[0].Finding)
	}
	if h.Checks[2].Finding.Severity != FindingCritical ||
		h.Checks[2].Detail != "health check failed" ||
		strings.Contains(h.Checks[2].Detail+h.Checks[2].Finding.Evidence, secret) {
		t.Fatalf("raw dependency error leaked or severity is wrong: %+v", h.Checks[2])
	}
	// A nil ping is down.
	if c := PingCheck("x", nil)(context.Background()); c.Status != StatusDown {
		t.Fatalf("nil ping: %+v", c)
	}
	// All-ok aggregates ok; empty set is ok.
	if RunChecks(context.Background(), nil, nil).Status != StatusOK {
		t.Fatal("empty checks must be ok")
	}
}

func TestReadinessActionsStayWithinTheLocalDeployment(t *testing.T) {
	for _, href := range []string{
		"https://advisor.example.invalid/finding",
		"//advisor.example.invalid/finding",
		`/\advisor.example.invalid/finding`,
		"/admin\nexternal",
	} {
		got := normalizeAction(LocalAction{Label: "Unsafe", Href: href, Kind: ActionNavigate})
		if got.Href != "/admin#support-bundle" || got.Label != "Review diagnostics" {
			t.Fatalf("unsafe action %q was not replaced: %+v", href, got)
		}
	}
	got := normalizeAction(LocalAction{
		Label: "Download redacted support bundle",
		Href:  "/v1/diagnostics/bundle",
		Kind:  ActionDownload,
	})
	if got.Href != "/v1/diagnostics/bundle" || got.Kind != ActionDownload {
		t.Fatalf("safe local action changed: %+v", got)
	}
}

// TestSelfSnapshot: the self-metrics snapshot carries real runtime values.
func TestSelfSnapshot(t *testing.T) {
	m := SelfSnapshot(time.Now().Add(-2 * time.Second))
	if m["goroutines"] < 1 || m["uptime_seconds"] < 1 {
		t.Fatalf("self snapshot: %+v", m)
	}
}

func keys(m map[string][]byte) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
