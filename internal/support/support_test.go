package support

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/version"
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
		Health:      Health{Status: StatusOK},
		SelfMetrics: map[string]float64{"goroutines": 12},
		Topology:    TopologySummary{Tenants: 3, Agents: 9, Region: "us-east"},
		Runtime:     CollectRuntime(time.Now().Add(-time.Hour)),
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
	for _, want := range []string{"manifest.json", "version.json", "config-redacted.json", "health.json", "self-metrics.json", "topology-summary.json", "runtime.json"} {
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
	checks := map[string]CheckFunc{
		"database": PingCheck("database", func(context.Context) error { return nil }),
		"bus":      func(context.Context) Check { return Check{Status: StatusDegraded, Detail: "lagging"} },
		"secrets":  PingCheck("secrets", func(context.Context) error { return errors.New("vault sealed") }),
	}
	h := RunChecks(context.Background(), checks, func() time.Time { return time.Unix(1700000000, 0) })
	if h.Status != StatusDown { // the worst (secrets is down) wins
		t.Fatalf("aggregate must be the worst component: %s", h.Status)
	}
	if len(h.Checks) != 3 || h.Checks[0].Name != "bus" || h.Checks[1].Name != "database" || h.Checks[2].Name != "secrets" {
		t.Fatalf("checks must be name-sorted: %+v", h.Checks)
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
