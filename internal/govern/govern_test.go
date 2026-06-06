package govern

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// TestIPsAsPII is the headline: an IP address classifies as PII by default and
// redacts to its network prefix (host identity dropped), for both v4 and v6.
func TestIPsAsPII(t *testing.T) {
	if DefaultClassOf(CatIPAddress) != ClassPII {
		t.Fatalf("ip_address must default to PII, got %s", DefaultClassOf(CatIPAddress))
	}
	for in, want := range map[string]string{
		"203.0.113.42":          "203.0.113.0/24",
		"10.1.2.3":              "10.1.2.0/24",
		"2001:db8:1234:5678::1": "2001:db8:1234::/48",
		"not-an-ip":             "no******", // generic fallback (2 kept + 6 masked)
	} {
		got := Redact(CatIPAddress, in, StrategyPartial)
		if got != want {
			t.Errorf("RedactIP(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestRedactionStrategies: each strategy behaves correctly and is idempotent
// where meaningful; non-PII categories are untouched below RedactFrom.
func TestRedactionStrategies(t *testing.T) {
	// partial masks per category.
	if got := Redact(CatEmail, "alice@example.com", StrategyPartial); got != "a***@example.com" {
		t.Errorf("email partial: %q", got)
	}
	if got := Redact(CatMAC, "00:1a:2b:3c:4d:5e", StrategyPartial); got != "00:1a:2b:xx:xx:xx" {
		t.Errorf("mac partial: %q", got)
	}
	// drop removes the value.
	if got := Redact(CatIPAddress, "203.0.113.42", StrategyDrop); got != "" {
		t.Errorf("drop: %q", got)
	}
	// hash is stable + non-reversible-looking.
	h1 := Redact(CatIPAddress, "203.0.113.42", StrategyHash)
	h2 := Redact(CatIPAddress, "203.0.113.42", StrategyHash)
	if h1 != h2 || !strings.HasPrefix(h1, "sha256:") || strings.Contains(h1, "203.0.113") {
		t.Errorf("hash unstable/leaky: %q vs %q", h1, h2)
	}
	// none is a no-op.
	if got := Redact(CatIPAddress, "203.0.113.42", StrategyNone); got != "203.0.113.42" {
		t.Errorf("none must not change: %q", got)
	}
}

// TestPolicyClassificationAndStrategy: overrides re-classify; RedactFrom gates
// which classes redact; Restricted always drops.
func TestPolicyClassificationAndStrategy(t *testing.T) {
	// Default policy redacts PII+ : ip (PII) redacts, hostname (Internal) does not.
	def := DefaultPIIPolicy()
	if def.StrategyFor(CatIPAddress) == StrategyNone {
		t.Fatal("PII must redact under the default policy")
	}
	if def.StrategyFor(CatHostname) != StrategyNone {
		t.Fatal("Internal (hostname) must NOT redact under a PII-floor policy")
	}
	// An override re-classifies hostname up to PII → now it redacts.
	strict := Policy{Overrides: map[Category]Class{CatHostname: ClassPII}, RedactFrom: ClassPII}
	if strict.StrategyFor(CatHostname) == StrategyNone {
		t.Fatal("re-classified hostname must redact")
	}
	// Restricted always drops, regardless of strategy table.
	if (Policy{RedactFrom: ClassInternal}).StrategyFor(CatCredential) != StrategyDrop {
		t.Fatal("Restricted (credential) must always drop")
	}
	// A lower RedactFrom pulls more classes in.
	loose := Policy{RedactFrom: ClassConfidential}
	if loose.StrategyFor(CatMAC) == StrategyNone {
		t.Fatal("Confidential (mac) must redact when RedactFrom=Confidential")
	}
}

// TestRedactRowAndJSONL: row/JSONL redaction masks sensitive columns by
// category mapping, leaves non-sensitive columns intact, and stays well-formed.
func TestRedactRowAndJSONL(t *testing.T) {
	pol := DefaultPIIPolicy()
	row := map[string]any{
		"source_address": "198.51.100.7",
		"dest_address":   "203.0.113.9",
		"hostname":       "edge-router-1", // Internal: not redacted at PII floor
		"name":           "icmp probe",    // unclassified: untouched
		"bytes":          float64(1024),   // numeric: untouched
		"secret":         "hunter2",       // Restricted: dropped
	}
	RedactRow(pol, row)
	if row["source_address"] != "198.51.100.0/24" || row["dest_address"] != "203.0.113.0/24" {
		t.Fatalf("IPs not masked: %+v", row)
	}
	if row["hostname"] != "edge-router-1" {
		t.Fatalf("hostname must survive at the PII floor: %+v", row)
	}
	if row["name"] != "icmp probe" || row["bytes"] != float64(1024) {
		t.Fatalf("non-sensitive fields must survive: %+v", row)
	}
	if row["secret"] != "" {
		t.Fatalf("credential must be dropped: %+v", row)
	}

	jsonl := []byte(`{"source_address":"10.0.0.5","name":"a"}` + "\n" +
		`{"source_address":"10.0.0.9","name":"b"}` + "\n" +
		`not json` + "\n")
	out := RedactJSONL(pol, jsonl)
	lines := strings.Split(strings.TrimRight(string(out), "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("line count changed: %d", len(lines))
	}
	var first map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &first); err != nil {
		t.Fatal(err)
	}
	if first["source_address"] != "10.0.0.0/24" || first["name"] != "a" {
		t.Fatalf("jsonl redaction: %+v", first)
	}
	if lines[2] != "not json" {
		t.Fatalf("malformed line must pass through: %q", lines[2])
	}
}

// fakeSource is a test PolicySource.
type fakeSource struct {
	pol   Policy
	ok    bool
	calls int
}

func (f *fakeSource) PolicyFor(context.Context, string) (Policy, bool, error) {
	f.calls++
	return f.pol, f.ok, nil
}

// TestSeam: PolicyFor returns the zero policy with no source, the stored policy
// when a source has one, and the default on a miss.
func TestSeam(t *testing.T) {
	defer Reset()
	Reset()
	if got := PolicyFor(context.Background(), "tnA"); got.RedactFrom != ClassUnset {
		t.Fatalf("no source must yield the zero policy: %+v", got)
	}
	src := &fakeSource{pol: Policy{RedactFrom: ClassConfidential, RedactExport: true}, ok: true}
	SetSource(src)
	got := PolicyFor(context.Background(), "tnA")
	if got.RedactFrom != ClassConfidential || !got.RedactExport {
		t.Fatalf("installed policy not returned: %+v", got)
	}
	src.ok = false
	if got := PolicyFor(context.Background(), "tnA"); got.RedactFrom != ClassUnset {
		t.Fatalf("a miss must fall back to the default: %+v", got)
	}
}

func TestClassRoundTrip(t *testing.T) {
	for _, c := range []Class{ClassPublic, ClassInternal, ClassConfidential, ClassPII, ClassRestricted} {
		if ParseClass(c.String()) != c {
			t.Errorf("round-trip %s", c)
		}
	}
	if ParseClass("nonsense") != ClassUnset {
		t.Error("unknown class must parse to unset")
	}
}
