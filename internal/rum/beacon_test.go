package rum

import (
	"strings"
	"testing"
)

func validBeacon() string {
	return `{"v":1,"key":"pk_abc","consent":true,"app":"storefront","host":"Web.Acme.Example",
		"page":"/checkout/12345?token=SECRET#frag","browser":"Chrome",
		"vitals":{"ttfb_ms":120,"lcp_ms":1800,"cls":0.02},"errors":0,"failed_requests":0,"sdk":"0.1.0"}`
}

func TestPeekKeyLenient(t *testing.T) {
	if k := PeekKey([]byte(validBeacon())); k != "pk_abc" {
		t.Errorf("PeekKey = %q want pk_abc", k)
	}
	// Lenient: recovers the key even from a beacon the strict parse refuses
	// (so the rejection is attributed to the right tenant).
	if k := PeekKey([]byte(`{"key":"pk_x","user_id":"u-7","consent":false}`)); k != "pk_x" {
		t.Errorf("PeekKey on rejectable payload = %q want pk_x", k)
	}
	if k := PeekKey([]byte(`garbage`)); k != "" {
		t.Errorf("PeekKey on garbage = %q want empty", k)
	}
}

func TestParseBeaconValidNormalizes(t *testing.T) {
	b, reason, err := ParseBeacon([]byte(validBeacon()))
	if err != nil {
		t.Fatalf("valid beacon rejected: %v (%s)", err, reason)
	}
	if b.Host != "web.acme.example" {
		t.Errorf("host must lowercase: %q", b.Host)
	}
	// THE privacy assertions: query/fragment gone, volatile segment collapsed.
	if b.Page != "/checkout/:id" {
		t.Errorf("page must be redacted to /checkout/:id, got %q", b.Page)
	}
	if strings.Contains(b.Page, "SECRET") {
		t.Error("query string leaked through redaction")
	}
	if b.Browser != "chrome" {
		t.Errorf("browser must map to family, got %q", b.Browser)
	}
}

func TestParseBeaconPrivacyFailClosed(t *testing.T) {
	tests := []struct {
		name   string
		raw    string
		reason RejectReason
	}{
		{"no consent", `{"v":1,"consent":false,"host":"a.example","page":"/"}`, RejectNoConsent},
		{"consent absent", `{"v":1,"host":"a.example","page":"/"}`, RejectNoConsent},
		// The structural privacy gate: ANY unknown field rejects the beacon —
		// identifier-bearing payloads can never ingest.
		{"unknown field user_id", `{"v":1,"consent":true,"host":"a.example","page":"/","user_id":"u-7"}`, RejectMalformed},
		{"unknown field ip", `{"v":1,"consent":true,"host":"a.example","page":"/","ip":"203.0.113.9"}`, RejectMalformed},
		{"garbage", `not json`, RejectMalformed},
		{"wrong version", `{"v":2,"consent":true,"host":"a.example","page":"/"}`, RejectBadField},
		{"host with port", `{"v":1,"consent":true,"host":"a.example:443","page":"/"}`, RejectBadField},
		{"host with path", `{"v":1,"consent":true,"host":"a.example/x","page":"/"}`, RejectBadField},
		{"empty host", `{"v":1,"consent":true,"host":"","page":"/"}`, RejectBadField},
		{"absurd vital", `{"v":1,"consent":true,"host":"a.example","page":"/","vitals":{"lcp_ms":9999999}}`, RejectBadField},
		{"negative errors", `{"v":1,"consent":true,"host":"a.example","page":"/","errors":-1}`, RejectBadField},
	}
	for _, tc := range tests {
		_, reason, err := ParseBeacon([]byte(tc.raw))
		if err == nil {
			t.Errorf("%s: must reject", tc.name)
			continue
		}
		if reason != tc.reason {
			t.Errorf("%s: reason = %s want %s", tc.name, reason, tc.reason)
		}
	}
}

func TestRedactPath(t *testing.T) {
	tests := map[string]string{
		"/checkout?token=abc":                     "/checkout",
		"/order/12345":                            "/order/:id",
		"/u/550e8400-e29b-41d4-a716-446655440000": "/u/:id",
		"/docs/getting-started":                   "/docs/getting-started",
		"":                                        "/",
		"no-slash":                                "/no-slash",
		"/a#frag":                                 "/a",
	}
	for in, want := range tests {
		if got := RedactPath(in); got != want {
			t.Errorf("RedactPath(%q) = %q want %q", in, got, want)
		}
	}
}

func TestToResultCanonicalMapping(t *testing.T) {
	b, _, err := ParseBeacon([]byte(validBeacon()))
	if err != nil {
		t.Fatal(err)
	}
	r := ToResult("t1", "", b, 1234)
	if r.GetTenantId() != "t1" || r.GetCanaryType() != "rum" {
		t.Fatalf("identity wrong: %+v", r)
	}
	if r.GetServerAddress() != "web.acme.example" {
		t.Errorf("host must ride ServerAddress (the join key), got %q", r.GetServerAddress())
	}
	if !r.GetSuccess() {
		t.Error("zero errors must be a successful view")
	}
	if r.GetStartTimeUnixNano() != 1234 {
		t.Error("timestamp must be the server receive time, never the client's")
	}
	// OTel semconv names where they exist.
	if r.GetAttributes()["url.path"] != "/checkout/:id" || r.GetAttributes()["browser.name"] != "chrome" {
		t.Errorf("attributes wrong: %+v", r.GetAttributes())
	}
	if r.GetMetrics()["rum.lcp_ms"] != 1800 {
		t.Errorf("vitals wrong: %+v", r.GetMetrics())
	}
	// The app comes from the VERIFIED key when supplied.
	if got := ToResult("t1", "keyed-app", b, 1).GetAttributes()["rum.app"]; got != "keyed-app" {
		t.Errorf("verified app must win, got %q", got)
	}
	// The app key is transport-only — it must never be stored.
	for k, v := range r.GetAttributes() {
		if v == "pk_abc" || strings.Contains(k, "key") {
			t.Errorf("app key leaked into stored attributes: %s=%s", k, v)
		}
	}
	// An erroring view is not a success.
	b.Errors = 2
	if ToResult("t1", "", b, 1).GetSuccess() {
		t.Error("erroring view must be success=false")
	}
}
