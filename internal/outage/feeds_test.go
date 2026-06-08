package outage

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"
)

// fakeDoer serves canned responses per URL substring and records requests.
type fakeDoer struct {
	responses map[string]fakeResp // URL substring → response
	requests  []*http.Request
}

type fakeResp struct {
	status int
	body   string
	err    error
}

func (f *fakeDoer) Do(req *http.Request) (*http.Response, error) {
	f.requests = append(f.requests, req)
	for sub, r := range f.responses {
		if strings.Contains(req.URL.String(), sub) {
			if r.err != nil {
				return nil, r.err
			}
			return &http.Response{StatusCode: r.status, Body: io.NopCloser(strings.NewReader(r.body))}, nil
		}
	}
	return nil, errors.New("fakeDoer: no canned response")
}

// Recorded-fixture style payloads (shape per the public APIs; values synthetic).
const iodaFixture = `{"data": [
  {"entity": {"type": "asn", "code": "174", "name": "Cogent"}, "start": 1780660800, "duration": 0, "score": 620, "datasource": "bgp"},
  {"entity": {"type": "country", "code": "br", "name": "Brazil"}, "start": 1780660800, "duration": 1800, "score": 80, "datasource": "ping-slash24"},
  {"location": "AS3356", "location_name": "Lumen", "start": 1780660800, "duration": 0, "score": 20, "datasource": "bgp"},
  {"entity": {"type": "asn", "code": "999"}, "start": 0, "duration": 0, "score": 50, "datasource": "bgp"},
  {"start": 1780660800, "score": 10, "datasource": "bgp"}
]}`

const radarFixture = `{"success": true, "result": {"annotations": [
  {"id": "ann-1", "dataSource": "ALL", "description": "Nationwide outage in Testland",
   "startDate": "2026-06-05T10:00:00Z", "endDate": "",
   "locations": ["TL"], "locationsDetails": [{"code": "TL", "name": "Testland"}],
   "asns": [64500], "asnsDetails": [{"asn": "64500", "name": "Testland Telecom"}],
   "eventType": "OUTAGE", "outage": {"outageCause": "POWER_OUTAGE", "outageType": "NATIONWIDE"}},
  {"id": "", "startDate": "2026-06-05T10:00:00Z"},
  {"id": "ann-3", "startDate": "not-a-date"}
]}}`

func TestIODAFetchNormalizes(t *testing.T) {
	doer := &fakeDoer{responses: map[string]fakeResp{"ioda": {status: 200, body: iodaFixture}}}
	f := NewIODA(doer)
	events, err := f.Fetch(context.Background(), time.Now().Add(-2*time.Hour))
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if len(events) != 3 {
		t.Fatalf("want 3 normalized events (2 malformed skipped), got %d: %+v", len(events), events)
	}

	asn := events[0]
	if asn.Scope.Kind != ScopeASN || asn.Scope.Code != "AS174" || asn.Scope.Name != "Cogent" {
		t.Errorf("asn scope wrong: %+v", asn.Scope)
	}
	if asn.Severity != "critical" || asn.Confidence != 1 {
		t.Errorf("score 620 must map critical/1.0, got %s/%.2f", asn.Severity, asn.Confidence)
	}
	if !asn.End.IsZero() {
		t.Error("duration 0 must be ongoing")
	}
	if !strings.Contains(asn.Evidence, "/asn/174") {
		t.Errorf("evidence deep link wrong: %s", asn.Evidence)
	}

	country := events[1]
	if country.Scope.Kind != ScopeCountry || country.Scope.Code != "BR" {
		t.Errorf("country scope wrong: %+v", country.Scope)
	}
	if country.Severity != "warning" || country.End.IsZero() {
		t.Errorf("score 80 + duration must map warning/ended, got %s end=%v", country.Severity, country.End)
	}

	flat := events[2]
	if flat.Scope.Kind != ScopeASN || flat.Scope.Code != "AS3356" || flat.Severity != "info" {
		t.Errorf("flat-location item wrong: %+v", flat)
	}
}

func TestIODAFetchErrors(t *testing.T) {
	for name, resp := range map[string]fakeResp{
		"non-200":   {status: 503, body: "busy"},
		"bad json":  {status: 200, body: "<html>"},
		"transport": {err: errors.New("timeout")},
	} {
		doer := &fakeDoer{responses: map[string]fakeResp{"ioda": resp}}
		if _, err := NewIODA(doer).Fetch(context.Background(), time.Now()); err == nil {
			t.Errorf("%s: want error", name)
		}
	}
}

func TestRadarFetchExpandsScopesAndAuthenticates(t *testing.T) {
	doer := &fakeDoer{responses: map[string]fakeResp{"radar": {status: 200, body: radarFixture}}}
	f := NewRadar("tok-123", doer)
	events, err := f.Fetch(context.Background(), time.Now().Add(-24*time.Hour))
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	// ann-1 expands per scope: AS64500 + TL; malformed annotations skipped.
	if len(events) != 2 {
		t.Fatalf("want 2 expanded events, got %d: %+v", len(events), events)
	}
	if events[0].Scope.Code != "AS64500" || events[0].Scope.Name != "Testland Telecom" {
		t.Errorf("asn expansion wrong: %+v", events[0].Scope)
	}
	if events[1].Scope.Code != "TL" || events[1].Scope.Kind != ScopeCountry {
		t.Errorf("country expansion wrong: %+v", events[1].Scope)
	}
	for _, e := range events {
		if e.Severity != "critical" {
			t.Errorf("NATIONWIDE must be critical, got %s", e.Severity)
		}
		if !strings.Contains(e.Summary, "power_outage") {
			t.Errorf("cause must ride the summary: %q", e.Summary)
		}
		if !e.Ongoing(time.Now()) {
			t.Error("empty endDate must be ongoing")
		}
	}
	if auth := doer.requests[0].Header.Get("Authorization"); auth != "Bearer tok-123" {
		t.Errorf("radar must send the bearer token, got %q", auth)
	}
}

func TestRadarFetchAPIFailure(t *testing.T) {
	doer := &fakeDoer{responses: map[string]fakeResp{"radar": {status: 200, body: `{"success": false}`}}}
	if _, err := NewRadar("tok", doer).Fetch(context.Background(), time.Now()); err == nil {
		t.Fatal("success=false must be an error")
	}
}

func TestNewFeedsOmitsRadarWithoutToken(t *testing.T) {
	feeds := NewFeeds(nil, "", &fakeDoer{})
	if len(feeds) != 1 || feeds[0].Descriptor().Name != "ioda" {
		t.Fatalf("without a token only ioda should build, got %d feeds", len(feeds))
	}
	feeds = NewFeeds(nil, "tok", &fakeDoer{})
	if len(feeds) != 2 {
		t.Fatalf("with a token both feeds should build, got %d", len(feeds))
	}
	// AUP provenance is tracked per feed (MSP-resale honesty).
	radar := feeds[1].Descriptor()
	if radar.AUP.CommercialUse != "restricted" {
		t.Errorf("radar CC BY-NC must be restricted, got %s", radar.AUP.CommercialUse)
	}
}

func TestRefresherKeepsLastGoodAndReportsHealth(t *testing.T) {
	doer := &fakeDoer{responses: map[string]fakeResp{"ioda": {status: 200, body: iodaFixture}}}
	store := NewStore(0)
	// Pin the store clock to the recorded fixture's epoch (iodaFixture uses
	// start=1780660800) so the 48h retention window deterministically covers all
	// three normalized events. Without this, the one *ended* event (BR, duration
	// 1800) ages out of the window as the wall clock advances past the fixture
	// date — a moving-real-time-fixture flake, not a code defect.
	fixtureNow := time.Unix(1780660800, 0).Add(time.Hour)
	store.clock = func() time.Time { return fixtureNow }
	r := NewRefresher(store, []Feed{NewIODA(doer)}, time.Minute, 48*time.Hour, slog.Default())

	r.Refresh(context.Background())
	if got := len(store.All()); got != 3 {
		t.Fatalf("first refresh: want 3 events, got %d", got)
	}
	h := r.Health()
	if len(h) != 1 || h[0].Status != "ok" || h[0].Events != 3 {
		t.Fatalf("health after success wrong: %+v", h)
	}
	if h[0].Attribution == "" || h[0].License == "" {
		t.Error("health must carry AUP provenance")
	}

	// Feed dies: last-good stays, health says failed.
	doer.responses["ioda"] = fakeResp{err: errors.New("rate limited")}
	r.Refresh(context.Background())
	if got := len(store.All()); got != 3 {
		t.Fatalf("failed refresh must keep last-good, got %d", got)
	}
	h = r.Health()
	if h[0].Status != "failed" || !strings.Contains(h[0].LastError, "rate limited") {
		t.Fatalf("health after failure wrong: %+v", h)
	}
}

func TestRadarRangeMapping(t *testing.T) {
	for d, want := range map[time.Duration]string{
		12 * time.Hour:  "1d",
		48 * time.Hour:  "2d",
		96 * time.Hour:  "7d",
		300 * time.Hour: "14d",
	} {
		if got := radarRange(d); got != want {
			t.Errorf("radarRange(%v) = %s want %s", d, got, want)
		}
	}
}
