package outage

import (
	"testing"
	"time"
)

func at(minutes int) time.Time {
	return time.Date(2026, 6, 5, 12, 0, 0, 0, time.UTC).Add(time.Duration(minutes) * time.Minute)
}

func extEvent(id string, scope Scope, start, end time.Time) Event {
	return Event{ID: id, Source: "ioda", Scope: scope, Severity: "warning",
		Confidence: 0.7, Title: "Internet outage: " + scope.Code, Start: start, End: end}
}

func TestStoreSetEventsValidatesAndRetains(t *testing.T) {
	s := NewStore(2 * time.Hour)
	s.clock = func() time.Time { return at(0) }
	asn := Scope{Kind: ScopeASN, Code: "AS174"}

	tests := []struct {
		name string
		ev   Event
		kept bool
	}{
		{"valid ongoing", extEvent("ioda:a", asn, at(-30), time.Time{}), true},
		{"valid ended recently", extEvent("ioda:b", asn, at(-90), at(-60)), true},
		{"ended before retention", extEvent("ioda:c", asn, at(-300), at(-180)), false},
		{"missing id", extEvent("", asn, at(-10), time.Time{}), false},
		{"mislabeled source", func() Event { e := extEvent("x", asn, at(-10), time.Time{}); e.Source = "spoof"; return e }(), false},
		{"zero start", extEvent("ioda:d", asn, time.Time{}, time.Time{}), false},
	}
	for _, tc := range tests {
		s.SetEvents("ioda", []Event{tc.ev})
		got := len(s.All()) == 1
		if got != tc.kept {
			t.Errorf("%s: kept=%v want %v", tc.name, got, tc.kept)
		}
	}
}

func TestStoreAllSortsNewestFirstAcrossSources(t *testing.T) {
	s := NewStore(0)
	s.clock = func() time.Time { return at(0) }
	asn := Scope{Kind: ScopeASN, Code: "AS174"}
	cty := Scope{Kind: ScopeCountry, Code: "BR"}
	s.SetEvents("ioda", []Event{extEvent("ioda:old", asn, at(-120), time.Time{})})
	radar := extEvent("cloudflare_radar:new", cty, at(-10), time.Time{})
	radar.Source = "cloudflare_radar"
	s.SetEvents("cloudflare_radar", []Event{radar})

	all := s.All()
	if len(all) != 2 || all[0].ID != "cloudflare_radar:new" || all[1].ID != "ioda:old" {
		t.Fatalf("want newest-first across sources, got %+v", all)
	}
}

func TestStoreActiveForMatchesScopeAndWindow(t *testing.T) {
	s := NewStore(0)
	s.clock = func() time.Time { return at(0) }
	asn := Scope{Kind: ScopeASN, Code: "AS174"}
	s.SetEvents("ioda", []Event{
		extEvent("ioda:live", asn, at(-30), time.Time{}),
		extEvent("ioda:done", asn, at(-200), at(-100)),
		extEvent("ioda:other", Scope{Kind: ScopeASN, Code: "AS3356"}, at(-30), time.Time{}),
	})

	got := s.ActiveFor(asn, at(-5))
	if len(got) != 1 || got[0].ID != "ioda:live" {
		t.Fatalf("want only the live AS174 event, got %+v", got)
	}
	// Slack admits a failure shortly after the recorded end (the live event
	// has not started yet at this instant).
	got = s.ActiveFor(asn, at(-95))
	if len(got) != 1 || got[0].ID != "ioda:done" {
		t.Fatalf("slack should admit the just-ended event, got %+v", got)
	}
}

func TestEventOngoing(t *testing.T) {
	now := at(0)
	if !(Event{Start: at(-10)}).Ongoing(now) {
		t.Error("zero end must be ongoing")
	}
	if (Event{Start: at(-10), End: at(-1)}).Ongoing(now) {
		t.Error("ended event must not be ongoing")
	}
}

func TestScopeKeyJoinsKindAndCode(t *testing.T) {
	a := Scope{Kind: ScopeASN, Code: "AS174"}
	b := Scope{Kind: ScopeCountry, Code: "AS174"} // same code, different kind
	if a.Key() == b.Key() {
		t.Fatal("scope keys must separate kinds")
	}
}
