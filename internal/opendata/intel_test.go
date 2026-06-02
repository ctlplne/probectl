package opendata

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"
)

const (
	sha1Hex = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0" // 40 hex
	ja3Hex  = "0123456789abcdef0123456789abcdef"         // 32 hex (md5)
)

// --- per-feed parser fixtures (the body is untrusted input; comments/blanks are skipped) ---

func TestFeedParsers(t *testing.T) {
	tests := []struct {
		name  string
		parse func(string) (IOC, bool)
		body  string
		want  []IOC
	}{
		{
			name:  "spamhaus_drop",
			parse: spamhausParse,
			body:  "; comment\n198.51.100.0/24 ; SBL123\n\n203.0.113.0/24 ; SBL456\nnotacidr ; x\n",
			want: []IOC{
				{Type: IOCTypeCIDR, Value: "198.51.100.0/24", Source: "spamhaus_drop", Category: CategorySpam, Confidence: 90, License: "Spamhaus DROP"},
				{Type: IOCTypeCIDR, Value: "203.0.113.0/24", Source: "spamhaus_drop", Category: CategorySpam, Confidence: 90, License: "Spamhaus DROP"},
			},
		},
		{
			name:  "feodo_tracker",
			parse: feodoParse,
			body:  "# Feodo Tracker\n192.0.2.10\n192.0.2.11\nbad line with spaces\n",
			want: []IOC{
				{Type: IOCTypeIP, Value: "192.0.2.10", Source: "feodo_tracker", Category: CategoryBotnetC2, Confidence: 90, License: "abuse.ch CC0"},
				{Type: IOCTypeIP, Value: "192.0.2.11", Source: "feodo_tracker", Category: CategoryBotnetC2, Confidence: 90, License: "abuse.ch CC0"},
			},
		},
		{
			name:  "sslbl_cert",
			parse: sslblCertParse,
			body:  "# Firstseen,SHA1,Listingreason\n2024-01-01 00:00:00," + sha1Hex + ",Dridex C&C\nshorthash,x,y\n",
			want: []IOC{
				{Type: IOCTypeCertSHA1, Value: sha1Hex, Source: "sslbl", Category: "Dridex C&C", Confidence: 95, License: "abuse.ch CC0"},
			},
		},
		{
			name:  "sslbl_ja3",
			parse: sslblJA3Parse,
			body:  "# ja3_md5,Firstseen,Lastseen,Listingreason\n" + ja3Hex + ",2024-01-01 00:00:00,2024-01-02 00:00:00,Malware JA3\n",
			want: []IOC{
				{Type: IOCTypeJA3, Value: ja3Hex, Source: "sslbl_ja3", Category: "Malware JA3", Confidence: 85, License: "abuse.ch CC0"},
			},
		},
		{
			name:  "urlhaus",
			parse: urlhausParse,
			body:  "# id,dateadded,url,...\n\"123\",\"2024-01-01 00:00:00\",\"http://evil.example/x.exe\",\"online\",\"malware\",\"tag\",\"link\",\"rep\"\n\"124\",\"2024-01-01\",\"notaurl\",\"online\"\n",
			want: []IOC{
				{Type: IOCTypeURL, Value: "http://evil.example/x.exe", Source: "urlhaus", Category: CategoryMalware, Confidence: 85, License: "abuse.ch CC0"},
			},
		},
		{
			name:  "tor_exit",
			parse: torParse,
			body:  "192.0.2.50\n2001:db8::1\n",
			want: []IOC{
				{Type: IOCTypeIP, Value: "192.0.2.50", Source: "tor_exit", Category: CategoryTorExit, Confidence: 50, License: "Tor Project CC0"},
				{Type: IOCTypeIP, Value: "2001:db8::1", Source: "tor_exit", Category: CategoryTorExit, Confidence: 50, License: "Tor Project CC0"},
			},
		},
		{
			name:  "firehol_level1",
			parse: fireholParse,
			body:  "# FireHOL level1\n198.51.100.0/22\n192.0.2.200\n",
			want: []IOC{
				{Type: IOCTypeCIDR, Value: "198.51.100.0/22", Source: "firehol_level1", Category: CategoryBlocklist, Confidence: 75, License: "FireHOL aggregate"},
				{Type: IOCTypeIP, Value: "192.0.2.200", Source: "firehol_level1", Category: CategoryBlocklist, Confidence: 75, License: "FireHOL aggregate"},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := parseFeed(strings.NewReader(tc.body), tc.parse)
			if len(got) != len(tc.want) {
				t.Fatalf("parsed %d IOCs, want %d: %+v", len(got), len(tc.want), got)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("ioc[%d] = %+v, want %+v", i, got[i], tc.want[i])
				}
			}
		})
	}
}

// --- store scoring ---

func TestIOCStoreScoring(t *testing.T) {
	s := NewIOCStore()
	s.Load([]IOC{
		{Type: IOCTypeIP, Value: "192.0.2.10", Source: "feodo_tracker", Category: CategoryBotnetC2, Confidence: 90, License: "abuse.ch CC0"},
		{Type: IOCTypeCIDR, Value: "198.51.100.0/24", Source: "spamhaus_drop", Category: CategorySpam, Confidence: 90, License: "Spamhaus DROP"},
		{Type: IOCTypeDomain, Value: "Evil.Example.", Source: "urlhaus", Category: CategoryMalware, Confidence: 80},
		{Type: IOCTypeURL, Value: "http://evil.example/x.exe", Source: "urlhaus", Category: CategoryMalware, Confidence: 85},
		{Type: IOCTypeCertSHA1, Value: strings.ToUpper(sha1Hex), Source: "sslbl", Category: CategoryMaliciousCert, Confidence: 95, License: "abuse.ch CC0"},
		{Type: IOCTypeJA3, Value: ja3Hex, Source: "sslbl_ja3", Category: CategoryMaliciousJA3, Confidence: 85},
		{Type: IOCTypeIP, Value: "not-an-ip", Source: "feodo_tracker"}, // malformed -> skipped
	})

	if got := s.Count(); got != 6 {
		t.Fatalf("Count = %d, want 6 (malformed skipped)", got)
	}

	// exact IP
	if m := s.ScoreIP("192.0.2.10"); len(m) != 1 || m[0].Source != "feodo_tracker" || m[0].Category != CategoryBotnetC2 {
		t.Errorf("ScoreIP exact = %+v", m)
	}
	// IP inside a loaded CIDR -> match carries the CIDR as the indicator + source attribution
	m := s.ScoreIP("198.51.100.77")
	if len(m) != 1 || m[0].Indicator != "198.51.100.0/24" || m[0].Source != "spamhaus_drop" {
		t.Fatalf("ScoreIP in-CIDR = %+v", m)
	}
	// clean IP -> no match
	if m := s.ScoreIP("8.8.8.8"); len(m) != 0 {
		t.Errorf("ScoreIP clean = %+v, want none", m)
	}
	// domain is case-insensitive + trailing-dot-insensitive
	if m := s.ScoreDomain("evil.example"); len(m) != 1 || m[0].Source != "urlhaus" {
		t.Errorf("ScoreDomain = %+v", m)
	}
	if m := s.ScoreURL("http://evil.example/x.exe"); len(m) != 1 {
		t.Errorf("ScoreURL = %+v", m)
	}
	// cert SHA1 stored uppercase, queried lowercase -> still matches; attribution preserved
	cm := s.ScoreCert(sha1Hex, "")
	if len(cm) != 1 || cm[0].Source != "sslbl" || cm[0].License != "abuse.ch CC0" || cm[0].Confidence != 95 {
		t.Fatalf("ScoreCert sha1 = %+v", cm)
	}
	// JA3 match
	if jm := s.ScoreCert("", ja3Hex); len(jm) != 1 || jm[0].Type != IOCTypeJA3 {
		t.Errorf("ScoreCert ja3 = %+v", jm)
	}
	// both at once
	if bm := s.ScoreCert(sha1Hex, ja3Hex); len(bm) != 2 {
		t.Errorf("ScoreCert both = %+v, want 2", bm)
	}

	// Sources sorted by name with per-source counts (the AUP/status matrix)
	srcs := s.Sources()
	if len(srcs) != 5 {
		t.Fatalf("Sources = %+v, want 5 distinct", srcs)
	}
	if srcs[0].Source != "feodo_tracker" || srcs[0].Count != 1 {
		t.Errorf("Sources[0] = %+v", srcs[0])
	}
}

func TestIOCStoreLoadIsAtomicReplace(t *testing.T) {
	s := NewIOCStore()
	s.Load([]IOC{{Type: IOCTypeIP, Value: "192.0.2.10", Source: "a"}})
	s.Load([]IOC{{Type: IOCTypeIP, Value: "203.0.113.5", Source: "b"}}) // replaces, not merges
	if m := s.ScoreIP("192.0.2.10"); len(m) != 0 {
		t.Errorf("old IOC still present after reload: %+v", m)
	}
	if m := s.ScoreIP("203.0.113.5"); len(m) != 1 {
		t.Errorf("new IOC missing after reload: %+v", m)
	}
}

// --- lineFeed.Fetch over a hardened (injected) client ---

func TestLineFeedFetch(t *testing.T) {
	body := "# header\n192.0.2.10\n192.0.2.11\n"
	doer := &fakeDoer{fn: func(req *http.Request) (*http.Response, error) {
		if req.URL.String() != urlFeodo {
			t.Errorf("unexpected URL %s", req.URL)
		}
		return jsonResp(http.StatusOK, body), nil
	}}
	f := NewFeodoTracker(doer)
	iocs, err := f.Fetch(context.Background())
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(iocs) != 2 {
		t.Fatalf("got %d iocs, want 2", len(iocs))
	}
	if f.Descriptor().AUP.CommercialUse != CommercialAllowed {
		t.Errorf("feodo AUP = %v", f.Descriptor().AUP.CommercialUse)
	}
}

func TestLineFeedFetchErrors(t *testing.T) {
	// non-200 -> error (graceful: caller keeps last-good)
	bad := &fakeDoer{fn: func(*http.Request) (*http.Response, error) {
		return jsonResp(http.StatusServiceUnavailable, "rate limited"), nil
	}}
	if _, err := NewSpamhausDROP(bad).Fetch(context.Background()); err == nil {
		t.Error("want error on non-200")
	}
	// transport error -> error
	boom := &fakeDoer{fn: func(*http.Request) (*http.Response, error) {
		return nil, errors.New("dial tcp: no route")
	}}
	if _, err := NewURLhaus(boom).Fetch(context.Background()); err == nil {
		t.Error("want error on transport failure")
	}
}

// --- refresher: graceful degradation keeps last-good ---

func TestIntelRefresherGracefulDegradation(t *testing.T) {
	store := NewIOCStore()
	calls := 0
	// a flaky feed: ok on the first refresh, failing on the second
	flaky := &fakeDoer{fn: func(*http.Request) (*http.Response, error) {
		calls++
		if calls == 1 {
			return jsonResp(http.StatusOK, "192.0.2.10\n192.0.2.11\n"), nil
		}
		return jsonResp(http.StatusBadGateway, "down"), nil
	}}
	r := NewIntelRefresher(store, []ThreatIntelSource{NewFeodoTracker(flaky)}, time.Hour, discardLogger())

	if n := r.Refresh(context.Background()); n != 2 {
		t.Fatalf("first refresh loaded %d, want 2", n)
	}
	// second refresh: feed is down -> last-good (2) is retained, store not emptied
	if n := r.Refresh(context.Background()); n != 2 {
		t.Fatalf("second refresh loaded %d, want last-good 2", n)
	}
	if m := store.ScoreIP("192.0.2.10"); len(m) != 1 {
		t.Errorf("last-good IOC dropped after feed outage: %+v", m)
	}
}

func TestIntelRefresherUnionAcrossSources(t *testing.T) {
	store := NewIOCStore()
	a := &fakeDoer{fn: func(*http.Request) (*http.Response, error) {
		return jsonResp(http.StatusOK, "192.0.2.10\n"), nil
	}}
	b := &fakeDoer{fn: func(*http.Request) (*http.Response, error) {
		return jsonResp(http.StatusOK, "198.51.100.0/24 ; SBL1\n"), nil
	}}
	r := NewIntelRefresher(store, []ThreatIntelSource{NewFeodoTracker(a), NewSpamhausDROP(b)}, time.Hour, discardLogger())
	if n := r.Refresh(context.Background()); n != 2 {
		t.Fatalf("union loaded %d, want 2", n)
	}
	if len(store.ScoreIP("192.0.2.10")) != 1 || len(store.ScoreIP("198.51.100.5")) != 1 {
		t.Error("union of feeds not both queryable")
	}
}

func TestNewIntelFeeds(t *testing.T) {
	feeds := NewIntelFeeds(append(IntelFeedNames(), "bogus"), nil)
	if len(feeds) != len(IntelFeedNames()) {
		t.Fatalf("built %d feeds, want %d (bogus skipped)", len(feeds), len(IntelFeedNames()))
	}
	if _, ok := NewIntelFeed("bogus", nil); ok {
		t.Error("bogus feed should be unknown")
	}
}
