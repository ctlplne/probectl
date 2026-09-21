// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package endpoint

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

type fakeWiFi struct {
	w   WiFi
	err error
}

func (f fakeWiFi) Collect(context.Context) (WiFi, error) { return f.w, f.err }

type fakeLastMile struct {
	lm  LastMile
	err error
}

func (f fakeLastMile) Collect(_ context.Context, target string) (LastMile, error) {
	f.lm.Target = target
	return f.lm, f.err
}

type fakeSession struct{ s Session }

func (f fakeSession) Collect(_ context.Context, target string) (Session, error) {
	f.s.Target = target
	return f.s, nil
}

func testConfig() *Config {
	c := Default()
	c.TenantID = "t1"
	c.AgentID = "laptop-1"
	c.Targets = []string{"https://app.example"}
	return c
}

// TestCollectOrchestration verifies the collector wires sub-collectors, derives
// the gateway from the trace, computes attribution, and applies privacy — the
// synthetic-WiFi-degradation case lands as a WiFi verdict, and the BSSID is
// dropped by default privacy.
func TestCollectOrchestration(t *testing.T) {
	wifi := fakeWiFi{w: WiFi{Present: true, Associated: true, SSID: "n", BSSID: "aa:bb:cc:dd:ee:ff", RSSIDBm: -84, Have: WiFiHave{RSSI: true}}}
	lm := fakeLastMile{lm: LastMile{Reached: true, Hops: []LastMileHop{
		{Index: 1, IP: "192.168.1.1", Private: true, RTTMs: 30},
		{Index: 2, IP: "203.0.113.1", Private: false, RTTMs: 95, LossPct: 0},
	}}}
	sess := fakeSession{s: Session{Success: true, TotalMs: 2200}}

	c := NewCollector(testConfig(), wifi, lm, sess)
	s := c.Collect(context.Background())

	if s.TenantID != "t1" || s.AgentID != "laptop-1" {
		t.Errorf("identity not stamped: %+v", s)
	}
	if s.Gateway.IP != "192.168.1.1" || s.Gateway.RTTMs != 30 {
		t.Errorf("gateway not derived from hop 1: %+v", s.Gateway)
	}
	if s.LastMile.ISPRTTMs != 95 { // classify ran
		t.Errorf("ISP RTT not classified: %+v", s.LastMile)
	}
	if s.Attribution.Cause != CauseWiFi {
		t.Errorf("weak WiFi should attribute to wifi, got %q", s.Attribution.Cause)
	}
	if s.WiFi.BSSID != "" {
		t.Errorf("default privacy should have dropped the BSSID, got %q", s.WiFi.BSSID)
	}
	if len(s.Sessions) != 1 || s.Sessions[0].Target != "https://app.example" {
		t.Errorf("session not collected per target: %+v", s.Sessions)
	}
}

func TestCollectDegradesOnCollectorError(t *testing.T) {
	c := NewCollector(testConfig(),
		fakeWiFi{err: errors.New("no wifi tool")},
		fakeLastMile{err: errors.New("traceroute missing")},
		fakeSession{s: Session{Success: true, TotalMs: 200}},
	)
	s := c.Collect(context.Background())
	if s.WiFi.Present {
		t.Errorf("a WiFi error should leave WiFi unavailable")
	}
	if len(s.LastMile.Hops) != 0 {
		t.Errorf("a trace error should leave the path empty")
	}
	if len(s.Sessions) != 1 { // the session still ran
		t.Errorf("the session should still be collected")
	}
	if s.Attribution.Cause != CauseNone { // healthy session, nothing impaired
		t.Errorf("cause = %q, want none", s.Attribution.Cause)
	}
}

func TestHTTPSessionCollector(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	sc := NewHTTPSessionCollector(0)
	got, err := sc.Collect(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if !got.Success || got.Status != 200 {
		t.Errorf("session = %+v, want success/200", got)
	}
	if got.Target != srv.URL {
		t.Errorf("target = %q", got.Target)
	}
}

func TestHTTPSessionCollectorBadTarget(t *testing.T) {
	sc := NewHTTPSessionCollector(0)
	got, err := sc.Collect(context.Background(), "http://127.0.0.1:1") // nothing listening
	if err != nil {
		t.Fatalf("a failed session is not a collector error: %v", err)
	}
	if got.Success || got.Error == "" {
		t.Errorf("expected a failed session with an error, got %+v", got)
	}
}

func TestCmdWiFiCollectorSeam(t *testing.T) {
	airport := "     agrCtlRSSI: -61\n        channel: 11\n             SSID: X\n          state: running"
	c := cmdWiFiCollector{
		run:   func(context.Context) (string, error) { return airport, nil },
		parse: parseAirportI,
	}
	w, err := c.Collect(context.Background())
	if err != nil || w.RSSIDBm != -61 || w.Channel != 11 {
		t.Fatalf("seam parse failed: %+v err=%v", w, err)
	}

	bad := cmdWiFiCollector{run: func(context.Context) (string, error) { return "", errors.New("x") }, parse: parseAirportI}
	if _, err := bad.Collect(context.Background()); err == nil {
		t.Errorf("a runner error should surface as unavailable")
	}
}

func TestCmdLastMileCollectorSeam(t *testing.T) {
	tr := " 1  192.168.1.1  1.0 ms  1.1 ms  1.2 ms\n 2  1.1.1.1  10 ms  10 ms  10 ms"
	c := cmdLastMileCollector{run: func(context.Context, string) (string, error) { return tr, nil }}
	lm, err := c.Collect(context.Background(), "1.1.1.1")
	if err != nil || len(lm.Hops) != 2 || lm.Target != "1.1.1.1" {
		t.Fatalf("seam parse failed: %+v err=%v", lm, err)
	}

	// A failed command with no parseable output is unavailable.
	bad := cmdLastMileCollector{run: func(context.Context, string) (string, error) { return "", errors.New("missing") }}
	if _, err := bad.Collect(context.Background(), "x"); err == nil {
		t.Errorf("empty output + error should be unavailable")
	}
}

// DPR-061: targets are URLs; the path trace needs the host. The URL used to be
// handed to traceroute verbatim ("Name does not resolve"), so the documented
// default configuration never traced anything.
func TestTraceHostReducesTargetsToTheHost(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"https://1.1.1.1", "1.1.1.1"},
		{"https://www.google.com/", "www.google.com"},
		{"http://app.example:8443/health", "app.example"},
		{"https://[2606:4700:4700::1111]/", "2606:4700:4700::1111"},
		{"example.com:443", "example.com"},
		{"example.com", "example.com"},
		{" 9.9.9.9 ", "9.9.9.9"},
	} {
		if got := traceHost(tc.in); got != tc.want {
			t.Errorf("traceHost(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

type stubLastMile struct {
	out string
	err error
}

func (f stubLastMile) Collect(_ context.Context, target string) (LastMile, error) {
	if f.err != nil {
		return LastMile{Target: target}, f.err
	}
	hops, reached := parseTraceHops(f.out)
	return LastMile{Target: target, Hops: hops, Reached: reached}, nil
}

// DPR-061: a sample that could not measure a layer says so, and the verdict
// over the measured layers is reported at reduced confidence instead of
// "no impairment, confidence 1.0".
func TestCollectRecordsUnavailableSignalsAndVerdictCoverage(t *testing.T) {
	cfg := Default()
	cfg.TenantID, cfg.AgentID = "t1", "dev-1"
	cfg.Targets = []string{"https://1.1.1.1"}
	sess := sessionFunc(func(context.Context, string) (Session, error) {
		return Session{Target: "https://1.1.1.1", Success: true, Status: 200, TotalMs: 90}, nil
	})

	t.Run("trace failed entirely", func(t *testing.T) {
		c := NewCollector(cfg, nil, stubLastMile{err: errors.New("traceroute: exit status 2")}, sess)
		s := c.Collect(context.Background())
		if len(s.Unavailable) != 1 || !strings.HasPrefix(s.Unavailable[0], "last_mile: traceroute") {
			t.Fatalf("unavailable = %v", s.Unavailable)
		}
		a := s.Attribution
		if a.Cause != CauseNone || a.Confidence != UnmeasuredLayerConfidence || strings.Join(a.Unmeasured, ",") != "local,isp" {
			t.Fatalf("attribution = %+v", a)
		}
		if !strings.Contains(a.Summary, "unmeasured: local, isp") {
			t.Fatalf("summary = %q", a.Summary)
		}
		if got := s.ToResults()[0].Attributes["endpoint.unmeasured"]; got != "local,isp" {
			t.Fatalf("bus attribute endpoint.unmeasured = %q", got)
		}
	})

	t.Run("trace answered on the LAN only", func(t *testing.T) {
		partial := "traceroute to 1.1.1.1 (1.1.1.1), 12 hops max\n 1  10.244.0.1  0.209 ms  0.201 ms\n 2  172.24.0.1  0.152 ms  0.160 ms\n 3  * *\n 4  * *\n"
		c := NewCollector(cfg, nil, stubLastMile{out: partial}, sess)
		s := c.Collect(context.Background())
		if s.Gateway.IP != "10.244.0.1" || !s.Gateway.Reachable {
			t.Fatalf("gateway not derived from the answering LAN hop: %+v", s.Gateway)
		}
		if strings.Join(s.Attribution.Unmeasured, ",") != "isp" || s.Attribution.Confidence != UnmeasuredLayerConfidence {
			t.Fatalf("attribution = %+v", s.Attribution)
		}
		if len(s.Unavailable) != 1 || !strings.HasPrefix(s.Unavailable[0], "isp_edge:") {
			t.Fatalf("unavailable = %v", s.Unavailable)
		}
	})

	t.Run("a public hop that answered with partial loss is a measured ISP edge", func(t *testing.T) {
		lossy := " 1  192.168.1.1  3.1 ms  2.9 ms\n 2  *  9.4 ms\n 3  203.0.113.9  18.0 ms  17.6 ms\n"
		c := NewCollector(cfg, nil, stubLastMile{out: lossy}, sess)
		s := c.Collect(context.Background())
		if s.LastMile.ISPRTTMs == 0 || s.LastMile.ISPLossPct != 0 || s.Attribution.Cause != CauseNone || s.Attribution.Confidence != 1 {
			t.Fatalf("lossy-but-answering path: last_mile=%+v attribution=%+v", s.LastMile, s.Attribution)
		}
		if s.LastMile.Hops[1].LossPct != 50 {
			t.Fatalf("hop 2 answered one of two probes, loss=%v", s.LastMile.Hops[1].LossPct)
		}
	})

	t.Run("every layer measured keeps full confidence", func(t *testing.T) {
		full := " 1  192.168.1.1  3.1 ms  2.9 ms\n 2  100.64.0.1  9.0 ms  9.4 ms\n 3  203.0.113.9  18.0 ms  17.6 ms\n 4  1.1.1.1  19.0 ms  19.2 ms\n"
		c := NewCollector(cfg, nil, stubLastMile{out: full}, sess)
		s := c.Collect(context.Background())
		if len(s.Unavailable) != 0 || s.Attribution.Confidence != 1 || len(s.Attribution.Unmeasured) != 0 {
			t.Fatalf("fully measured sample = unavailable %v attribution %+v", s.Unavailable, s.Attribution)
		}
	})
}

type sessionFunc func(context.Context, string) (Session, error)

func (f sessionFunc) Collect(ctx context.Context, target string) (Session, error) {
	return f(ctx, target)
}

// DPR-063: each sample dials afresh so DNS/connect/TLS are measured every
// interval instead of reading 0 on a kept-alive connection.
func TestHTTPSessionCollectorDialsFreshPerSample(t *testing.T) {
	var newConns atomic.Int32
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	srv.Config.ConnState = func(_ net.Conn, st http.ConnState) {
		if st == http.StateNew {
			newConns.Add(1)
		}
	}
	srv.Start()
	defer srv.Close()

	sc := NewHTTPSessionCollector(0)
	for i := 0; i < 3; i++ {
		if _, err := sc.Collect(context.Background(), srv.URL); err != nil {
			t.Fatalf("collect %d: %v", i, err)
		}
	}
	if got := newConns.Load(); got != 3 {
		t.Fatalf("new connections = %d, want 3 (one per sample)", got)
	}
}
