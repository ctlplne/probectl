// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package endpoint

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
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
