// SPDX-License-Identifier: LicenseRef-probectl-TBD

package canary

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
)

// U-002: the denylist catches every internal/metadata class, v4 and v6,
// including the IPv4-mapped smuggle.
func TestTargetGuardDeniesInternalClasses(t *testing.T) {
	g := NewTargetGuard(false)
	// One row per blocked RANGE (SEC-007 table): boundary + interior addresses.
	denied := []struct{ ip, class string }{
		{"127.0.0.1", "loopback"}, {"127.8.8.8", "loopback"}, {"127.255.255.255", "loopback"},
		{"10.0.0.1", "rfc1918"}, {"10.255.255.255", "rfc1918"},
		{"172.16.0.1", "rfc1918"}, {"172.31.255.255", "rfc1918"},
		{"192.168.1.1", "rfc1918"}, {"192.168.255.255", "rfc1918"},
		{"169.254.169.254", "link-local/metadata"}, {"169.254.0.1", "link-local"}, {"169.254.255.255", "link-local"},
		{"100.64.0.1", "cgnat"}, {"100.127.255.255", "cgnat"},
		{"0.0.0.0", "unspecified"},
		// SEC-007: the WHOLE 0.0.0.0/8 block (Linux routes 0.x.y.z to
		// localhost), not just the exact unspecified address.
		{"0.0.0.1", "this-network"}, {"0.1.2.3", "this-network"}, {"0.255.255.255", "this-network"},
		{"255.255.255.255", "broadcast"}, {"224.0.0.1", "multicast"}, {"239.255.255.255", "multicast"},
		{"::1", "v6 loopback"}, {"::", "v6 unspecified"},
		{"fe80::1", "v6 link-local"}, {"fc00::1", "ULA"}, {"fd12::1", "ULA"}, {"ff02::1", "v6 multicast"},
		{"::ffff:10.0.0.1", "v4-mapped rfc1918"}, {"::ffff:169.254.169.254", "v4-mapped metadata"},
		{"::ffff:0.1.2.3", "v4-mapped this-network"},
	}
	for _, tc := range denied {
		if err := g.CheckIP(netip.MustParseAddr(tc.ip)); err == nil {
			t.Errorf("CheckIP(%s) [%s]: want denied", tc.ip, tc.class)
		}
	}
	allowed := []string{"8.8.8.8", "1.1.1.1", "93.184.216.34", "2606:4700::1111"}
	for _, ip := range allowed {
		if err := g.CheckIP(netip.MustParseAddr(ip)); err != nil {
			t.Errorf("CheckIP(%s): want allowed, got %v", ip, err)
		}
	}
}

// Bypass encodings: decimal, hex, octal, short forms — rejected outright,
// never resolved.
func TestTargetGuardRejectsBypassEncodings(t *testing.T) {
	g := NewTargetGuard(false)
	bypasses := []string{
		"2130706433",       // decimal 127.0.0.1
		"0x7f000001",       // hex 127.0.0.1
		"0177.0.0.1",       // octal first label
		"0x7f.0.0.1",       // hex first label
		"127.1",            // short form
		"127.0.1",          // short form
		"025177524292",     // octal whole
		"[::ffff:7f00:1]",  // bracketed mapped literal
		"169.254.169.254.", // trailing-dot literal
		"0x7f.0x0.0x0.0x1", // all-hex labels
	}
	for _, host := range bypasses {
		if err := g.CheckHost(host); err == nil {
			t.Errorf("CheckHost(%q): want rejected", host)
		}
	}
	// Real hostnames pass construction (they are enforced at dial time).
	for _, host := range []string{"example.com", "api.internal-name.example.", "xn--nxasmq6b.example"} {
		if err := g.CheckHost(host); err != nil {
			t.Errorf("CheckHost(%q): want allowed at construction, got %v", host, err)
		}
	}
}

// DNS rebinding: a hostname passes construction, but the RESOLVED address is
// checked at the kernel handoff on every connection — a rebind to an internal
// IP is refused at dial time.
func TestTargetGuardDialControlBlocksRebind(t *testing.T) {
	g := NewTargetGuard(false)
	if err := g.CheckHost("rebind.example.com"); err != nil {
		t.Fatalf("hostname must pass construction: %v", err)
	}
	control := g.DialControl(nil)
	for _, addr := range []string{"169.254.169.254:80", "10.0.0.5:443", "[::1]:8443", "[fe80::1%eth0]:80"} {
		if err := control("tcp", addr, nil); err == nil {
			t.Errorf("DialControl(%s): want refused", addr)
		}
	}
	if err := control("tcp", "93.184.216.34:443", nil); err != nil {
		t.Fatalf("public dial refused: %v", err)
	}
}

// DialControl chains to the next Control (the DSCP marker keeps working) and
// never runs it for a denied address.
func TestTargetGuardDialControlChains(t *testing.T) {
	g := NewTargetGuard(false)
	called := false
	chained := g.DialControl(func(_, _ string, _ syscall.RawConn) error {
		called = true
		return nil
	})
	if err := chained("tcp", "8.8.8.8:53", nil); err != nil {
		t.Fatalf("chained allow: %v", err)
	}
	if !called {
		t.Fatal("next Control was not chained")
	}
	called = false
	if err := chained("tcp", "10.0.0.1:80", nil); err == nil {
		t.Fatal("denied address passed")
	}
	if called {
		t.Fatal("next Control ran for a denied address")
	}
}

// The audited override lifts every check.
func TestTargetGuardAllowPrivateOverride(t *testing.T) {
	g := GuardFromParams(map[string]string{AllowPrivateParam: "true"})
	for _, host := range []string{"127.0.0.1", "169.254.169.254", "2130706433", "10.0.0.1"} {
		if err := g.CheckHost(host); err != nil {
			t.Errorf("override CheckHost(%q): %v", host, err)
		}
	}
	if err := g.DialControl(nil)("tcp", "10.0.0.1:80", nil); err != nil {
		t.Errorf("override DialControl: %v", err)
	}
}

// Factory-level enforcement: literal internal targets never construct, and
// the error names the audited override knob.
func TestCanaryFactoriesEnforceGuard(t *testing.T) {
	cases := []struct {
		name string
		f    Factory
		cfg  Config
	}{
		{"tcp metadata", NewTCP, Config{Target: "169.254.169.254:80"}},
		{"udp rfc1918", NewUDP, Config{Target: "10.0.0.1:53"}},
		{"http loopback", NewHTTP, Config{Target: "http://127.0.0.1:8080/x"}},
		{"http decimal", NewHTTP, Config{Target: "http://2130706433/"}},
		{"icmp private", NewICMP, Config{Target: "192.168.1.1"}},
		{"voice private", NewVoice, Config{Target: "172.16.0.9:5004"}},
		{"dns private explicit server", NewDNS, Config{Target: "example.com", Params: map[string]string{"server": "10.0.0.53:53"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tc.f(tc.cfg)
			if err == nil {
				t.Fatal("factory accepted a denied target")
			}
			if !strings.Contains(err.Error(), AllowPrivateParam) && !strings.Contains(err.Error(), "denied") {
				t.Fatalf("error should explain the guard/override: %v", err)
			}
		})
	}

	// The audited override constructs the same canaries.
	allow := map[string]string{AllowPrivateParam: "true"}
	if _, err := NewTCP(Config{Target: "169.254.169.254:80", Params: allow}); err != nil {
		t.Fatalf("override tcp: %v", err)
	}
	if _, err := NewHTTP(Config{Target: "http://127.0.0.1:8080/x", Params: allow}); err != nil {
		t.Fatalf("override http: %v", err)
	}
	// The dns default (system resolver) stays exempt: no server param, no error.
	if _, err := NewDNS(Config{Target: "example.com"}); err != nil {
		t.Fatalf("dns default resolver must construct: %v", err)
	}
}

func TestHTTPCanaryRejectsDeniedTargetsBeforeAmbientProxy(t *testing.T) {
	var proxyHits atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		proxyHits.Add(1)
		http.Error(w, "proxy should not be reached", http.StatusBadGateway)
	}))
	defer proxy.Close()
	t.Setenv("HTTP_PROXY", proxy.URL)
	t.Setenv("HTTPS_PROXY", proxy.URL)
	t.Setenv("NO_PROXY", "")

	for _, target := range []string{
		"http://169.254.169.254/latest/meta-data", // link-local / cloud metadata
		"https://169.254.169.254/",
		"http://127.0.0.1:8080/admin", // loopback
		"http://10.0.0.7/",            // RFC1918
		"http://192.168.1.10/",        // RFC1918
	} {
		t.Run(target, func(t *testing.T) {
			_, err := NewHTTP(Config{Target: target})
			if err == nil {
				t.Fatal("factory accepted a denied HTTP target")
			}
			if !strings.Contains(err.Error(), "denied") {
				t.Fatalf("error should explain the SSRF guard, got %v", err)
			}
		})
	}
	if proxyHits.Load() != 0 {
		t.Fatalf("denied HTTP targets reached ambient proxy %d times", proxyHits.Load())
	}
}
