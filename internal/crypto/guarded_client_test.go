// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package crypto

import (
	"bufio"
	"context"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/http/httpproxy"
)

// GuardedHTTPClient must refuse a connection whose resolved address is in a
// reserved range (loopback/link-local/metadata/private) BEFORE the socket is
// opened — the SSRF guard that protects tenant-controlled egress (webhooks).
func TestGuardedHTTPClientBlocksReservedDestinationsPreConnect(t *testing.T) {
	// A real loopback listener: if the guard worked, it never accepts.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	var accepted atomic.Bool
	go func() {
		if c, err := ln.Accept(); err == nil {
			accepted.Store(true)
			c.Close()
		}
	}()

	c := GuardedHTTPClient(3 * time.Second)
	for _, url := range []string{
		"https://" + ln.Addr().String(), // loopback (real listener)
		"https://169.254.169.254/",      // cloud metadata (link-local)
		"https://10.0.0.1/",             // RFC1918
		"https://[::1]/",                // IPv6 loopback
		"http://127.0.0.1:1/",           // this-network / loopback
	} {
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
		resp, err := c.Do(req)
		if err == nil {
			resp.Body.Close()
			t.Fatalf("request to %s was not blocked", url)
		}
	}
	time.Sleep(50 * time.Millisecond)
	if accepted.Load() {
		t.Fatal("the guarded dialer opened a socket to the loopback listener")
	}
}

// TestGuardedHTTPClientDialsTheOperatorsEgressProxy is the DPR-289 regression:
// an egress proxy almost always sits on a private or loopback address, and the
// SSRF guard refused that dial, so a guarded client (alert webhooks, OIDC
// discovery) with HTTPS_PROXY set could reach nothing. The operator's proxy is
// now dialed without the guard; every other dial stays guarded.
func TestGuardedHTTPClientDialsTheOperatorsEgressProxy(t *testing.T) {
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	}))
	defer target.Close()
	proxy, tunnels := connectProxy(t, target.Listener.Addr().String())
	pool := x509.NewCertPool()
	pool.AddCert(target.Certificate())

	client := func(exempt map[string]bool) *http.Client {
		tlsCfg := hardenedTLS()
		tlsCfg.RootCAs = pool
		c := guardedHTTPClient(3*time.Second, tlsCfg, exempt, publicResolver)
		c.Transport.(*http.Transport).Proxy = guardedProxy(http.ProxyURL(&url.URL{Scheme: "http", Host: proxy}), publicResolver)
		return c
	}
	post := func(c *http.Client) error {
		resp, err := c.Post("https://example.com/hook", "application/json", strings.NewReader("{}"))
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusAccepted {
			return fmt.Errorf("status %d", resp.StatusCode)
		}
		return nil
	}

	if err := post(client(map[string]bool{})); err == nil {
		t.Fatal("a loopback proxy that is not the operator's configured proxy was dialed past the SSRF guard")
	}
	if n := tunnels.Load(); n != 0 {
		t.Fatalf("the guard let %d CONNECTs reach an unconfigured proxy", n)
	}
	if err := post(client(envProxyAddrs(&httpproxy.Config{HTTPSProxy: proxy}))); err != nil {
		t.Fatalf("delivery through the operator's loopback egress proxy failed: %v", err)
	}
	if n := tunnels.Load(); n != 1 {
		t.Fatalf("the proxy carried %d tunnels, want 1", n)
	}
}

func TestEnvProxyAddrsCanonicalizesLikeTheTransport(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  httpproxy.Config
		want []string
	}{
		{"none", httpproxy.Config{}, nil},
		{"bare host:port", httpproxy.Config{HTTPSProxy: "127.0.0.1:3128"}, []string{"127.0.0.1:3128"}},
		{"http default port", httpproxy.Config{HTTPProxy: "http://proxy.corp"}, []string{"proxy.corp:80"}},
		{"https explicit port", httpproxy.Config{HTTPSProxy: "https://proxy.corp:8443"}, []string{"proxy.corp:8443"}},
		{"socks5 ipv6", httpproxy.Config{HTTPSProxy: "socks5://[::1]"}, []string{"[::1]:1080"}},
		{"both", httpproxy.Config{HTTPProxy: "10.0.0.5:3128", HTTPSProxy: "10.0.0.6:3129"}, []string{"10.0.0.5:3128", "10.0.0.6:3129"}},
		{"unknown scheme without port adds nothing", httpproxy.Config{HTTPSProxy: "gopher://proxy.corp"}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := envProxyAddrs(&tc.cfg)
			if len(got) != len(tc.want) {
				t.Fatalf("envProxyAddrs = %v, want %v", got, tc.want)
			}
			for _, w := range tc.want {
				if !got[w] {
					t.Fatalf("envProxyAddrs = %v, missing %s", got, w)
				}
			}
		})
	}
}

// connectProxy is a loopback HTTP CONNECT proxy that tunnels every request to
// upstream, counting the tunnels it opened.
func connectProxy(t *testing.T, upstream string) (string, *atomic.Int64) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	var tunnels atomic.Int64
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				req, err := http.ReadRequest(bufio.NewReader(conn))
				if err != nil || req.Method != http.MethodConnect {
					return
				}
				up, err := net.Dial("tcp", upstream)
				if err != nil {
					_, _ = io.WriteString(conn, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
					return
				}
				defer up.Close()
				tunnels.Add(1)
				_, _ = io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")
				go func() { _, _ = io.Copy(up, conn) }()
				_, _ = io.Copy(conn, up)
			}()
		}
	}()
	return ln.Addr().String(), &tunnels
}

// fixedResolver answers LookupNetIP from a table, so proxied-destination tests
// never touch real DNS.
type fixedResolver map[string][]netip.Addr

func (f fixedResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	if a, ok := f[host]; ok {
		return a, nil
	}
	return nil, fmt.Errorf("no such host %q", host)
}

var publicResolver = fixedResolver{
	"example.com":         {netip.MustParseAddr("93.184.215.14")},
	"internal.corp.test":  {netip.MustParseAddr("10.20.30.40")},
	"rebind.example.test": {netip.MustParseAddr("93.184.215.14"), netip.MustParseAddr("169.254.169.254")},
}

// DPR-292: through the operator's proxy the transport dials only the proxy,
// so the dial-time guard never sees the destination. A proxied request whose
// host is, or resolves (in any answer) to, a reserved address must fail
// before the proxy is asked to open it; a public destination still goes.
func TestGuardedProxyRefusesReservedDestinations(t *testing.T) {
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	}))
	defer target.Close()
	proxy, tunnels := connectProxy(t, target.Listener.Addr().String())
	pool := x509.NewCertPool()
	pool.AddCert(target.Certificate())
	tlsCfg := hardenedTLS()
	tlsCfg.RootCAs = pool
	c := guardedHTTPClient(3*time.Second, tlsCfg, envProxyAddrs(&httpproxy.Config{HTTPSProxy: proxy}), publicResolver)
	c.Transport.(*http.Transport).Proxy = guardedProxy(http.ProxyURL(&url.URL{Scheme: "http", Host: proxy}), publicResolver)

	for _, dest := range []string{
		"https://127.0.0.1:8443/hook",
		"https://[::1]/hook",
		"https://169.254.169.254/latest/meta-data",
		"https://internal.corp.test/hook",
		"https://rebind.example.test/hook",
	} {
		resp, err := c.Post(dest, "application/json", strings.NewReader("{}"))
		if err == nil {
			_ = resp.Body.Close()
			t.Fatalf("proxied request to %s was sent; want it refused before the proxy", dest)
		}
	}
	if n := tunnels.Load(); n != 0 {
		t.Fatalf("the proxy opened %d tunnels for reserved destinations", n)
	}
	// A public name, and a name only the proxy can resolve (egress networks
	// often have no local DNS for outside names), both go to the proxy.
	for _, dest := range []string{"https://example.com/hook", "https://only-the-proxy-resolves.example.com/hook"} {
		resp, err := c.Post(dest, "application/json", strings.NewReader("{}"))
		if err != nil {
			t.Fatalf("%s through the proxy failed: %v", dest, err)
		}
		_ = resp.Body.Close()
	}
	if n := tunnels.Load(); n != 2 {
		t.Fatalf("the proxy carried %d tunnels, want 2", n)
	}
}
