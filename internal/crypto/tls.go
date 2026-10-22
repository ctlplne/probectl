// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package crypto

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"syscall"
	"time"

	"golang.org/x/net/http/httpproxy"
)

// TLS policy (WIRE-005/WIRE-007), owned HERE so the rest of the codebase
// imports no crypto package directly:
//
//   - probectl↔probectl endpoints (API/OTLP/MCP servers, agent mTLS, the
//     enrollment client) use hardenedServerTLS: **TLS 1.3 floor** — both ends
//     are ours (or modern browsers), nothing older needs to connect.
//   - OUTBOUND probe/integration clients (canary HTTP/DNS, gNMI devices)
//     keep the 1.2 floor via hardenedTLS: they speak to THIRD-PARTY endpoints
//     the operator monitors, where a 1.3-only floor would break legitimate
//     targets. Certificate validation is always on.
//
// hardenedTLS returns the base config: TLS 1.2 minimum (1.3 negotiated when
// available), AEAD-only cipher suites for 1.2, and modern curve preferences.
func hardenedTLS() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		},
		CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256},
	}
}

// hardenedServerTLS is the policy for every probectl-OWNED listener and
// probectl↔probectl client: TLS 1.3 floor (WIRE-007). The 1.2 suite list is
// retained harmlessly (ignored at 1.3) so a deliberate future floor change
// stays AEAD-only without edits.
func hardenedServerTLS() *tls.Config {
	cfg := hardenedTLS()
	cfg.MinVersion = tls.VersionTLS13
	// SUP-13 / G7-4: disable TLS session resumption on every probectl server
	// listener. On a resumed handshake Go does NOT re-invoke VerifyPeerCertificate,
	// so the custom mTLS checks layered on top of it — SPIFFE trust-domain
	// pinning, the live issued-identity registry lookup, and CRL revocation —
	// would be silently skipped, letting a client whose identity was revoked
	// after its first handshake keep resuming. Forcing a full handshake every
	// time keeps those checks on the authentication path. (TLS 1.3, 1-RTT.)
	cfg.SessionTicketsDisabled = true
	return cfg
}

// ServerTLSConfig builds the hardened server TLS config from a cert/key pair
// (no client auth) — the ONE config every probectl HTTPS listener uses
// (API, OTLP, MCP; WIRE-005): TLS 1.3 floor.
func ServerTLSConfig(certFile, keyFile string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("crypto: load server keypair: %w", err)
	}
	cfg := hardenedServerTLS()
	cfg.Certificates = []tls.Certificate{cert}
	return cfg, nil
}

// ConfigureServerTLS sets a hardened TLS config (with the loaded keypair) on srv,
// so callers serve HTTPS via srv.ListenAndServeTLS("", "") without importing any
// crypto package. Returns an error if the keypair cannot be loaded.
func ConfigureServerTLS(srv *http.Server, certFile, keyFile string) error {
	cfg, err := ServerTLSConfig(certFile, keyFile)
	if err != nil {
		return err
	}
	srv.TLSConfig = cfg
	return nil
}

// HardenedClientTLSConfig returns a hardened *tls.Config for OUTBOUND client
// connections (TLS 1.2+, modern ciphers/curves). Certificate validation is ALWAYS
// on — InsecureSkipVerify is never set (docs/guardrails.md G7-12). Used for
// remote model endpoints and any other outbound fetch that needs the policy.
func HardenedClientTLSConfig() *tls.Config { return hardenedTLS() }

// HardenedClientTLSConfigWithCAFile returns the shared outbound-client policy
// with an operator-supplied PEM trust bundle. A non-empty file replaces the
// system roots, matching the usual "ca_file" contract for managed appliances.
// Keeping both policy and trust-store construction here prevents gNMI and other
// third-party integrations from drifting outside the FIPS-swappable seam.
func HardenedClientTLSConfigWithCAFile(caFile string) (*tls.Config, error) {
	cfg := hardenedTLS()
	if strings.TrimSpace(caFile) == "" {
		return cfg, nil
	}
	pemBytes, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("crypto: read client CA file: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		return nil, fmt.Errorf("crypto: client CA file contains no certificates")
	}
	cfg.RootCAs = pool
	return cfg, nil
}

// InternalClientTLSConfig is the client policy for probectl↔probectl calls
// (the enrollment/rotation client): TLS 1.3 floor — the server is ours
// (WIRE-007). Validation is always on; callers may add a pin or RootCAs.
func InternalClientTLSConfig() *tls.Config { return hardenedServerTLS() }

// HardenedHTTPClient returns an *http.Client whose transport validates server
// certificates with the hardened TLS policy. timeout bounds the entire request
// (a non-positive value leaves it unbounded — callers should pass a positive
// timeout). Redirects are re-checked here so shared outbound clients do not
// leak credentials or follow a public feed into private/metadata space. The
// only crypto policy routes through internal/crypto, so callers import no crypto
// package directly.
func HardenedHTTPClient(timeout time.Duration) *http.Client {
	return hardenedHTTPClient(timeout, hardenedTLS())
}

// HardenedHTTPClientWithCAFile is HardenedHTTPClient whose server-certificate
// validation is anchored on an operator-supplied PEM trust bundle instead of the
// system roots — the same "ca_file" contract as HardenedClientTLSConfigWithCAFile,
// for outbound integrations that sit behind a private CA (an enterprise LLM
// gateway, an internal vLLM). An empty caFile yields exactly HardenedHTTPClient.
// Certificate validation is never disabled; a bundle with no certificates fails.
func HardenedHTTPClientWithCAFile(timeout time.Duration, caFile string) (*http.Client, error) {
	tlsCfg, err := HardenedClientTLSConfigWithCAFile(caFile)
	if err != nil {
		return nil, err
	}
	return hardenedHTTPClient(timeout, tlsCfg), nil
}

func hardenedHTTPClient(timeout time.Duration, tlsCfg *tls.Config) *http.Client {
	return &http.Client{
		Timeout:       timeout,
		CheckRedirect: hardenedHTTPRedirectPolicy,
		Transport: &http.Transport{
			// PLAT-07: honor HTTPS_PROXY/HTTP_PROXY/NO_PROXY so outbound
			// integrations (SIEM, on-call/ITSM, AI, secret managers, S3, CMDB,
			// feeds) can traverse a mandatory egress proxy. With no proxy env set
			// (the default) this is a no-op and the dialer behaves as before.
			Proxy:               http.ProxyFromEnvironment,
			TLSClientConfig:     tlsCfg,
			ForceAttemptHTTP2:   true,
			MaxIdleConns:        10,
			IdleConnTimeout:     90 * time.Second,
			TLSHandshakeTimeout: 10 * time.Second,
		},
	}
}

// StreamingHTTPClientFrom returns an HTTP client for a long-lived streaming read
// (e.g. a large tenant export) that must NOT be bounded by an overall request
// deadline — http.Client.Timeout caps the entire request including the body
// read, which would abort a large but healthy stream mid-flight. It drops that
// overall deadline while preserving the source client's hardened transport and
// redirect policy (TLS-handshake + idle-conn timeouts still bound a stalled
// peer; cancellation rides the caller's context). A nil source yields a
// hardened client with no overall cap. The bare client literal lives here, in
// the approved constructor (U-036), so callers never hand-roll one.
func StreamingHTTPClientFrom(src *http.Client) *http.Client {
	if src == nil {
		return HardenedHTTPClient(0)
	}
	return &http.Client{Transport: src.Transport, CheckRedirect: src.CheckRedirect, Jar: src.Jar}
}

const hardenedHTTPMaxRedirects = 5

func hardenedHTTPRedirectPolicy(req *http.Request, via []*http.Request) error {
	if len(via) >= hardenedHTTPMaxRedirects {
		return fmt.Errorf("crypto: redirect rejected after %d hops", hardenedHTTPMaxRedirects)
	}
	if req == nil || req.URL == nil {
		return fmt.Errorf("crypto: redirect rejected: missing target URL")
	}
	if err := checkRedirectURL(req.URL); err != nil {
		return err
	}
	if len(via) == 0 {
		return nil
	}
	prev := via[len(via)-1]
	if prev != nil && prev.URL != nil && prev.URL.Scheme == "https" && req.URL.Scheme != "https" {
		return fmt.Errorf("crypto: redirect rejected: HTTPS-to-%s scheme downgrade", req.URL.Scheme)
	}
	if prev != nil && prev.URL != nil && !sameOrigin(prev.URL, req.URL) && redirectCarriesCredentialHeaders(via) {
		return fmt.Errorf("crypto: redirect rejected: credential-bearing request crossed origin from %s to %s", origin(prev.URL), origin(req.URL))
	}
	return nil
}

func checkRedirectURL(u *url.URL) error {
	scheme := strings.ToLower(u.Scheme)
	if scheme != "https" && scheme != "http" {
		return fmt.Errorf("crypto: redirect rejected: unsupported target scheme %q", u.Scheme)
	}
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	if host == "" {
		return fmt.Errorf("crypto: redirect rejected: empty target host")
	}
	if host == "localhost" || redirectMetadataHost(host) {
		return fmt.Errorf("crypto: redirect rejected: private/link-local target %q", host)
	}
	addr, err := netip.ParseAddr(strings.Trim(host, "[]"))
	if err != nil {
		return nil
	}
	addr = addr.Unmap()
	switch {
	case !addr.IsValid(),
		addr.IsLoopback(),
		addr.IsLinkLocalUnicast(),
		addr.IsLinkLocalMulticast(),
		addr.IsMulticast(),
		addr.IsPrivate(),
		addr.IsUnspecified(),
		addr.Is4() && redirectCGNAT.Contains(addr),
		addr.Is4() && redirectZeroNet.Contains(addr),
		addr.Is4() && addr == netip.AddrFrom4([4]byte{255, 255, 255, 255}):
		return fmt.Errorf("crypto: redirect rejected: private/link-local target %s", addr)
	}
	return nil
}

// reservedAddr returns a non-nil error when addr is in a loopback, link-local
// (incl. 169.254.169.254 cloud metadata), multicast, private (RFC1918/ULA),
// unspecified, CGNAT, this-network (0.0.0.0/8) or broadcast range — the ranges
// a request to a caller-supplied destination must never reach (SSRF guard).
func reservedAddr(addr netip.Addr) error {
	addr = addr.Unmap()
	switch {
	case !addr.IsValid(),
		addr.IsLoopback(),
		addr.IsLinkLocalUnicast(),
		addr.IsLinkLocalMulticast(),
		addr.IsMulticast(),
		addr.IsPrivate(),
		addr.IsUnspecified(),
		addr.Is4() && redirectCGNAT.Contains(addr),
		addr.Is4() && redirectZeroNet.Contains(addr),
		addr.Is4() && addr == netip.AddrFrom4([4]byte{255, 255, 255, 255}):
		return fmt.Errorf("destination %s is a private/link-local/reserved address", addr)
	}
	return nil
}

// GuardedHTTPClient is HardenedHTTPClient plus an SSRF egress guard: the dialer
// rejects a connection whose RESOLVED address is loopback/link-local/metadata/
// private/CGNAT/this-net/broadcast BEFORE the socket opens, so a hostname that
// resolves (or DNS-rebinds) into those ranges cannot be reached. Redirects are
// re-checked by the hardened policy. Use it for requests to destinations a
// tenant or other untrusted caller controls (webhooks, notification channels).
func GuardedHTTPClient(timeout time.Duration) *http.Client {
	return guardedHTTPClient(timeout, hardenedTLS(), envProxyAddrs(httpproxy.FromEnvironment()), net.DefaultResolver)
}

// GuardedHTTPClientWithCAFile is GuardedHTTPClient whose server-certificate
// validation is anchored on an operator-supplied PEM trust bundle instead of
// the system roots — the same "ca_file" contract as
// HardenedClientTLSConfigWithCAFile, for tenant-directed deliveries that cross
// a TLS-inspecting egress proxy or reach receivers behind an enterprise CA. An
// empty caFile yields exactly GuardedHTTPClient. The SSRF guard is unchanged
// and certificate validation is never disabled.
func GuardedHTTPClientWithCAFile(timeout time.Duration, caFile string) (*http.Client, error) {
	tlsCfg, err := HardenedClientTLSConfigWithCAFile(caFile)
	if err != nil {
		return nil, err
	}
	return guardedHTTPClient(timeout, tlsCfg, envProxyAddrs(httpproxy.FromEnvironment()), net.DefaultResolver), nil
}

// guardedHTTPClient builds the SSRF-guarded client. proxyAddrs are the
// operator's configured egress proxies (host:port exactly as the transport
// dials them): those dials are the operator's own infrastructure, not a
// caller-supplied destination, so they skip the reserved-range check. Every
// other dial is guarded.
//
// DPR-289: an egress proxy almost always sits on a private or loopback address
// (a corporate Squid on 10.x, a sidecar on 127.0.0.1). The guard refused that
// dial, so a guarded client with HTTPS_PROXY set could reach nothing at all:
// PLAT-07 held for the hardened clients but not for webhook delivery or OIDC
// discovery.
func guardedHTTPClient(timeout time.Duration, tlsCfg *tls.Config, proxyAddrs map[string]bool, res destinationResolver) *http.Client {
	direct := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	guarded := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
		Control: func(_, address string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				host = address
			}
			a, err := netip.ParseAddr(strings.Trim(host, "[]"))
			if err != nil {
				return fmt.Errorf("crypto: unparseable dial address %q", address)
			}
			return reservedAddr(a)
		},
	}
	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		if proxyAddrs[address] {
			return direct.DialContext(ctx, network, address)
		}
		return guarded.DialContext(ctx, network, address)
	}
	return &http.Client{
		Timeout:       timeout,
		CheckRedirect: hardenedHTTPRedirectPolicy,
		Transport: &http.Transport{
			DialContext: dial,
			// PLAT-07: honor a configured egress proxy. When no proxy is set (the
			// default) this is a no-op and the dial-time SSRF guard above runs on
			// the real target. When a proxy is set, the transport dials only the
			// proxy, so guardedProxy checks the destination itself first (DPR-292).
			Proxy:               guardedProxy(guardedProxySource, res),
			TLSClientConfig:     tlsCfg,
			ForceAttemptHTTP2:   true,
			MaxIdleConns:        10,
			IdleConnTimeout:     90 * time.Second,
			TLSHandshakeTimeout: 10 * time.Second,
		},
	}
}

// guardedProxySource is the proxy selection the guarded transport wraps: the
// environment (HTTPS_PROXY/HTTP_PROXY/NO_PROXY), as for the hardened client
// (PLAT-07). A package variable so TestHardenedClientsHonorProxyEnv can assert
// it structurally.
var guardedProxySource = http.ProxyFromEnvironment

// destinationResolver is the lookup guardedProxy uses (net.Resolver in
// production; a fixed table in tests).
type destinationResolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// guardedProxy wraps the transport's proxy selection so a proxied request is
// still SSRF-checked. Through a proxy the transport dials only the proxy and
// the proxy opens the destination, so the dial-time guard never sees the
// tenant-supplied host. Before a request is handed to a proxy, its host
// (a literal IP, or every address the name resolves to here) must clear the
// same reserved-range check; otherwise the request fails closed. A name that
// does not resolve here is left to the proxy (PLAT-07). Direct requests
// (no proxy) are left to the dial-time guard. DPR-292: DPR-289 made proxied
// delivery work, which without this would have let a webhook reach an internal
// address through the operator's proxy.
func guardedProxy(proxy func(*http.Request) (*url.URL, error), res destinationResolver) func(*http.Request) (*url.URL, error) {
	return func(req *http.Request) (*url.URL, error) {
		u, err := proxy(req)
		if err != nil || u == nil {
			return u, err
		}
		host := strings.Trim(req.URL.Hostname(), "[]")
		if a, perr := netip.ParseAddr(host); perr == nil {
			if rerr := reservedAddr(a); rerr != nil {
				return nil, rerr
			}
			return u, nil
		}
		addrs, lerr := res.LookupNetIP(req.Context(), "ip", host)
		if lerr != nil {
			// A name this host cannot resolve is the proxy's to resolve: egress
			// networks often have no local DNS for outside names, and a name that
			// does not resolve here cannot be one of this host's internal names.
			// Its policy is the proxy's (PLAT-07).
			return u, nil
		}
		for _, a := range addrs {
			if rerr := reservedAddr(a); rerr != nil {
				return nil, rerr
			}
		}
		return u, nil
	}
}

// envProxyAddrs is the set of egress-proxy addresses the transport will dial
// for cfg (HTTP_PROXY / HTTPS_PROXY), canonicalized the way net/http does: a
// proxy without a scheme is http://, and a missing port takes the scheme's
// default. A value that does not parse adds nothing, so its dial stays guarded
// (fail closed).
func envProxyAddrs(cfg *httpproxy.Config) map[string]bool {
	out := map[string]bool{}
	if cfg == nil {
		return out
	}
	for _, raw := range []string{cfg.HTTPProxy, cfg.HTTPSProxy} {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		u, err := url.Parse(raw)
		if err != nil || u.Scheme == "" || u.Host == "" {
			if u, err = url.Parse("http://" + raw); err != nil {
				continue
			}
		}
		host := u.Hostname()
		if host == "" {
			continue
		}
		port := u.Port()
		if port == "" {
			port = map[string]string{"http": "80", "https": "443", "socks5": "1080", "socks5h": "1080"}[strings.ToLower(u.Scheme)]
		}
		if port == "" {
			continue
		}
		out[net.JoinHostPort(host, port)] = true
	}
	return out
}

func redirectMetadataHost(host string) bool {
	switch host {
	case "metadata", "metadata.google.internal", "metadata.google.internal.":
		return true
	default:
		return false
	}
}

var (
	redirectCGNAT   = netip.MustParsePrefix("100.64.0.0/10")
	redirectZeroNet = netip.MustParsePrefix("0.0.0.0/8")
)

func redirectCarriesCredentialHeaders(via []*http.Request) bool {
	for _, r := range via {
		if r == nil {
			continue
		}
		for name := range r.Header {
			if redirectCredentialHeader(name) {
				return true
			}
		}
	}
	return false
}

func redirectCredentialHeader(name string) bool {
	canonical := http.CanonicalHeaderKey(name)
	lower := strings.ToLower(canonical)
	switch lower {
	case "authorization", "cookie", "proxy-authorization", "x-vault-token":
		return true
	}
	if strings.HasPrefix(lower, "x-") {
		return true
	}
	return strings.Contains(lower, "token") ||
		strings.Contains(lower, "secret") ||
		strings.Contains(lower, "credential") ||
		strings.Contains(lower, "api-key") ||
		strings.Contains(lower, "auth")
}

func sameOrigin(a, b *url.URL) bool {
	return origin(a) == origin(b)
}

func origin(u *url.URL) string {
	if u == nil {
		return ""
	}
	scheme := strings.ToLower(u.Scheme)
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	port := u.Port()
	if port == "" {
		switch scheme {
		case "https":
			port = "443"
		case "http":
			port = "80"
		}
	}
	return scheme + "://" + host + ":" + port
}
