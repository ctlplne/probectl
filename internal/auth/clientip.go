// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package auth

import (
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// ClientIP returns the address the authentication limiters should key on
// (DPR-039). With no trusted proxies it is the transport peer, exactly as
// before: forwarded headers from an arbitrary peer are spoofable and are
// ignored. When the peer IS one of the operator-declared trusted proxies
// (PROBECTL_TRUSTED_PROXIES — the ingress controller, a load balancer), the
// nearest untrusted hop of X-Forwarded-For is the client; X-Real-IP is the
// fallback when the proxy sets only that. Without this, every user behind the
// shipped ingress shared one limiter key — the ingress pod's IP — so five
// failed logins by anyone locked out SSO for the whole deployment, and the
// per-IP dimension never slowed a real attacker down.
func ClientIP(remoteAddr string, header http.Header, trusted []netip.Prefix) string {
	peer := peerAddr(remoteAddr)
	if len(trusted) == 0 || !isTrusted(peer, trusted) {
		return peer.String()
	}
	// Walk X-Forwarded-For right to left: the rightmost hop was appended by
	// the trusted proxy we are talking to, hops before it may have been
	// appended by other trusted proxies, and the first untrusted address is
	// the client. Anything a client put in the header itself sits further
	// left and is never reached while a trusted proxy stands in between.
	var hops []string
	for _, h := range header.Values("X-Forwarded-For") {
		for _, part := range strings.Split(h, ",") {
			if part = strings.TrimSpace(part); part != "" {
				hops = append(hops, part)
			}
		}
	}
	for i := len(hops) - 1; i >= 0; i-- {
		addr, ok := parseForwarded(hops[i])
		if !ok {
			// A malformed hop ends the walk: never key on garbage a client
			// could vary at will.
			break
		}
		if !isTrusted(addr, trusted) {
			return addr.String()
		}
	}
	if realIP := strings.TrimSpace(header.Get("X-Real-IP")); realIP != "" {
		if addr, ok := parseForwarded(realIP); ok && !isTrusted(addr, trusted) {
			return addr.String()
		}
	}
	// Every hop was a trusted proxy (or nothing was forwarded): the request
	// really did originate inside the trusted set.
	return peer.String()
}

// ParseTrustedProxies turns the comma-separated PROBECTL_TRUSTED_PROXIES value
// (CIDRs or single addresses) into prefixes, rejecting anything unparseable
// so a typo cannot silently turn the guard off or on.
func ParseTrustedProxies(entries []string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(entries))
	for _, raw := range entries {
		e := strings.TrimSpace(raw)
		if e == "" {
			continue
		}
		if p, err := netip.ParsePrefix(e); err == nil {
			out = append(out, p.Masked())
			continue
		}
		a, err := netip.ParseAddr(e)
		if err != nil {
			return nil, err
		}
		out = append(out, netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen()))
	}
	return out, nil
}

func peerAddr(remoteAddr string) netip.Addr {
	host := remoteAddr
	if h, _, err := net.SplitHostPort(remoteAddr); err == nil {
		host = h
	}
	if a, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil {
		return a.Unmap()
	}
	return netip.Addr{}
}

func parseForwarded(hop string) (netip.Addr, bool) {
	hop = strings.Trim(hop, "\"")
	if h, _, err := net.SplitHostPort(hop); err == nil {
		hop = h
	}
	a, err := netip.ParseAddr(strings.Trim(hop, "[]"))
	if err != nil {
		return netip.Addr{}, false
	}
	return a.Unmap(), true
}

func isTrusted(a netip.Addr, trusted []netip.Prefix) bool {
	if !a.IsValid() {
		return false
	}
	for _, p := range trusted {
		if p.Contains(a) {
			return true
		}
	}
	return false
}
