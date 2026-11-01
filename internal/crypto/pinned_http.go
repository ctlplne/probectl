// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package crypto

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// PinnedHTTPSClient is the outbound transport for an operator-approved source
// origin. It preserves the origin hostname for TLS validation while resolving
// and checking every address immediately before dialing its numeric IP. A
// proxy, redirect, alternate host or DNS answer outside the explicit deployment
// CIDRs cannot turn a tenant-controlled source into general network egress.
// The caller must resolve the tenant-owned source record before constructing
// this client and supply a positive whole-request timeout.
func PinnedHTTPSClient(origin string, allowed []netip.Prefix, caFile string,
	timeout time.Duration) (*http.Client, error) {
	host, port, err := pinnedOrigin(origin)
	if err != nil || timeout <= 0 || len(allowed) == 0 {
		return nil, errors.New("crypto: pinned HTTPS origin or egress policy invalid")
	}
	for _, prefix := range allowed {
		if !prefix.IsValid() || prefix.Addr().Zone() != "" {
			return nil, errors.New("crypto: pinned HTTPS egress CIDR invalid")
		}
	}
	client, err := HardenedHTTPClientWithCAFile(timeout, caFile)
	if err != nil {
		return nil, err
	}
	approved := append([]netip.Prefix(nil), allowed...)
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	transport := client.Transport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.ForceAttemptHTTP2 = true
	transport.DisableKeepAlives = true
	transport.ResponseHeaderTimeout = 15 * time.Second
	transport.TLSHandshakeTimeout = 10 * time.Second
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		dialHost, dialPort, err := net.SplitHostPort(address)
		if err != nil || !strings.EqualFold(dialHost, host) || dialPort != port ||
			(network != "tcp" && network != "tcp4" && network != "tcp6") {
			return nil, errors.New("crypto: pinned HTTPS origin mismatch")
		}
		addresses, err := pinnedAddresses(ctx, host, approved)
		if err != nil {
			return nil, err
		}
		return dialer.DialContext(ctx, network, net.JoinHostPort(addresses[0].String(), port))
	}
	client.Transport = transport
	// A source response is untrusted; even a same-origin redirect would
	// change the fixed endpoint and may forward its bearer credential.
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return client, nil
}

func pinnedOrigin(raw string) (string, string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Opaque != "" || u.User != nil ||
		u.Host == "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" ||
		(u.Path != "" && u.Path != "/") || u.RawPath != "" {
		return "", "", errors.New("crypto: source origin must be an HTTPS authority")
	}
	host := u.Hostname()
	if host == "" || strings.Contains(host, "%") || !pinnedHost(host) {
		return "", "", errors.New("crypto: source origin host invalid")
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return "", "", errors.New("crypto: source origin port invalid")
	}
	return host, port, nil
}

func pinnedHost(host string) bool {
	if addr, err := netip.ParseAddr(host); err == nil {
		return addr.IsValid() && addr.Zone() == ""
	}
	if len(host) > 253 || strings.HasSuffix(host, ".") {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') &&
				(c < '0' || c > '9') && c != '-' {
				return false
			}
		}
	}
	return true
}

func pinnedAddresses(ctx context.Context, host string, allowed []netip.Prefix) ([]netip.Addr, error) {
	var addresses []netip.Addr
	if literal, err := netip.ParseAddr(host); err == nil {
		addresses = []netip.Addr{literal}
	} else {
		var err error
		addresses, err = net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		if err != nil {
			return nil, errors.New("crypto: pinned HTTPS DNS lookup failed")
		}
	}
	if len(addresses) == 0 {
		return nil, errors.New("crypto: pinned HTTPS DNS returned no addresses")
	}
	for _, address := range addresses {
		address = address.Unmap()
		permitted := false
		for _, prefix := range allowed {
			if prefix.Contains(address) {
				permitted = true
				break
			}
		}
		if !permitted {
			return nil, errors.New("crypto: pinned HTTPS destination outside approved CIDRs")
		}
	}
	return addresses, nil
}
