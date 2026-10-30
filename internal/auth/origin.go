// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package auth

import (
	"errors"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

// CanonicalHTTPOrigin validates one serialized HTTP(S) browser origin for an
// explicit deployment trust policy. It never derives trust from request Host,
// forwarded headers or DNS. Opaque/null, wildcard and multi-origin values fail
// closed. Browser IDNs must use their ASCII serialized form.
func CanonicalHTTPOrigin(raw string) (string, error) {
	invalid := errors.New("origin must be one serialized HTTP(S) origin without credentials, path, query, fragment or wildcard")
	for _, c := range raw {
		if c <= ' ' || c >= 127 || c == '*' {
			return "", invalid
		}
	}
	u, err := url.Parse(raw)
	if err != nil || u == nil || u.User != nil || u.Opaque != "" || u.Host == "" || u.Path != "" || u.RawPath != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.Contains(raw, "#") || strings.HasSuffix(u.Host, ":") {
		return "", invalid
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "https" && scheme != "http" {
		return "", invalid
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return "", invalid
	}
	if address, err := netip.ParseAddr(host); err == nil {
		if address.Zone() != "" {
			return "", invalid
		}
		host = address.String()
	} else {
		if strings.HasPrefix(u.Host, "[") {
			return "", invalid
		}
		for _, c := range host {
			if c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '.' || c == '-' || c == '_' {
				continue
			}
			return "", invalid
		}
	}
	port := u.Port()
	if port != "" {
		number, err := strconv.Atoi(port)
		if err != nil || number < 0 || number > 65535 {
			return "", invalid
		}
		port = strconv.Itoa(number)
		if scheme == "https" && port == "443" || scheme == "http" && port == "80" {
			port = ""
		}
	}
	authority := host
	if port != "" {
		authority = net.JoinHostPort(host, port)
	} else if strings.Contains(host, ":") {
		authority = "[" + host + "]"
	}
	return scheme + "://" + authority, nil
}
