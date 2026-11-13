// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package canary

import (
	"errors"
	"net"
	"net/url"
	"strings"

	"github.com/miekg/dns"
)

// ConfiguredResultTarget derives the producer's exact result identity without
// executing a probe, resolving a name or exposing secret-bearing parameters.
// Consumers must still require original sender-bound execution evidence; this
// configuration-derived string is never proof that a test ran.
func ConfiguredResultTarget(cfg Config) (string, error) {
	switch cfg.Type {
	case "icmp", "noop":
		return cfg.Target, nil
	case "tcp", "udp", "voice":
		host, port, err := splitTarget(cfg.Target, cfg.Params["port"])
		if err != nil {
			return "", errors.New("configured socket result identity is invalid")
		}
		return net.JoinHostPort(host, port), nil
	case "dns":
		name := strings.TrimSpace(cfg.Target)
		if name == "" {
			return "", errors.New("configured DNS result identity is invalid")
		}
		return strings.TrimSuffix(dns.Fqdn(name), "."), nil
	case "http":
		u, err := url.Parse(strings.TrimSpace(cfg.Target))
		if err != nil || u.Host == "" || u.Scheme != "http" && u.Scheme != "https" {
			return "", errors.New("configured HTTP result identity is invalid")
		}
		return redactURLUserinfo(u), nil
	default:
		return "", errors.New("configured canary result identity is unsupported")
	}
}
