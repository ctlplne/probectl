// SPDX-License-Identifier: LicenseRef-probectl-TBD

package canary

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// rootServers are IANA root-server IPs (root hints). A trace starts here and
// follows the delegations down. They are stable anycast addresses.
var rootServers = []string{
	"198.41.0.4",   // a.root-servers.net
	"199.9.14.201", // b.root-servers.net
	"192.33.4.12",  // c.root-servers.net
	"192.5.5.241",  // f.root-servers.net
}

// runTrace walks the delegation from the root to the authoritative server,
// recording each zone cut. Trace always uses UDP (iterative resolution).
func (c *dnsCanary) runTrace(ctx context.Context, res Result) Result {
	chain, total, err := c.trace(ctx)
	res.Duration = time.Since(res.StartedAt)
	if err != nil && len(chain) <= 1 {
		res.Success = false
		res.Error = err.Error()
		res.Metrics = map[string]float64{}
		return res
	}
	res.Metrics = map[string]float64{
		"dns.query.ms":   round(float64(total)/float64(time.Millisecond), 3),
		"dns.trace.hops": float64(len(chain)),
	}
	res.Attributes["probectl.dns.trace"] = strings.Join(chain, " > ")
	res.Success = err == nil && len(chain) > 1
	if !res.Success && res.Error == "" {
		res.Error = "trace did not reach an authoritative answer"
	}
	return res
}

func (c *dnsCanary) trace(ctx context.Context) (chain []string, total time.Duration, err error) {
	client := &dns.Client{Timeout: c.timeout, Net: "udp"}
	servers := rootServers
	chain = []string{"."}

	for hop := 0; hop < 16; hop++ {
		m := new(dns.Msg)
		m.SetQuestion(c.name, c.qtype)
		m.RecursionDesired = false

		resp, rtt, qerr := exchangeAny(ctx, client, m, servers)
		total += rtt
		if qerr != nil {
			return chain, total, fmt.Errorf("trace query failed: %w", qerr)
		}

		// An authoritative server answered (data, NODATA, or NXDOMAIN).
		if resp.Authoritative || len(resp.Answer) > 0 || resp.Rcode == dns.RcodeNameError {
			chain = append(chain, fmt.Sprintf("authoritative (%s)", dns.RcodeToString[resp.Rcode]))
			return chain, total, nil
		}

		next, zone := c.referral(ctx, client, resp)
		if len(next) == 0 {
			return chain, total, fmt.Errorf("no usable delegation below %s", zone)
		}
		chain = append(chain, zone)
		servers = next
	}
	return chain, total, fmt.Errorf("too many delegations")
}

// referral extracts the next set of nameserver IPs and the delegated zone from a
// referral response, preferring glue and falling back to resolving an NS name.
func (c *dnsCanary) referral(ctx context.Context, client *dns.Client, resp *dns.Msg) (servers []string, zone string) {
	glue := map[string]string{}
	for _, rr := range resp.Extra {
		if a, ok := rr.(*dns.A); ok {
			glue[strings.ToLower(a.Header().Name)] = a.A.String()
		}
	}
	for _, rr := range resp.Ns {
		ns, ok := rr.(*dns.NS)
		if !ok {
			continue
		}
		zone = ns.Header().Name
		if ip := glue[strings.ToLower(ns.Ns)]; ip != "" {
			servers = append(servers, ip)
		}
	}
	if len(servers) == 0 {
		for _, rr := range resp.Ns {
			if ns, ok := rr.(*dns.NS); ok {
				if ips := resolveA(ctx, client, ns.Ns); len(ips) > 0 {
					return ips, zone
				}
			}
		}
	}
	return servers, zone
}

func exchangeAny(ctx context.Context, client *dns.Client, m *dns.Msg, servers []string) (*dns.Msg, time.Duration, error) {
	var lastErr error
	for _, s := range servers {
		resp, rtt, err := client.ExchangeContext(ctx, m, withDefaultPort(s, "53"))
		if err == nil {
			return resp, rtt, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no servers to query")
	}
	return nil, 0, lastErr
}

// resolveA resolves a hostname to A records via a public recursive resolver (the
// no-glue fallback during a trace).
func resolveA(ctx context.Context, client *dns.Client, host string) []string {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(host), dns.TypeA)
	m.RecursionDesired = true
	resp, _, err := client.ExchangeContext(ctx, m, "1.1.1.1:53")
	if err != nil {
		return nil
	}
	var ips []string
	for _, rr := range resp.Answer {
		if a, ok := rr.(*dns.A); ok {
			ips = append(ips, a.A.String())
		}
	}
	return ips
}
