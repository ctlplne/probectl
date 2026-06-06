package canary

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
	"syscall"
)

// SSRF target guard (U-002): probe/canary targets are operator- and
// API-supplied, and agents sit inside customer networks — an unguarded
// target turns the agent fleet into an SSRF proxy (cloud metadata, RFC1918
// scanning). The guard denies private/internal destinations BY DEFAULT and
// is enforced at three layers:
//
//  1. CheckHost at canary construction (literal IPs + ambiguous numeric
//     hosts like "2130706433", "0x7f000001", "0177.0.0.1" are decided
//     before any network I/O);
//  2. CheckIP on every RESOLVED address at dial time via DialControl (the
//     kernel-handoff point: DNS rebinding cannot skip it, and HTTP
//     redirects re-enter it on every hop because the transport's dialer is
//     guarded);
//  3. explicit resolve-then-check for non-dialer probes (ICMP), which must
//     then use the checked IP, not re-resolve.
//
// The override (Params["allow_private_targets"] = "true") is per-test,
// tenant-scoped, admin-gated and audited at the control plane (the agent
// only honors what the API accepted).

// AllowPrivateParam is the per-test Params key for the audited override.
const AllowPrivateParam = "allow_private_targets"

// TargetGuard validates probe/canary destinations.
type TargetGuard struct {
	allowPrivate bool
}

// NewTargetGuard returns a guard; allowPrivate true disables the denylist
// (the audited per-test override).
func NewTargetGuard(allowPrivate bool) *TargetGuard {
	return &TargetGuard{allowPrivate: allowPrivate}
}

// GuardFromParams builds the guard from a canary Config's params.
func GuardFromParams(params map[string]string) *TargetGuard {
	return NewTargetGuard(params[AllowPrivateParam] == "true")
}

// CheckIP applies the denylist to one resolved address.
func (g *TargetGuard) CheckIP(ip netip.Addr) error {
	if g.allowPrivate {
		return nil
	}
	a := ip.Unmap() // ::ffff:10.0.0.1 is 10.0.0.1
	switch {
	case !a.IsValid():
		return fmt.Errorf("canary: invalid target address")
	case a.IsLoopback():
		return deniedErr(a, "loopback")
	case a.IsLinkLocalUnicast(): // includes 169.254.169.254 (cloud metadata)
		return deniedErr(a, "link-local / cloud-metadata")
	case a.IsLinkLocalMulticast(), a.IsMulticast():
		return deniedErr(a, "multicast")
	case a.IsPrivate(): // RFC1918 / fc00::/7
		return deniedErr(a, "private (RFC1918/ULA)")
	case a.IsUnspecified():
		return deniedErr(a, "unspecified")
	case a.Is4() && cgnat.Contains(a):
		return deniedErr(a, "carrier-grade NAT (RFC6598)")
	case a.Is4() && a == netip.AddrFrom4([4]byte{255, 255, 255, 255}):
		return deniedErr(a, "broadcast")
	}
	return nil
}

var cgnat = netip.MustParsePrefix("100.64.0.0/10")

func deniedErr(a netip.Addr, class string) error {
	return fmt.Errorf("canary: target %s is denied by the SSRF guard (%s); "+
		"an admin may set %s=true on the test (audited)", a, class, AllowPrivateParam)
}

// CheckHost validates a host BEFORE any resolution: a literal IP is checked
// directly; an ambiguous all-numeric host (decimal "2130706433", hex
// "0x7f000001", octal "0177.0.0.1", short "127.1") that is not a canonical
// IP is rejected outright — such forms exist only to smuggle addresses past
// parsers, so they are never handed to a resolver. Hostnames pass here and
// are enforced at dial time against their RESOLVED addresses.
func (g *TargetGuard) CheckHost(host string) error {
	if g.allowPrivate {
		return nil
	}
	host = strings.TrimSuffix(strings.Trim(host, "[]"), ".")
	if host == "" {
		return fmt.Errorf("canary: empty target host")
	}
	if a, err := netip.ParseAddr(host); err == nil {
		return g.CheckIP(a)
	}
	if numericIPLike(host) {
		return fmt.Errorf("canary: ambiguous numeric target %q is denied by the SSRF guard "+
			"(use the canonical IP form)", host)
	}
	return nil
}

// numericIPLike reports whether every dot label is decimal/hex/octal — an
// IP-smuggling encoding rather than a hostname (DNS labels must start with
// an alphanumeric and real hostnames contain letters).
func numericIPLike(host string) bool {
	labels := strings.Split(host, ".")
	for _, l := range labels {
		if l == "" {
			return false
		}
		rest := l
		if len(l) > 2 && (strings.HasPrefix(l, "0x") || strings.HasPrefix(l, "0X")) {
			rest = l[2:]
			if !isHex(rest) {
				return false
			}
			continue
		}
		for _, r := range rest {
			if r < '0' || r > '9' {
				return false
			}
		}
	}
	return true
}

func isHex(s string) bool {
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f', r >= 'A' && r <= 'F':
		default:
			return false
		}
	}
	return s != ""
}

// DialControl returns a net.Dialer Control that enforces the guard on the
// RESOLVED address (rebind-proof: it runs for every connection attempt,
// after DNS, at the kernel handoff) and then chains to next (e.g. the DSCP
// marker). Pass next nil when there is nothing to chain.
func (g *TargetGuard) DialControl(next func(network, address string, c syscall.RawConn) error) func(network, address string, c syscall.RawConn) error {
	return func(network, address string, c syscall.RawConn) error {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			host = address
		}
		a, err := netip.ParseAddr(strings.Trim(host, "[]"))
		if err != nil {
			return fmt.Errorf("canary: unparseable dial address %q: %w", address, err)
		}
		if err := g.CheckIP(a); err != nil {
			return err
		}
		if next != nil {
			return next(network, address, c)
		}
		return nil
	}
}

// CheckNetIP adapts net.IP resolution results (the ICMP path: resolve once,
// check, then ping the CHECKED address — never re-resolve).
func (g *TargetGuard) CheckNetIP(ip net.IP) error {
	a, ok := netip.AddrFromSlice(ip)
	if !ok {
		return fmt.Errorf("canary: invalid resolved address %v", ip)
	}
	return g.CheckIP(a)
}
