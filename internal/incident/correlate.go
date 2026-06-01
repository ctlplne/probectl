package incident

import (
	"net"
	"net/netip"
	"time"
)

// related reports whether sig belongs to an open incident: the signal must be
// close in time to the incident's activity AND share a target/prefix with it.
// This is the S17 "basic correlation grouping (time + target/prefix proximity)".
func related(inc *Incident, sig Signal, window time.Duration) bool {
	if inc.Status != StatusOpen {
		return false
	}
	if !withinWindow(sig.OccurredAt, inc.StartedAt, inc.LastSeenAt, window) {
		return false
	}
	return targetsRelated(inc.Target, inc.Prefix, sig.Target, sig.Prefix)
}

// withinWindow allows a signal up to window before the incident started and up to
// window after its last activity (so a burst stays one incident, but a much-later
// recurrence opens a new one).
func withinWindow(t, start, last time.Time, window time.Duration) bool {
	if t.Before(start.Add(-window)) {
		return false
	}
	return !t.After(last.Add(window))
}

// targetsRelated is true when an incident and a signal concern the same target or
// overlapping address space — the cross-plane join (a network alert on an IP and
// a BGP event on the prefix that contains it correlate).
func targetsRelated(incTarget, incPrefix, sigTarget, sigPrefix string) bool {
	if incTarget != "" && incTarget == sigTarget {
		return true
	}
	// The signal's IP target inside the incident's prefix (or vice versa).
	if ipInPrefix(sigTarget, incPrefix) || ipInPrefix(incTarget, sigPrefix) {
		return true
	}
	// Overlapping prefixes (e.g. a /24 incident and a more-specific /25 signal).
	if prefixesOverlap(incPrefix, sigPrefix) {
		return true
	}
	return false
}

// asAddr extracts an IP from a target that may be a bare IP, a host:port, or a
// URL host. A non-IP host (a DNS name) yields ok=false (matched only by exact
// string equality elsewhere).
func asAddr(target string) (netip.Addr, bool) {
	if target == "" {
		return netip.Addr{}, false
	}
	if a, err := netip.ParseAddr(target); err == nil {
		return a, true
	}
	if host, _, err := net.SplitHostPort(target); err == nil {
		if a, err := netip.ParseAddr(host); err == nil {
			return a, true
		}
	}
	return netip.Addr{}, false
}

func ipInPrefix(target, prefix string) bool {
	if target == "" || prefix == "" {
		return false
	}
	addr, ok := asAddr(target)
	if !ok {
		return false
	}
	p, err := netip.ParsePrefix(prefix)
	if err != nil {
		return false
	}
	return p.Contains(addr)
}

func prefixesOverlap(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	pa, err := netip.ParsePrefix(a)
	if err != nil {
		return false
	}
	pb, err := netip.ParsePrefix(b)
	if err != nil {
		return false
	}
	return pa.Contains(pb.Addr()) || pb.Contains(pa.Addr())
}
