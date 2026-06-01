package canary

import (
	"crypto/tls"
	"net/http/httptrace"
	"time"
)

// phaseTimer records the per-phase durations of an HTTP request via httptrace.
// It keeps the first occurrence of each phase, so when a request follows
// redirects the breakdown reflects the initial connection rather than the last
// hop.
type phaseTimer struct {
	dnsStart, connStart, tlsStart time.Time
	dns, connect, tlsHS, ttfb     time.Duration
}

// clientTrace returns an httptrace.ClientTrace bound to this timer. peerAddr is
// filled with the remote address of the first connection used (the network-layer
// datum that correlates an HTTP result to path/traceroute data for the same IP).
func (t *phaseTimer) clientTrace(start time.Time, peerAddr *string) *httptrace.ClientTrace {
	return &httptrace.ClientTrace{
		DNSStart: func(httptrace.DNSStartInfo) {
			if t.dnsStart.IsZero() {
				t.dnsStart = time.Now()
			}
		},
		DNSDone: func(httptrace.DNSDoneInfo) {
			if t.dns == 0 && !t.dnsStart.IsZero() {
				t.dns = time.Since(t.dnsStart)
			}
		},
		ConnectStart: func(_, _ string) {
			if t.connStart.IsZero() {
				t.connStart = time.Now()
			}
		},
		ConnectDone: func(_, _ string, _ error) {
			if t.connect == 0 && !t.connStart.IsZero() {
				t.connect = time.Since(t.connStart)
			}
		},
		TLSHandshakeStart: func() {
			if t.tlsStart.IsZero() {
				t.tlsStart = time.Now()
			}
		},
		TLSHandshakeDone: func(tls.ConnectionState, error) {
			if t.tlsHS == 0 && !t.tlsStart.IsZero() {
				t.tlsHS = time.Since(t.tlsStart)
			}
		},
		GotConn: func(info httptrace.GotConnInfo) {
			if *peerAddr == "" && info.Conn != nil {
				*peerAddr = info.Conn.RemoteAddr().String()
			}
		},
		GotFirstResponseByte: func() {
			if t.ttfb == 0 {
				t.ttfb = time.Since(start)
			}
		},
	}
}

// attachTiming writes the phase metrics that actually occurred onto res. A phase
// that did not happen (e.g. no DNS lookup for an IP target, no TLS for http://)
// is omitted rather than reported as zero.
func (t *phaseTimer) attachTiming(res *Result) {
	if t.dns > 0 {
		res.Metrics["http.dns.ms"] = round(msf(t.dns), 3)
	}
	if t.connect > 0 {
		res.Metrics["http.connect.ms"] = round(msf(t.connect), 3)
	}
	if t.tlsHS > 0 {
		res.Metrics["http.tls.ms"] = round(msf(t.tlsHS), 3)
	}
	if t.ttfb > 0 {
		res.Metrics["http.ttfb.ms"] = round(msf(t.ttfb), 3)
	}
}
