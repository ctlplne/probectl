package path

import (
	"context"
	"errors"
	"net"
	"strconv"
	"syscall"
	"time"

	"golang.org/x/net/icmp"
)

// tcpTracer runs a TCP-SYN traceroute. The destination is detected by the connect
// outcome (SYN-ACK → success, RST → refused — both mean "reached"), which works
// unprivileged. Intermediate hop IPs come from Time Exceeded responses read on a
// raw ICMP socket (privileged); without it only the destination is discovered.
type tcpTracer struct{ port int }

func (t *tcpTracer) resolve(target string) (string, error) { return resolveIPv4(target) }

func (t *tcpTracer) traceFlow(ctx context.Context, cfg Config, targetIP string, flowID uint16) (flowTrace, error) {
	var icmpConn *icmp.PacketConn
	if c, raw, err := listenICMP(true); err == nil && raw {
		icmpConn = c
		defer c.Close()
	}
	addr := net.JoinHostPort(targetIP, strconv.Itoa(t.port))
	ft := flowTrace{flowID: flowID}

	for ttl := 1; ttl <= cfg.MaxHops; ttl++ {
		if ctx.Err() != nil {
			break
		}
		obs := hopObservation{ttl: ttl, sent: 1}
		sentAt := time.Now()
		dialer := net.Dialer{Timeout: cfg.PerHopTimeout, Control: ttlControl(ttl)}
		conn, err := dialer.DialContext(ctx, "tcp4", addr)
		rtt := time.Since(sentAt)

		switch {
		case err == nil:
			_ = conn.Close()
			obs.ip, obs.received, obs.rtts, obs.final = targetIP, 1, []time.Duration{rtt}, true
		case isConnRefused(err):
			obs.ip, obs.received, obs.rtts, obs.final = targetIP, 1, []time.Duration{rtt}, true
		default:
			// The SYN's TTL likely expired at a router; learn it from a quoted
			// Time Exceeded if we have a raw socket.
			if icmpConn != nil {
				if ip, mpls, ok := awaitTCPHop(icmpConn, uint16(t.port), sentAt, cfg.PerHopTimeout); ok {
					obs.ip, obs.received, obs.rtts, obs.mpls = ip, 1, []time.Duration{rtt}, mpls
				}
			}
		}
		ft.hops = append(ft.hops, obs)
		if obs.final {
			break
		}
	}
	return ft, nil
}

func awaitTCPHop(conn *icmp.PacketConn, dstPort uint16, sentAt time.Time, timeout time.Duration) (ip string, mpls []MPLSLabel, ok bool) {
	deadline := sentAt.Add(timeout)
	buf := make([]byte, 1500)
	for {
		if err := conn.SetReadDeadline(deadline); err != nil {
			return "", nil, false
		}
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			return "", nil, false
		}
		data, labels, isTE := parseTimeExceeded(buf[:n])
		if !isTE {
			continue
		}
		if _, dp, valid := embeddedTCP(data); valid && dp == dstPort {
			return ipOf(addr), labels, true
		}
	}
}

func isConnRefused(err error) bool { return errors.Is(err, syscall.ECONNREFUSED) }
