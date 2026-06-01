package path

import (
	"context"
	"fmt"
	"net"
	"os"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// Run discovers the multi-path route to cfg.Target: it runs cfg.TraceCount
// Paris traces and merges them into one Path.
func Run(ctx context.Context, cfg Config) (*Path, error) {
	if err := cfg.normalize(); err != nil {
		return nil, err
	}
	return discover(ctx, newTracer(cfg), cfg)
}

func newTracer(cfg Config) tracer {
	if cfg.Mode == "tcp" {
		return &tcpTracer{port: cfg.Port}
	}
	return &icmpTracer{privileged: cfg.Privileged}
}

func resolveIPv4(target string) (string, error) {
	ip, err := net.ResolveIPAddr("ip4", target)
	if err != nil {
		return "", fmt.Errorf("path: resolve %s: %w", target, err)
	}
	return ip.IP.String(), nil
}

// listenICMP opens an ICMP socket: a raw socket (which receives Time Exceeded for
// full traceroute) or, unprivileged, a datagram ICMP socket (which receives only
// the destination's Echo Reply). It reports whether the socket is raw.
func listenICMP(privileged bool) (conn *icmp.PacketConn, raw bool, err error) {
	openRaw := func() (*icmp.PacketConn, bool, error) {
		c, e := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
		return c, true, e
	}
	openUDP := func() (*icmp.PacketConn, bool, error) {
		c, e := icmp.ListenPacket("udp4", "0.0.0.0")
		return c, false, e
	}
	order := []func() (*icmp.PacketConn, bool, error){openUDP, openRaw}
	if privileged {
		order = []func() (*icmp.PacketConn, bool, error){openRaw, openUDP}
	}
	for _, open := range order {
		c, isRaw, e := open()
		if e == nil {
			return c, isRaw, nil
		}
		if err == nil {
			err = e
		}
	}
	return nil, false, err
}

func ipOf(addr net.Addr) string {
	switch a := addr.(type) {
	case *net.IPAddr:
		return a.IP.String()
	case *net.UDPAddr:
		return a.IP.String()
	default:
		if host, _, err := net.SplitHostPort(addr.String()); err == nil {
			return host
		}
		return addr.String()
	}
}

// icmpTracer runs ICMP traceroutes. With a raw socket it captures full per-hop
// paths (intermediate Time Exceeded + MPLS); unprivileged it captures only the
// destination's Echo Reply.
type icmpTracer struct{ privileged bool }

func (t *icmpTracer) resolve(target string) (string, error) { return resolveIPv4(target) }

func (t *icmpTracer) traceFlow(ctx context.Context, cfg Config, targetIP string, flowID uint16) (flowTrace, error) {
	conn, raw, err := listenICMP(t.privileged)
	if err != nil {
		return flowTrace{}, fmt.Errorf("path: open icmp socket: %w", err)
	}
	defer conn.Close()

	pc := conn.IPv4PacketConn()
	ip := net.ParseIP(targetIP).To4()
	var dst net.Addr = &net.UDPAddr{IP: ip}
	if raw {
		dst = &net.IPAddr{IP: ip}
	}
	id := uint16(os.Getpid() & 0xffff)
	const payloadLen = 40

	ft := flowTrace{flowID: flowID}
	for ttl := 1; ttl <= cfg.MaxHops; ttl++ {
		if ctx.Err() != nil {
			break
		}
		if pc != nil {
			_ = pc.SetTTL(ttl)
		}
		obs := hopObservation{ttl: ttl, sent: cfg.ProbesPerHop}
		for probe := 0; probe < cfg.ProbesPerHop; probe++ {
			seq := uint16(ttl*256 + probe)
			var pkt []byte
			if raw {
				pkt = craftParisEcho(id, seq, flowID, payloadLen)
			} else {
				m := icmp.Message{Type: ipv4.ICMPTypeEcho, Body: &icmp.Echo{ID: int(id), Seq: int(seq), Data: make([]byte, payloadLen)}}
				pkt, _ = m.Marshal(nil)
			}
			sentAt := time.Now()
			if _, err := conn.WriteTo(pkt, dst); err != nil {
				continue
			}
			ipStr, rtt, mpls, final, ok := awaitICMP(conn, raw, id, seq, flowID, sentAt, cfg.PerHopTimeout)
			if ok {
				obs.received++
				obs.ip = ipStr
				obs.rtts = append(obs.rtts, rtt)
				if len(mpls) > 0 {
					obs.mpls = mpls
				}
				if final {
					obs.final = true
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

// awaitICMP reads until a response matching (id,seq,flow) arrives or the per-hop
// timeout elapses. For raw sockets responses are matched on the forced flow
// checksum (Paris); on datagram sockets the kernel rewrites id/checksum, so only
// the destination Echo Reply (matched by sequence) is seen.
func awaitICMP(conn *icmp.PacketConn, raw bool, id, seq, flow uint16, sentAt time.Time, timeout time.Duration) (ip string, rtt time.Duration, mpls []MPLSLabel, final, ok bool) {
	deadline := sentAt.Add(timeout)
	buf := make([]byte, 1500)
	for {
		if err := conn.SetReadDeadline(deadline); err != nil {
			return "", 0, nil, false, false
		}
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			return "", 0, nil, false, false // timeout / closed
		}
		recv := time.Now()
		resp, parsed := parseICMPv4(buf[:n])
		if !parsed {
			continue
		}
		switch resp.kind {
		case respEchoReply:
			if resp.echoSeq == seq && (!raw || resp.echoID == id) {
				return ipOf(addr), recv.Sub(sentAt), nil, true, true
			}
		case respTimeExceeded, respDstUnreach:
			if resp.origSeq == seq && (!raw || resp.origFlow == flow) {
				return ipOf(addr), recv.Sub(sentAt), resp.mpls, resp.kind == respDstUnreach, true
			}
		}
	}
}
