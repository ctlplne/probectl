package path

import (
	"encoding/binary"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

const ianaProtoICMP = 1

type responseKind int

const (
	respOther responseKind = iota
	respTimeExceeded
	respEchoReply
	respDstUnreach
)

// icmpResponse is a parsed ICMP message received during a trace.
type icmpResponse struct {
	kind responseKind
	// For Time Exceeded / Dest Unreachable: the embedded original probe, which
	// identifies which TTL (seq) and flow (checksum) this response answers.
	origID, origSeq, origFlow uint16
	// For Echo Reply (the destination).
	echoID, echoSeq uint16
	mpls            []MPLSLabel
}

// parseICMPv4 parses a received IPv4 ICMP message.
func parseICMPv4(b []byte) (icmpResponse, bool) {
	m, err := icmp.ParseMessage(ianaProtoICMP, b)
	if err != nil {
		return icmpResponse{}, false
	}
	switch body := m.Body.(type) {
	case *icmp.TimeExceeded:
		r := icmpResponse{kind: respTimeExceeded, mpls: mplsFromExtensions(body.Extensions)}
		r.origID, r.origSeq, r.origFlow, _ = embeddedEcho(body.Data)
		return r, true
	case *icmp.DstUnreach:
		r := icmpResponse{kind: respDstUnreach, mpls: mplsFromExtensions(body.Extensions)}
		r.origID, r.origSeq, r.origFlow, _ = embeddedEcho(body.Data)
		return r, true
	case *icmp.Echo:
		if m.Type == ipv4.ICMPTypeEchoReply {
			return icmpResponse{kind: respEchoReply, echoID: uint16(body.ID), echoSeq: uint16(body.Seq)}, true
		}
		return icmpResponse{kind: respOther}, false
	default:
		return icmpResponse{kind: respOther}, false
	}
}

// parseTimeExceeded returns the quoted datagram + MPLS labels of a Time Exceeded
// message (used by the TCP tracer, which quotes a TCP segment rather than an ICMP
// echo).
func parseTimeExceeded(b []byte) (data []byte, mpls []MPLSLabel, ok bool) {
	m, err := icmp.ParseMessage(ianaProtoICMP, b)
	if err != nil {
		return nil, nil, false
	}
	if te, isTE := m.Body.(*icmp.TimeExceeded); isTE {
		return te.Data, mplsFromExtensions(te.Extensions), true
	}
	return nil, nil, false
}

// mplsFromExtensions converts the RFC 4950 MPLS label-stack objects carried in an
// ICMP multipart message (RFC 4884) into the path model's labels.
func mplsFromExtensions(exts []icmp.Extension) []MPLSLabel {
	var out []MPLSLabel
	for _, e := range exts {
		ls, ok := e.(*icmp.MPLSLabelStack)
		if !ok {
			continue
		}
		for _, l := range ls.Labels {
			out = append(out, MPLSLabel{
				Label: uint32(l.Label),
				TC:    uint8(l.TC),
				S:     l.S,
				TTL:   uint8(l.TTL),
			})
		}
	}
	return out
}

// embeddedEcho recovers the original probe's id, sequence, and flow (the forced
// ICMP checksum) from the IP datagram quoted inside a Time Exceeded / Dest
// Unreachable message — that is how a response is matched back to its TTL + flow.
func embeddedEcho(data []byte) (id, seq, flow uint16, ok bool) {
	if len(data) < 1 || data[0]>>4 != 4 {
		return 0, 0, 0, false
	}
	ihl := int(data[0]&0x0f) * 4
	if ihl < 20 || len(data) < ihl+8 {
		return 0, 0, 0, false
	}
	inner := data[ihl:]
	flow = binary.BigEndian.Uint16(inner[2:4]) // the embedded ICMP checksum
	id = binary.BigEndian.Uint16(inner[4:6])
	seq = binary.BigEndian.Uint16(inner[6:8])
	return id, seq, flow, true
}

// embeddedTCP recovers the source/destination ports of the TCP segment quoted
// inside a Time Exceeded — how a TCP-mode probe is matched back to its hop.
func embeddedTCP(data []byte) (srcPort, dstPort uint16, ok bool) {
	if len(data) < 1 || data[0]>>4 != 4 {
		return 0, 0, false
	}
	ihl := int(data[0]&0x0f) * 4
	if ihl < 20 || len(data) < ihl+4 {
		return 0, 0, false
	}
	tcp := data[ihl:]
	return binary.BigEndian.Uint16(tcp[0:2]), binary.BigEndian.Uint16(tcp[2:4]), true
}
