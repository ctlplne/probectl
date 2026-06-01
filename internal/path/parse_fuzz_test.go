package path

import (
	"encoding/binary"
	"testing"
)

// These fuzz targets harden the ICMP response parsers, which consume untrusted
// bytes straight off the wire. The invariant is simply: never panic, whatever
// the input. (Run: `go test -run=^$ -fuzz=FuzzParseICMPv4 ./internal/path`.)

// timeExceededv4 builds a minimal valid ICMPv4 Time Exceeded quoting an IP+ICMP
// echo, to seed the corpus with a structurally-valid input.
func timeExceededv4(flow, id, seq uint16) []byte {
	inner := make([]byte, 28) // 20-byte IP header + 8-byte ICMP echo
	inner[0] = 0x45           // IPv4, IHL 5
	inner[9] = ianaProtoICMP
	binary.BigEndian.PutUint16(inner[22:24], flow) // embedded ICMP checksum = flow id
	binary.BigEndian.PutUint16(inner[24:26], id)
	binary.BigEndian.PutUint16(inner[26:28], seq)

	msg := make([]byte, 4+4+len(inner)) // ICMP header(4) + unused(4) + quoted datagram
	msg[0] = 11                         // Time Exceeded
	copy(msg[8:], inner)
	return msg
}

func FuzzParseICMPv4(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x00})
	f.Add(timeExceededv4(0x1234, 0xabcd, 7))
	f.Add([]byte{8, 0, 0, 0, 0, 1, 0, 1}) // echo request
	f.Fuzz(func(_ *testing.T, b []byte) {
		_, _ = parseICMPv4(b) // must not panic
	})
}

func FuzzParseTimeExceeded(f *testing.F) {
	f.Add(timeExceededv4(1, 2, 3))
	f.Add([]byte{11, 0, 0, 0})
	f.Fuzz(func(_ *testing.T, b []byte) {
		data, _, ok := parseTimeExceeded(b)
		if !ok && data != nil {
			panic("parseTimeExceeded returned data with ok=false")
		}
	})
}

func FuzzEmbeddedEcho(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x45})
	f.Add(make([]byte, 28))
	f.Fuzz(func(_ *testing.T, b []byte) {
		id, seq, flow, ok := embeddedEcho(b)
		if !ok && (id != 0 || seq != 0 || flow != 0) {
			panic("embeddedEcho returned values with ok=false")
		}
		_, _, _ = embeddedTCP(b) // exercise the TCP-quote parser on the same bytes
	})
}
