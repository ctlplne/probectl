package path

import "encoding/binary"

// internetChecksum computes the RFC 1071 one's-complement checksum of b.
func internetChecksum(b []byte) uint16 {
	var s uint32
	for i := 0; i+1 < len(b); i += 2 {
		s += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		s += uint32(b[len(b)-1]) << 8
	}
	for s>>16 != 0 {
		s = (s & 0xffff) + (s >> 16)
	}
	return ^uint16(s)
}

// onesAdd adds two values with one's-complement (end-around carry) folding.
func onesAdd(a, b uint16) uint16 {
	s := uint32(a) + uint32(b)
	for s>>16 != 0 {
		s = (s & 0xffff) + (s >> 16)
	}
	return uint16(s)
}

// onesSub computes a - b in one's-complement arithmetic.
func onesSub(a, b uint16) uint16 { return onesAdd(a, ^b) }

// icmpEchoType is the IPv4 ICMP Echo Request type.
const icmpEchoType = 8

// craftParisEcho builds an ICMP Echo Request (IPv4) for id+seq whose on-wire
// checksum field is forced to flowID, by solving a 2-byte "balance" word in the
// payload. The packet stays a valid ICMP echo (a verifier still computes 0), so
// routers and the destination accept it — but ECMP routers that hash on the ICMP
// checksum keep this flow on one stable path. Different flowIDs explore different
// paths. This is the Paris-traceroute technique. payloadLen is clamped to >= 2
// (the balance word).
func craftParisEcho(id, seq, flowID uint16, payloadLen int) []byte {
	if payloadLen < 2 {
		payloadLen = 2
	}
	b := make([]byte, 8+payloadLen)
	b[0] = icmpEchoType
	b[1] = 0 // code
	// b[2:4] checksum field — left 0 while we solve the balance word.
	binary.BigEndian.PutUint16(b[4:6], id)
	binary.BigEndian.PutUint16(b[6:8], seq)
	// b[8:10] is the balance word (currently 0); fill the rest with a pattern.
	for i := 10; i < len(b); i++ {
		b[i] = byte(i)
	}

	// With the checksum field and balance word both 0, internetChecksum(b) is the
	// correct checksum the wire would carry, = ^fold(baseSum). We want the on-wire
	// checksum field to equal flowID, so choose balance so the recomputed checksum
	// becomes flowID:
	//   ^fold(baseSum + balance) = flowID
	//   fold(baseSum) + balance  = ^flowID         (one's-complement)
	//   balance = (^flowID) - fold(baseSum) = onesSub(^flowID, ^cur)
	cur := internetChecksum(b) // = ^fold(baseSum)
	balance := onesSub(^flowID, ^cur)
	binary.BigEndian.PutUint16(b[8:10], balance)
	binary.BigEndian.PutUint16(b[2:4], flowID)
	return b
}

// echoChecksumField returns the ICMP checksum field of a crafted echo (its flow
// identifier).
func echoChecksumField(b []byte) uint16 {
	if len(b) < 4 {
		return 0
	}
	return binary.BigEndian.Uint16(b[2:4])
}
