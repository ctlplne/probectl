package path

import "testing"

func TestParisChecksumForcesFlowID(t *testing.T) {
	for _, flowID := range []uint16{0x0000, 0x0001, 0x1234, 0xabcd, 0xffff, 0x8000} {
		pkt := craftParisEcho(0x4321, 7, flowID, 56)
		if got := echoChecksumField(pkt); got != flowID {
			t.Errorf("flowID %#04x: checksum field = %#04x", flowID, got)
		}
		// The packet must remain a valid ICMP echo (a verifier computes 0).
		if v := internetChecksum(pkt); v != 0 {
			t.Errorf("flowID %#04x: packet is not a valid ICMP echo (verify = %#04x)", flowID, v)
		}
	}
}

func TestParisChecksumStableAcrossSeq(t *testing.T) {
	const flowID = 0x2bad
	for seq := uint16(0); seq < 8; seq++ {
		pkt := craftParisEcho(0x1111, seq, flowID, 40)
		if got := echoChecksumField(pkt); got != flowID {
			t.Errorf("seq %d: checksum field = %#04x, want %#04x (flow must stay stable)", seq, got, flowID)
		}
		if internetChecksum(pkt) != 0 {
			t.Errorf("seq %d: invalid checksum", seq)
		}
	}
}

func TestParisChecksumVariesByFlow(t *testing.T) {
	seen := map[uint16]bool{}
	for _, flowID := range []uint16{0x1000, 0x2000, 0x3000, 0x4000} {
		got := echoChecksumField(craftParisEcho(1, 1, flowID, 32))
		if seen[got] {
			t.Errorf("flow %#04x produced a duplicate checksum %#04x", flowID, got)
		}
		seen[got] = true
	}
}
