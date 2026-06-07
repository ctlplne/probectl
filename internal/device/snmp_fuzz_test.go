package device

import (
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"
)

// fuzzConn serves fuzz-controlled PDU values for every requested OID and
// table row — a hostile device. The wire decoding is gosnmp's job; OUR
// untrusted surface is the value handling (type switches, string
// conversions, counter math, index parsing) in pollSNMP and the walkers.
type fuzzConn struct {
	val  []byte
	num  int64
	kind gosnmp.Asn1BER
}

func (c fuzzConn) Get(oids []string) ([]gosnmp.SnmpPDU, error) {
	out := make([]gosnmp.SnmpPDU, 0, len(oids))
	for _, oid := range oids {
		out = append(out, gosnmp.SnmpPDU{Name: oid, Type: c.kind, Value: c.value()})
	}
	return out, nil
}

func (c fuzzConn) BulkWalk(root string, fn gosnmp.WalkFunc) error {
	// A few rows, including a hostile (non-numeric-suffix) index.
	for _, suffix := range []string{".1", ".4294967295", ".x", ""} {
		if err := fn(gosnmp.SnmpPDU{Name: root + suffix, Type: c.kind, Value: c.value()}); err != nil {
			return err
		}
	}
	return nil
}

func (c fuzzConn) Close() error { return nil }

func (c fuzzConn) value() any {
	switch c.kind {
	case gosnmp.OctetString:
		return c.val
	case gosnmp.Counter64, gosnmp.Counter32, gosnmp.Gauge32, gosnmp.Integer:
		return c.num
	default:
		return c.val
	}
}

// FuzzSNMPPoll (U-082): a polled device answers with attacker-controllable
// PDU values (octet strings, lying counters, hostile table indexes). The
// poller must never panic and must return tenant-stamped metrics only.
func FuzzSNMPPoll(f *testing.F) {
	f.Add([]byte("Cisco IOS XE"), int64(1000), uint8(gosnmp.OctetString))
	f.Add([]byte{0xff, 0xfe, 0x00}, int64(-1), uint8(gosnmp.Counter64))
	f.Add([]byte(""), int64(1<<62), uint8(gosnmp.Integer))
	f.Add([]byte("\x00\x00\x00"), int64(0), uint8(gosnmp.Gauge32))

	now := time.Unix(1750000000, 0).UTC()
	f.Fuzz(func(t *testing.T, val []byte, num int64, kind uint8) {
		conn := fuzzConn{val: val, num: num, kind: gosnmp.Asn1BER(kind)}
		dev := Target{Address: "192.0.2.10", Port: 161, Transport: "snmpv2c", Sensors: true}
		metrics, _, err := pollSNMP(conn, dev, "tenant-1", "agent-1", now)
		if err != nil {
			return // a refusal is fine; a panic is not
		}
		for _, m := range metrics {
			if m.TenantID != "tenant-1" {
				t.Fatalf("metric escaped tenant stamping: %+v", m)
			}
		}
	})
}
