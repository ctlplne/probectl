package flow

import (
	"net/netip"
	"testing"
	"time"
)

const exporter = "203.0.113.10"

// --- NetFlow v5 ---------------------------------------------------------

// TestNetFlow5Decode checks the fixed-format decoder end to end: header clock
// mapping, the 14-bit sampling interval, and every record field.
func TestNetFlow5Decode(t *testing.T) {
	unixSecs := uint32(testTime.Unix())
	pkt := buildNF5(60_000, unixSecs, 0x4002 /* mode 01, rate 2 */, []nf5rec{{
		src: [4]byte{10, 0, 0, 1}, dst: [4]byte{10, 0, 0, 2}, nexthop: [4]byte{10, 0, 0, 254},
		inIf: 3, outIf: 4, pkts: 10, bytes: 1000,
		first: 30_000, last: 50_000,
		sport: 1234, dport: 80, flags: 0x18, proto: 6, tos: 0xB8,
		srcAS: 64500, dstAS: 64501,
	}})

	recs, err := decodeNetFlow5(pkt, exporter, testTime)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(recs) != 1 {
		t.Fatalf("records = %d, want 1", len(recs))
	}
	r := recs[0]
	if r.Protocol != ProtoNetFlow5 || r.Exporter != exporter {
		t.Fatalf("identity = %q/%q", r.Protocol, r.Exporter)
	}
	if got, want := r.SrcAddr, netip.MustParseAddr("10.0.0.1"); got != want {
		t.Errorf("src = %v", got)
	}
	if r.SrcPort != 1234 || r.DstPort != 80 || r.Transport != 6 || r.TCPFlags != 0x18 || r.ToS != 0xB8 {
		t.Errorf("tuple = %+v", r)
	}
	if r.InIf != 3 || r.OutIf != 4 || r.SrcAS != 64500 || r.DstAS != 64501 {
		t.Errorf("ifaces/AS = %+v", r)
	}
	if r.Bytes != 1000 || r.Packets != 10 || r.SamplingRate != 2 {
		t.Errorf("volume = bytes %d pkts %d rate %d", r.Bytes, r.Packets, r.SamplingRate)
	}
	// boot = export - 60s; first = +30s => start = export - 30s.
	if want := testTime.Add(-30 * time.Second); !r.Start.Equal(want) {
		t.Errorf("start = %v, want %v", r.Start, want)
	}
	if want := testTime.Add(-10 * time.Second); !r.End.Equal(want) {
		t.Errorf("end = %v, want %v", r.End, want)
	}
	// Sampling correction surfaces in the proto mapping.
	pr := r.ToProto()
	if pr.GetBytesScaled() != 2000 || pr.GetPacketsScaled() != 20 {
		t.Errorf("scaled = %d/%d, want 2000/20", pr.GetBytesScaled(), pr.GetPacketsScaled())
	}
	if pr.GetNetworkTransport() != "tcp" || pr.GetNetworkType() != "ipv4" {
		t.Errorf("otel names = %s/%s", pr.GetNetworkTransport(), pr.GetNetworkType())
	}
}

// TestNetFlow5Hostile checks bounds: truncation and absurd counts error, never panic.
func TestNetFlow5Hostile(t *testing.T) {
	good := buildNF5(1000, uint32(testTime.Unix()), 0, []nf5rec{{proto: 17}})
	cases := map[string][]byte{
		"short header":   good[:10],
		"truncated body": good[:nf5HeaderLen+10],
		"huge count":     append(append([]byte{}, good[:2]...), 0xFF, 0xFF),
	}
	for name, pkt := range cases {
		if _, err := decodeNetFlow5(pkt, exporter, testTime); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

// --- NetFlow v9 ---------------------------------------------------------

// nf9V4Fields is the field layout used by the v9 tests (width 41).
var nf9V4Fields = [][2]uint16{
	{ieIPv4Src, 4}, {ieIPv4Dst, 4}, {ieSrcPort, 2}, {ieDstPort, 2}, {ieProtocol, 1},
	{ieInBytes, 4}, {ieInPackets, 4}, {ieFirstSwitched, 4}, {ieLastSwitched, 4},
	{ieIngressIf, 2}, {ieEgressIf, 2}, {ieVLAN, 2}, {ieSrcAS, 2}, {ieDstAS, 2},
	{ieTCPFlags, 1}, {ieTOS, 1},
}

func nf9V4Row(src, dst [4]byte, sport, dport uint16, proto byte, bytes, pkts, first, last uint32) []byte {
	w := &wire{}
	w.raw(src[:]).raw(dst[:]).u16(sport).u16(dport).u8(proto)
	w.u32(bytes).u32(pkts).u32(first).u32(last)
	w.u16(7).u16(8).u16(120).u16(64496).u16(64497).u8(0x02).u8(0)
	return w.b
}

// TestNetFlow9TemplateThenData drives the template lifecycle: data before the
// template is a counted miss; after the template arrives the same data decodes.
func TestNetFlow9TemplateThenData(t *testing.T) {
	d := NewDecoder(time.Hour, 128)
	unix := uint32(testTime.Unix())
	row := nf9V4Row([4]byte{172, 16, 0, 1}, [4]byte{172, 16, 0, 2}, 53, 33000, 17, 512, 4, 10_000, 20_000)
	data := buildNF9Data(100_000, unix, 7, 260, [][]byte{row, row})

	recs, misses, err := d.Decode(data, exporter, testTime)
	if err != nil || len(recs) != 0 || misses != 1 {
		t.Fatalf("pre-template: recs=%d misses=%d err=%v (want 0/1/nil)", len(recs), misses, err)
	}

	tmpl := buildNF9Template(100_000, unix, 7, 260, nf9V4Fields)
	if _, _, err := d.Decode(tmpl, exporter, testTime); err != nil {
		t.Fatalf("template: %v", err)
	}
	if d.TemplateCount() != 1 {
		t.Fatalf("template cache = %d, want 1", d.TemplateCount())
	}

	recs, misses, err = d.Decode(data, exporter, testTime)
	if err != nil || misses != 0 {
		t.Fatalf("post-template: misses=%d err=%v", misses, err)
	}
	if len(recs) != 2 {
		t.Fatalf("records = %d, want 2", len(recs))
	}
	r := recs[0]
	if r.Protocol != ProtoNetFlow9 || r.ObservationDomain != 7 {
		t.Errorf("identity = %+v", r)
	}
	if r.SrcAddr != netip.MustParseAddr("172.16.0.1") || r.DstPort != 33000 || r.Transport != 17 {
		t.Errorf("tuple = %+v", r)
	}
	if r.Bytes != 512 || r.Packets != 4 || r.VLAN != 120 || r.SrcAS != 64496 {
		t.Errorf("fields = %+v", r)
	}
	// boot = export - 100s; first = +10s => start = export - 90s.
	if want := testTime.Add(-90 * time.Second); !r.Start.Equal(want) {
		t.Errorf("start = %v, want %v", r.Start, want)
	}
	// The same data from a DIFFERENT exporter must miss (templates are scoped).
	_, misses, _ = d.Decode(data, "198.51.100.99", testTime)
	if misses != 1 {
		t.Errorf("cross-exporter misses = %d, want 1", misses)
	}
}

// TestNetFlow9OptionsSampling checks that an options data record sets the
// exporter sampling state applied to subsequent flow records.
func TestNetFlow9OptionsSampling(t *testing.T) {
	d := NewDecoder(time.Hour, 128)
	unix := uint32(testTime.Unix())

	opts := buildNF9OptionsTemplate(50_000, unix, 7, 256,
		[][2]uint16{{1, 4}}, [][2]uint16{{ieSamplingIvl, 4}})
	if _, _, err := d.Decode(opts, exporter, testTime); err != nil {
		t.Fatalf("options template: %v", err)
	}
	optData := buildNF9Data(50_000, unix, 7, 256, [][]byte{
		(&wire{}).u32(1).u32(64).b, // scope + samplingInterval 64
	})
	if _, _, err := d.Decode(optData, exporter, testTime); err != nil {
		t.Fatalf("options data: %v", err)
	}

	tmpl := buildNF9Template(50_000, unix, 7, 260, nf9V4Fields)
	if _, _, err := d.Decode(tmpl, exporter, testTime); err != nil {
		t.Fatalf("template: %v", err)
	}
	row := nf9V4Row([4]byte{10, 9, 8, 7}, [4]byte{10, 9, 8, 6}, 1, 2, 6, 100, 1, 0, 0)
	recs, _, err := d.Decode(buildNF9Data(50_000, unix, 7, 260, [][]byte{row}), exporter, testTime)
	if err != nil || len(recs) != 1 {
		t.Fatalf("data: recs=%d err=%v", len(recs), err)
	}
	if recs[0].SamplingRate != 64 {
		t.Fatalf("sampling = %d, want 64 (from options)", recs[0].SamplingRate)
	}
	if recs[0].ToProto().GetBytesScaled() != 6400 {
		t.Fatalf("scaled bytes = %d, want 6400", recs[0].ToProto().GetBytesScaled())
	}
}

// TestNetFlow9IPv6Template checks a v6 template decodes v6 addresses.
func TestNetFlow9IPv6Template(t *testing.T) {
	d := NewDecoder(time.Hour, 128)
	unix := uint32(testTime.Unix())
	fields := [][2]uint16{{ieIPv6Src, 16}, {ieIPv6Dst, 16}, {ieSrcPort, 2}, {ieDstPort, 2}, {ieProtocol, 1}, {ieInBytes, 4}}
	if _, _, err := d.Decode(buildNF9Template(1000, unix, 7, 270, fields), exporter, testTime); err != nil {
		t.Fatalf("template: %v", err)
	}
	src := netip.MustParseAddr("2001:db8::1").As16()
	dst := netip.MustParseAddr("2001:db8::2").As16()
	row := (&wire{}).raw(src[:]).raw(dst[:]).u16(8080).u16(443).u8(6).u32(900).b
	recs, _, err := d.Decode(buildNF9Data(1000, unix, 7, 270, [][]byte{row}), exporter, testTime)
	if err != nil || len(recs) != 1 {
		t.Fatalf("decode: recs=%d err=%v", len(recs), err)
	}
	if recs[0].SrcAddr != netip.MustParseAddr("2001:db8::1") {
		t.Errorf("v6 src = %v", recs[0].SrcAddr)
	}
	if recs[0].ToProto().GetNetworkType() != "ipv6" {
		t.Errorf("network.type = %s", recs[0].ToProto().GetNetworkType())
	}
}

// TestNetFlow9Hostile: malformed flowset lengths error; junk templates are
// ignored without state corruption.
func TestNetFlow9Hostile(t *testing.T) {
	d := NewDecoder(time.Hour, 8)
	unix := uint32(testTime.Unix())
	// Flowset claiming to run past the datagram.
	bad := nf9Header(1, 0, unix, 7)
	bad.u16(0).u16(60_000)
	if _, _, err := d.Decode(bad.b, exporter, testTime); err == nil {
		t.Error("oversize flowset: expected error")
	}
	// Template with absurd field count is dropped quietly.
	tw := nf9Header(1, 0, unix, 7)
	tw.u16(0).u16(8).u16(300).u16(60_000)
	if _, _, err := d.Decode(tw.b, exporter, testTime); err != nil {
		t.Errorf("junk template should not error the datagram: %v", err)
	}
	if d.TemplateCount() != 0 {
		t.Errorf("junk template cached")
	}
	// Cache cap: 8 templates max; the 9th evicts rather than grows.
	for i := 0; i < 12; i++ {
		tid := uint16(300 + i)
		if _, _, err := d.Decode(buildNF9Template(0, unix, 7, tid, [][2]uint16{{ieProtocol, 1}}), exporter, testTime); err != nil {
			t.Fatalf("template %d: %v", tid, err)
		}
	}
	if d.TemplateCount() > 8 {
		t.Errorf("template cache grew past cap: %d", d.TemplateCount())
	}
}

// --- IPFIX --------------------------------------------------------------

// TestIPFIXDecode covers 64-bit counters, absolute millisecond timestamps,
// 4-byte AS numbers, and the message-length envelope.
func TestIPFIXDecode(t *testing.T) {
	d := NewDecoder(time.Hour, 128)
	fields := []ipfixField{
		{ID: ieIPv4Src, Len: 4}, {ID: ieIPv4Dst, Len: 4},
		{ID: ieSrcPort, Len: 2}, {ID: ieDstPort, Len: 2}, {ID: ieProtocol, Len: 1},
		{ID: ieInBytes, Len: 8}, {ID: ieInPackets, Len: 8},
		{ID: ieFlowStartMs, Len: 8}, {ID: ieFlowEndMs, Len: 8},
		{ID: ieSrcAS, Len: 4}, {ID: ieDstAS, Len: 4},
	}
	startMs := uint64(testTime.Add(-2 * time.Minute).UnixMilli())
	endMs := uint64(testTime.Add(-1 * time.Minute).UnixMilli())
	row := (&wire{}).
		raw([]byte{192, 0, 2, 1}).raw([]byte{198, 51, 100, 2}).
		u16(443).u16(55000).u8(6).
		u64(123_456).u64(789).
		u64(startMs).u64(endMs).
		u32(4_200_000_000).u32(65550). // 32-bit AS numbers
		b

	msg := ipfixMsg(uint32(testTime.Unix()), 9,
		ipfixTemplateSet(2, 300, 0, fields),
		ipfixDataSet(300, row))

	recs, misses, err := d.Decode(msg, exporter, testTime)
	if err != nil || misses != 0 {
		t.Fatalf("decode: misses=%d err=%v", misses, err)
	}
	if len(recs) != 1 {
		t.Fatalf("records = %d, want 1", len(recs))
	}
	r := recs[0]
	if r.Protocol != ProtoIPFIX || r.ObservationDomain != 9 {
		t.Errorf("identity = %+v", r)
	}
	if r.Bytes != 123_456 || r.Packets != 789 {
		t.Errorf("64-bit counters = %d/%d", r.Bytes, r.Packets)
	}
	if r.SrcAS != 4_200_000_000 {
		t.Errorf("32-bit AS = %d", r.SrcAS)
	}
	if !r.Start.Equal(time.UnixMilli(int64(startMs))) || !r.End.Equal(time.UnixMilli(int64(endMs))) {
		t.Errorf("absolute times = %v..%v", r.Start, r.End)
	}
}

// TestIPFIXVariableAndEnterprise checks RFC 7011 variable-length encoding and
// enterprise-specific fields are skipped without derailing the record.
func TestIPFIXVariableAndEnterprise(t *testing.T) {
	d := NewDecoder(time.Hour, 128)
	fields := []ipfixField{
		{ID: ieIPv4Src, Len: 4},
		{ID: 82, Len: 0xFFFF},              // interfaceName: variable, unmapped
		{ID: 99, Len: 4, Enterprise: 4242}, // vendor field: skipped
		{ID: ieIPv4Dst, Len: 4},
	}
	short := (&wire{}).
		raw([]byte{10, 0, 0, 1}).
		u8(3).raw([]byte("ge0")). // varlen short form
		u32(0xDEADBEEF).
		raw([]byte{10, 0, 0, 2}).b
	long := (&wire{}).
		raw([]byte{10, 0, 0, 3}).
		u8(255).u16(4).raw([]byte("xe-1")). // varlen long form
		u32(0xDEADBEEF).
		raw([]byte{10, 0, 0, 4}).b

	msg := ipfixMsg(uint32(testTime.Unix()), 9,
		ipfixTemplateSet(2, 301, 0, fields),
		ipfixDataSet(301, short, long))
	recs, _, err := d.Decode(msg, exporter, testTime)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(recs) != 2 {
		t.Fatalf("records = %d, want 2", len(recs))
	}
	if recs[0].DstAddr != netip.MustParseAddr("10.0.0.2") || recs[1].DstAddr != netip.MustParseAddr("10.0.0.4") {
		t.Errorf("fields after varlen/enterprise misparsed: %v / %v", recs[0].DstAddr, recs[1].DstAddr)
	}
}

// TestIPFIXOptionsSampling: samplingPacketInterval (IE 305) from an options
// data set applies to subsequent flow records.
func TestIPFIXOptionsSampling(t *testing.T) {
	d := NewDecoder(time.Hour, 128)
	now := uint32(testTime.Unix())
	optTmpl := ipfixTemplateSet(3, 310, 1, []ipfixField{{ID: 149, Len: 4}, {ID: ieSamplingPktIvl, Len: 4}})
	optData := ipfixDataSet(310, (&wire{}).u32(9).u32(1000).b)
	flowTmpl := ipfixTemplateSet(2, 320, 0, []ipfixField{{ID: ieIPv4Src, Len: 4}, {ID: ieInBytes, Len: 4}})
	flowData := ipfixDataSet(320, (&wire{}).raw([]byte{10, 1, 1, 1}).u32(50).b)

	if _, _, err := d.Decode(ipfixMsg(now, 9, optTmpl, optData), exporter, testTime); err != nil {
		t.Fatalf("options msg: %v", err)
	}
	recs, _, err := d.Decode(ipfixMsg(now, 9, flowTmpl, flowData), exporter, testTime)
	if err != nil || len(recs) != 1 {
		t.Fatalf("flow msg: recs=%d err=%v", len(recs), err)
	}
	if recs[0].SamplingRate != 1000 {
		t.Fatalf("sampling = %d, want 1000", recs[0].SamplingRate)
	}
}

// TestIPFIXHostile: header/set length lies error out cleanly.
func TestIPFIXHostile(t *testing.T) {
	d := NewDecoder(time.Hour, 8)
	msg := ipfixMsg(uint32(testTime.Unix()), 9, ipfixDataSet(300, []byte{1, 2, 3, 4}))
	if _, misses, err := d.Decode(msg, exporter, testTime); err != nil || misses != 1 {
		t.Errorf("unknown template: misses=%d err=%v (want 1, nil)", misses, err)
	}
	short := msg[:10]
	if _, _, err := d.Decode(short, exporter, testTime); err == nil {
		t.Error("short message: expected error")
	}
	lying := append([]byte{}, msg...)
	lying[2], lying[3] = 0xFF, 0xFF // message length > datagram
	if _, _, err := d.Decode(lying, exporter, testTime); err == nil {
		t.Error("length lie: expected error")
	}
}

// --- sFlow --------------------------------------------------------------

// TestSFlowRawHeaderSample decodes a VLAN-tagged IPv4/TCP raw-header sample,
// including the per-sample sampling rate and a skipped counter sample.
func TestSFlowRawHeaderSample(t *testing.T) {
	hdr := buildEthIPv4TCP(100, [4]byte{10, 1, 1, 1}, [4]byte{192, 0, 2, 9}, 443, 51000, 0x12, 6)
	pkt := buildSFlowRaw(1024, 5, 7, hdr, false, true)

	recs, err := decodeSFlow(pkt, exporter, testTime)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(recs) != 1 {
		t.Fatalf("records = %d, want 1 (counter sample must be skipped)", len(recs))
	}
	r := recs[0]
	if r.Protocol != ProtoSFlow5 || r.ObservationDomain != 3 {
		t.Errorf("identity = %+v", r)
	}
	if r.SrcAddr != netip.MustParseAddr("10.1.1.1") || r.DstAddr != netip.MustParseAddr("192.0.2.9") {
		t.Errorf("addrs = %v -> %v", r.SrcAddr, r.DstAddr)
	}
	if r.SrcPort != 443 || r.DstPort != 51000 || r.Transport != 6 || r.TCPFlags != 0x12 {
		t.Errorf("l4 = %+v", r)
	}
	if r.VLAN != 100 || r.InIf != 5 || r.OutIf != 7 {
		t.Errorf("l2/ifaces = %+v", r)
	}
	if r.Bytes != 1500 || r.Packets != 1 || r.SamplingRate != 1024 {
		t.Errorf("volume = %+v", r)
	}
	if got := r.ToProto().GetBytesScaled(); got != 1500*1024 {
		t.Errorf("scaled = %d", got)
	}
}

// TestSFlowExpandedIPv6 decodes an expanded flow sample carrying IPv6/UDP.
func TestSFlowExpandedIPv6(t *testing.T) {
	src := netip.MustParseAddr("2001:db8::10").As16()
	dst := netip.MustParseAddr("2001:db8::20").As16()
	hdr := buildEthIPv6UDP(src, dst, 5353, 5353)
	pkt := buildSFlowRaw(512, 11, 12, hdr, true, false)

	recs, err := decodeSFlow(pkt, exporter, testTime)
	if err != nil || len(recs) != 1 {
		t.Fatalf("decode: recs=%d err=%v", len(recs), err)
	}
	r := recs[0]
	if r.SrcAddr != netip.MustParseAddr("2001:db8::10") || r.Transport != 17 || r.SrcPort != 5353 {
		t.Errorf("v6 record = %+v", r)
	}
	if r.InIf != 11 || r.OutIf != 12 || r.SamplingRate != 512 {
		t.Errorf("expanded fields = %+v", r)
	}
}

// TestSFlowHostile: truncations error without panicking.
func TestSFlowHostile(t *testing.T) {
	hdr := buildEthIPv4TCP(0, [4]byte{1, 2, 3, 4}, [4]byte{5, 6, 7, 8}, 1, 2, 0, 6)
	good := buildSFlowRaw(1, 1, 2, hdr, false, false)
	for cut := 4; cut < len(good); cut += 13 {
		if _, err := decodeSFlow(good[:cut], exporter, testTime); err == nil && cut < 28 {
			t.Errorf("cut at %d: expected error", cut)
		}
	}
	if _, err := decodeSFlow([]byte{0, 0, 0, 9}, exporter, testTime); err == nil {
		t.Error("wrong version: expected error")
	}
}

// --- dispatch ------------------------------------------------------------

// TestDecodeDispatch checks version sniffing routes each wire format and
// rejects garbage.
func TestDecodeDispatch(t *testing.T) {
	d := NewDecoder(time.Hour, 64)
	unix := uint32(testTime.Unix())

	if recs, _, err := d.Decode(buildNF5(1000, unix, 0, []nf5rec{{proto: 6}}), exporter, testTime); err != nil || len(recs) != 1 || recs[0].Protocol != ProtoNetFlow5 {
		t.Errorf("v5 dispatch: %v", err)
	}
	if _, _, err := d.Decode(buildNF9Template(0, unix, 1, 260, nf9V4Fields), exporter, testTime); err != nil {
		t.Errorf("v9 dispatch: %v", err)
	}
	if _, _, err := d.Decode(ipfixMsg(unix, 1, ipfixTemplateSet(2, 300, 0, []ipfixField{{ID: ieProtocol, Len: 1}})), exporter, testTime); err != nil {
		t.Errorf("ipfix dispatch: %v", err)
	}
	hdr := buildEthIPv4TCP(0, [4]byte{1, 1, 1, 1}, [4]byte{2, 2, 2, 2}, 1, 2, 0, 17)
	if recs, _, err := d.Decode(buildSFlowRaw(4, 1, 2, hdr, false, false), exporter, testTime); err != nil || len(recs) != 1 || recs[0].Protocol != ProtoSFlow5 {
		t.Errorf("sflow dispatch: %v", err)
	}
	for _, garbage := range [][]byte{{}, {1}, {0xDE, 0xAD, 0xBE, 0xEF}, {0, 0, 0, 99, 1, 2}} {
		if _, _, err := d.Decode(garbage, exporter, testTime); err == nil {
			t.Errorf("garbage %x: expected error", garbage)
		}
	}
}
