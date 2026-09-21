// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flow

import (
	"encoding/binary"
	"net/netip"
	"time"
)

// Information elements shared by NetFlow v9 and IPFIX (the IPFIX registry kept
// the v9 numbers for the basics). Only the elements probectl maps are listed;
// every other element is skipped by its declared length — unknown fields must
// never break decoding.
const (
	ieInBytes        = 1
	ieInPackets      = 2
	ieProtocol       = 4
	ieTOS            = 5
	ieTCPFlags       = 6
	ieSrcPort        = 7
	ieIPv4Src        = 8
	ieIngressIf      = 10
	ieDstPort        = 11
	ieIPv4Dst        = 12
	ieEgressIf       = 14
	ieIPv4NextHop    = 15
	ieSrcAS          = 16
	ieDstAS          = 17
	ieLastSwitched   = 21 // ms of exporter sysUptime
	ieFirstSwitched  = 22
	ieOutBytes       = 23
	ieOutPackets     = 24
	ieIPv6Src        = 27
	ieIPv6Dst        = 28
	ieSamplingIvl    = 34 // legacy samplingInterval (v9 options / inline)
	ieVLAN           = 58
	ieIPv6NextHop    = 62
	ieFlowStartSec   = 150
	ieFlowEndSec     = 151
	ieFlowStartMs    = 152
	ieFlowEndMs      = 153
	ieSamplerRandIvl = 50  // samplerRandomInterval (v9 random sampler rate)
	ieSamplingPktIvl = 305 // IPFIX samplingPacketInterval
)

// readUint decodes a big-endian unsigned integer of 1..8 bytes (v9/IPFIX allow
// reduced-size encoding); longer or zero-length values return 0.
func readUint(b []byte) uint64 {
	switch len(b) {
	case 1:
		return uint64(b[0])
	case 2:
		return uint64(binary.BigEndian.Uint16(b))
	case 4:
		return uint64(binary.BigEndian.Uint32(b))
	case 8:
		return binary.BigEndian.Uint64(b)
	case 3, 5, 6, 7:
		var v uint64
		for _, x := range b {
			v = v<<8 | uint64(x)
		}
		return v
	default:
		return 0
	}
}

// ieClock carries the per-datagram clock context needed to map relative
// first/last-switched values onto absolute time. boot is zero when the wire
// protocol has no sysUptime (IPFIX), in which case relative elements fall back
// to the export time.
type ieClock struct {
	boot   time.Time // exporter boot time (v5/v9); zero for IPFIX
	export time.Time // datagram export time
}

func (c ieClock) fromUptimeMS(ms uint64) time.Time {
	if c.boot.IsZero() {
		return c.export
	}
	return c.boot.Add(time.Duration(ms) * time.Millisecond)
}

// applyIE folds one decoded information element into the record. Returns the
// inline sampling rate when the element carries one (0 otherwise) so the data
// decoder can apply record-level sampling precedence.
func applyIE(rec *Record, id uint16, val []byte, clk ieClock) (samplingRate uint64) {
	switch id {
	case ieInBytes:
		rec.Bytes += readUint(val)
	case ieOutBytes:
		rec.Bytes += readUint(val)
	case ieInPackets:
		rec.Packets += readUint(val)
	case ieOutPackets:
		rec.Packets += readUint(val)
	case ieProtocol:
		rec.Transport = uint8(readUint(val))
	case ieTOS:
		rec.ToS = uint8(readUint(val))
	case ieTCPFlags:
		rec.TCPFlags = uint8(readUint(val))
	case ieSrcPort:
		rec.SrcPort = uint16(readUint(val))
	case ieDstPort:
		rec.DstPort = uint16(readUint(val))
	case ieIngressIf:
		rec.InIf = uint32(readUint(val))
	case ieEgressIf:
		rec.OutIf = uint32(readUint(val))
	case ieVLAN:
		rec.VLAN = uint16(readUint(val))
	case ieSrcAS:
		rec.SrcAS = uint32(readUint(val))
	case ieDstAS:
		rec.DstAS = uint32(readUint(val))
	case ieIPv4Src:
		if len(val) == 4 {
			rec.SrcAddr = netip.AddrFrom4([4]byte(val))
		}
	case ieIPv4Dst:
		if len(val) == 4 {
			rec.DstAddr = netip.AddrFrom4([4]byte(val))
		}
	case ieIPv4NextHop:
		if len(val) == 4 {
			rec.NextHop = netip.AddrFrom4([4]byte(val))
		}
	case ieIPv6Src:
		if len(val) == 16 {
			rec.SrcAddr = netip.AddrFrom16([16]byte(val))
		}
	case ieIPv6Dst:
		if len(val) == 16 {
			rec.DstAddr = netip.AddrFrom16([16]byte(val))
		}
	case ieIPv6NextHop:
		if len(val) == 16 {
			rec.NextHop = netip.AddrFrom16([16]byte(val))
		}
	case ieFirstSwitched:
		rec.Start = clk.fromUptimeMS(readUint(val))
	case ieLastSwitched:
		rec.End = clk.fromUptimeMS(readUint(val))
	case ieFlowStartSec:
		rec.Start = time.Unix(int64(readUint(val)), 0)
	case ieFlowEndSec:
		rec.End = time.Unix(int64(readUint(val)), 0)
	case ieFlowStartMs:
		rec.Start = time.UnixMilli(int64(readUint(val)))
	case ieFlowEndMs:
		rec.End = time.UnixMilli(int64(readUint(val)))
	case ieSamplingIvl, ieSamplerRandIvl, ieSamplingPktIvl:
		return readUint(val)
	}
	return 0
}

// optionsSamplingRate scans a decoded options data record (field id -> value)
// for any of the sampling-rate elements.
func optionsSamplingRate(id uint16, val []byte) uint64 {
	switch id {
	case ieSamplingIvl, ieSamplerRandIvl, ieSamplingPktIvl:
		return readUint(val)
	}
	return 0
}
