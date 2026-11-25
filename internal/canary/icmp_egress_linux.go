// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package canary

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net/netip"

	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

type linuxICMPEgressWitness struct {
	fd         int
	ifindex    int
	egress     ICMPEgress
	echoOffset int
	localMAC   []byte
}

func openICMPEgressWitness(egress ICMPEgress, target netip.Addr, tokens []byte) (icmpEgressWitness, error) {
	iface, err := lookupICMPEgressInterface(egress)
	if err != nil {
		return nil, err
	}
	filter, echoOffset := icmpEgressFilter(egress, target, tokens)
	code, err := bpf.Assemble(filter)
	if err != nil {
		return nil, err
	}
	// Only listen after installing the filter. The kernel queues just the
	// active requests for this execution, truncated immediately after the nonce.
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	witness := &linuxICMPEgressWitness{fd: fd, ifindex: iface.Index, egress: egress, echoOffset: echoOffset, localMAC: iface.HardwareAddr}
	if err := witness.bind(code); err != nil {
		witness.Close()
		return nil, err
	}
	return witness, nil
}

func (w *linuxICMPEgressWitness) bind(code []bpf.RawInstruction) error {
	if len(code) == 0 || len(code) > 4096 {
		return errors.New("icmp: invalid egress filter size")
	}
	filter := make([]unix.SockFilter, len(code))
	for i, op := range code {
		filter[i] = unix.SockFilter{Code: op.Op, Jt: op.Jt, Jf: op.Jf, K: op.K}
	}
	if err := unix.SetsockoptSockFprog(w.fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER,
		&unix.SockFprog{Len: uint16(len(filter)), Filter: &filter[0]}); err != nil {
		return err
	}
	// ETH_P_ALL sees outbound packets on AF_PACKET. The installed filter
	// narrows this to the configured IP family, peer and this run's echo nonces.
	networkOrder := binary.NativeEndian.Uint16([]byte{0, unix.ETH_P_ALL})
	return unix.Bind(w.fd, &unix.SockaddrLinklayer{Ifindex: w.ifindex, Protocol: networkOrder})
}

func (w *linuxICMPEgressWitness) Close() { _ = unix.Close(w.fd) }

func (w *linuxICMPEgressWitness) interfaceIndex() int { return w.ifindex }

func (w *linuxICMPEgressWitness) verifiedMeasurement(challenges map[uint64]int, written []bool) *ICMPEgressMeasurement {
	iface, err := lookupICMPEgressInterface(w.egress)
	if err != nil || iface.Index != w.ifindex || !bytes.Equal(iface.HardwareAddr, w.localMAC) {
		return nil
	}
	frame := make([]byte, ethernetHeaderBytes+40+16)
	seen := make([]bool, len(written))
	matched := 0
	for i := 0; i < len(written)*2 && matched < len(written); i++ {
		n, from, err := unix.Recvfrom(w.fd, frame, unix.MSG_DONTWAIT)
		if err != nil {
			return nil
		}
		link, ok := from.(*unix.SockaddrLinklayer)
		if !ok || link.Ifindex != w.ifindex || link.Pkttype != unix.PACKET_OUTGOING || n != w.echoOffset+16 {
			continue
		}
		echo := frame[w.echoOffset:n]
		sequence, ok := challenges[binary.BigEndian.Uint64(echo[8:])]
		if ok && written[sequence] && !seen[sequence] && int(binary.BigEndian.Uint16(echo[6:8])) == sequence {
			seen[sequence] = true
			matched++
		}
	}
	if matched != len(written) {
		return nil
	}
	return &ICMPEgressMeasurement{ICMPEgress: w.egress, Transmitted: matched}
}
