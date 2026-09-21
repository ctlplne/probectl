// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build linux

package canary

import (
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

// dialControl returns a net.Dialer.Control that marks outgoing packets with the
// given DSCP (0 = no control func). The address family is taken from the resolved
// remote address. Best-effort: setsockopt errors are ignored.
func dialControl(dscp int) func(network, address string, c syscall.RawConn) error {
	if dscp == 0 {
		return nil
	}
	tos := dscp << 2 // DSCP occupies the top 6 bits of the TOS / traffic-class byte
	return func(_, address string, rc syscall.RawConn) error {
		v6 := false
		if h, _, err := net.SplitHostPort(address); err == nil {
			if ip := net.ParseIP(h); ip != nil && ip.To4() == nil {
				v6 = true
			}
		}
		return rc.Control(func(fd uintptr) {
			if v6 {
				_ = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_TCLASS, tos)
				return
			}
			_ = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_TOS, tos)
		})
	}
}
