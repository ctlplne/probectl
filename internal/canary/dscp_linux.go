// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

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
