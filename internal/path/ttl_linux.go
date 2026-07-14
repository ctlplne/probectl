// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//go:build linux

package path

import (
	"syscall"

	"golang.org/x/sys/unix"
)

// ttlControl returns a net.Dialer.Control that sets the IP TTL on the socket
// before connect, so a TCP-mode probe's SYN carries the trace TTL.
func ttlControl(ttl int) func(network, address string, c syscall.RawConn) error {
	return func(_, _ string, rc syscall.RawConn) error {
		return rc.Control(func(fd uintptr) {
			_ = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_TTL, ttl)
		})
	}
}
