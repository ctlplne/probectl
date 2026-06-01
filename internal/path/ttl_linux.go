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
