//go:build !linux

package path

import "syscall"

// ttlControl is a no-op off Linux (the agent targets Linux).
func ttlControl(_ int) func(network, address string, c syscall.RawConn) error {
	return nil
}
