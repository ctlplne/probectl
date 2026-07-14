// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//go:build !linux

package path

import "syscall"

// ttlControl is a no-op off Linux (the agent targets Linux).
func ttlControl(_ int) func(network, address string, c syscall.RawConn) error {
	return nil
}
