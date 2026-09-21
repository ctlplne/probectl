// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build !linux

package canary

import "syscall"

// dialControl is a no-op off Linux (DSCP marking is best-effort and the agent
// targets Linux).
func dialControl(_ int) func(network, address string, c syscall.RawConn) error {
	return nil
}
