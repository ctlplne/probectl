// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build linux

package ebpf

import "os"

// lockdownMode reads the active kernel lockdown mode, or "" when securityfs is
// not mounted / the file is absent (lockdown not built in).
func lockdownMode() string {
	data, err := os.ReadFile("/sys/kernel/security/lockdown")
	if err != nil {
		return ""
	}
	return parseLockdown(string(data))
}
