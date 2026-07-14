// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

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
