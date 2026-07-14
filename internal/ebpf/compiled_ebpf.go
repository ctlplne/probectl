// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//go:build ebpf

package ebpf

// liveCompiled is true when built with -tags ebpf: the cilium/ebpf live source
// is linked in (see source_live_linux.go).
const liveCompiled = true
