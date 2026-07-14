// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//go:build !ebpf

package ebpf

// liveCompiled reports whether the live eBPF source (the cilium/ebpf loader) is
// linked into this build. It is false here; it is true only under -tags ebpf
// (see source_live_linux.go / compiled_ebpf.go). The default build ships the
// stub source, so the binary is complete and CI needs no eBPF toolchain.
const liveCompiled = false
