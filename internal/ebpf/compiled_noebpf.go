// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build !ebpf

package ebpf

// liveCompiled reports whether the live eBPF source (the cilium/ebpf loader) is
// linked into this build. It is false here; it is true only under -tags ebpf
// (see source_live_linux.go / compiled_ebpf.go). The default build ships the
// stub source, so the binary is complete and CI needs no eBPF toolchain.
const liveCompiled = false
